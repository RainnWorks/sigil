//! The local unix-socket protocol between the `op` shim, the `latch` CLI, and
//! the daemon.
//!
//! This is deliberately *not* the end-to-end envelope layer: it is a trusted,
//! same-machine, same-user channel (the socket is 0600). It carries two kinds
//! of traffic, distinguished by a tagged [`Frame`]:
//!
//! * a **run request** from the shim / `latch <cmd>` primitive, which also passes
//!   the caller's own stdout/stderr file descriptors over SCM_RIGHTS, so the
//!   underlying tool's child writes secrets straight to the caller's terminal or
//!   pipe and the daemon never sees output; and
//! * **control commands** from the CLI (local approve/deny, lockdown, lease
//!   list/revoke), which carry no descriptors.
//!
//! The daemon replies with a [`Reply`]: an exit code to mirror for run requests,
//! or a small status payload for control commands.

use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where the daemon listens. `LATCH_SOCK` overrides; otherwise it is
/// `$TMPDIR/latch/daemon.sock` (falling back to `/tmp`).
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("LATCH_SOCK") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("latch").join("daemon.sock")
}

/// A request frame from a client. Tagged so op traffic and the control protocol
/// share one socket unambiguously.
///
/// This is the daemon control protocol — the single machine interface the Mac
/// app speaks directly and the human CLI renders (see `crates/latch/PROTOCOL.md`).
/// It splits into three groups: read/report queries that return a
/// [`Reply::Json`] body (`Status`, `Doctor`, `LeaseList`, `Pending`, `History`),
/// runtime-control commands that return a [`Reply::Control`] result (`Lockdown`,
/// `LeaseRevoke`, `Approve`, `Deny`), and the [`Frame::SubscribePending`] stream
/// that emits a [`Reply::Event`] per pending-set change. The `Run` variant is the
/// shim / `latch <cmd>` separate SCM_RIGHTS secret path and is untouched by the
/// control surface. Keystore/config *mutations* (account add/rotate/remove,
/// command config, settings, wipe, mac-approvals, shim install, pairing) are
/// deliberately NOT here: they stay short-lived CLI operations so a compromised
/// always-on daemon cannot perform them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    /// A gated command invocation: the original argv (argv[0] is the command
    /// name) and the caller's cwd. The caller's stdin, stdout, and stderr
    /// descriptors ride alongside as SCM_RIGHTS (in that order). The daemon looks
    /// up the command config, gates it, injects the provider's environment, and
    /// runs it with those descriptors spliced to the child — it never reads them.
    Run { argv: Vec<String>, cwd: String },
    /// The full status report (armed state, factor, shim drift, relay, counts,
    /// lockdown). Returns [`Reply::Json`] of a `StatusJson`.
    Status,
    /// The doctor checks. Returns [`Reply::Json`] of a `[CheckJson]`.
    Doctor,
    /// Active session leases. Returns [`Reply::Json`] of a `[LeaseJson]`.
    LeaseList,
    /// Requests currently parked for a local decision. Returns [`Reply::Json`]
    /// of a `[PendingJson]`.
    Pending,
    /// The decision audit log, newest-first. Returns [`Reply::Json`] of a
    /// `[HistoryJson]`.
    History,
    /// Seal (or, with `clear`, unseal) the daemon. Returns [`Reply::Control`].
    Lockdown { clear: bool },
    /// Revoke leases whose grant-key hex starts with `prefix`. [`Reply::Control`].
    LeaseRevoke { prefix: String },
    /// Resolve a pending local approval as approve; `lease` makes it a session
    /// lease rather than a single shot. [`Reply::Control`].
    Approve { id: String, lease: bool },
    /// Resolve a pending local approval as deny. [`Reply::Control`].
    Deny { id: String },
    /// Subscribe to pending-set changes: the daemon emits a [`Reply::Event`]
    /// carrying the current `[PendingJson]` immediately and again on every
    /// change, until the client disconnects. Drives the live menubar.
    SubscribePending,
}

/// The daemon's reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    /// The `op` exit code to mirror.
    Exit { code: i32 },
    /// A control result: success flag plus display lines. The reply to the
    /// runtime-control commands (`Lockdown`, `LeaseRevoke`, `Approve`, `Deny`).
    Control { ok: bool, lines: Vec<String> },
    /// A pre-serialized JSON body (one value, no trailing newline) for the
    /// read/report queries. Carried as a `String` so [`Reply`] stays `Eq`; the
    /// client parses it into the matching DTO.
    Json { body: String },
    /// One item of a subscription stream (e.g. a pending-set snapshot). The
    /// daemon writes these repeatedly on one connection until the client hangs
    /// up. Same `String`-body convention as [`Reply::Json`].
    Event { body: String },
}

fn invalid_data<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Send a frame, optionally with descriptors (run requests pass stdout/stderr).
pub fn send_frame(stream: &UnixStream, frame: &Frame, fds: &[RawFd]) -> io::Result<()> {
    let mut line = serde_json::to_vec(frame).map_err(invalid_data)?;
    line.push(b'\n');
    send_with_fds(stream.as_raw_fd(), &line, fds)
}

/// Receive a frame and any passed descriptors. Returns
/// [`io::ErrorKind::UnexpectedEof`] if the peer connected then hung up without
/// sending anything (e.g. a `status` probe), which the caller treats as a
/// quiet no-op.
pub fn recv_frame(stream: &UnixStream) -> io::Result<(Frame, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 64 * 1024];
    // Up to three descriptors ride a Run frame: the caller's stdin, stdout, and
    // stderr, spliced straight to the tool child (never read by the daemon).
    let (n, fds) = recv_with_fds(stream.as_raw_fd(), &mut buf, 3)?;
    if n == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    let end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let frame = serde_json::from_slice(&buf[..end]).map_err(invalid_data)?;
    Ok((frame, fds))
}

/// Write the reply line.
pub fn send_reply(stream: &mut UnixStream, reply: &Reply) -> io::Result<()> {
    let mut line = serde_json::to_vec(reply).map_err(invalid_data)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Read the reply line.
pub fn recv_reply(stream: &mut UnixStream) -> io::Result<Reply> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).map_err(invalid_data)
}

/// `sendmsg` with an SCM_RIGHTS control message carrying `fds`.
fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let fd_bytes = mem::size_of_val(fds);
    // SAFETY: CMSG_SPACE is a pure size computation over a byte count.
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut cbuf = vec![0u8; cmsg_space.max(1)];

    // SAFETY: msghdr is a C plain-old-data struct; an all-zero value is the
    // documented empty message, which we then fill in.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;
        // SAFETY: msg_control points at `cbuf`, which is exactly `cmsg_space`
        // bytes; CMSG_FIRSTHDR therefore returns a header inside that buffer,
        // and the copy writes exactly `fd_bytes` into the CMSG data region.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                fd_bytes,
            );
        }
    }

    // SAFETY: `msg` is fully initialised and `sock` is a connected socket fd.
    let n = unsafe { libc::sendmsg(sock, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `recvmsg` returning the data length and any SCM_RIGHTS descriptors, wrapped
/// in [`OwnedFd`] so they close on drop.
fn recv_with_fds(sock: RawFd, buf: &mut [u8], max_fds: usize) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let fd_bytes = max_fds * mem::size_of::<RawFd>();
    // SAFETY: pure size computation.
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut cbuf = vec![0u8; cmsg_space.max(1)];

    // SAFETY: see send_with_fds; zeroed msghdr is the documented empty message.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: `msg` is initialised and all buffers outlive the call.
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut fds = Vec::new();
    // SAFETY: we walk the control buffer using the kernel-provided cmsg macros,
    // reading only within each header's declared length. Each fd the kernel
    // installed is now owned by this process; wrapping in OwnedFd transfers that
    // ownership so it is closed exactly once.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let payload = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = payload / mem::size_of::<RawFd>();
                for i in 0..count {
                    let mut raw: RawFd = 0;
                    std::ptr::copy_nonoverlapping(
                        data_ptr.add(i * mem::size_of::<RawFd>()),
                        (&mut raw as *mut RawFd).cast::<u8>(),
                        mem::size_of::<RawFd>(),
                    );
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((n as usize, fds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn op_fd_passing_and_reply_roundtrip_over_a_socketpair() {
        // Pass a pipe's write end through the socket; reading the read end
        // proves the descriptor really crossed the process boundary intact.
        let (mut shim, daemon) = UnixStream::pair().unwrap();
        let mut pipe_fds = [0 as RawFd; 2];
        // SAFETY: standard pipe(2) with a 2-element array out-param.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe(2) just handed us these two fresh, owned fds.
        let read_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        let frame = Frame::Run {
            argv: vec!["op".into(), "read".into()],
            cwd: "/work".into(),
        };
        send_frame(&shim, &frame, &[write_end.as_raw_fd()]).unwrap();
        drop(write_end);

        let (got, mut fds) = recv_frame(&daemon).unwrap();
        assert_eq!(got, frame);
        assert_eq!(fds.len(), 1);

        // The received fd is a live handle to the same pipe.
        let mut sender = File::from(fds.pop().unwrap());
        writeln!(sender, "hello").unwrap();
        drop(sender);
        let mut reader = File::from(read_end);
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello\n");

        // Terminal reply mirrors the exit code back to the shim.
        let mut daemon = daemon;
        send_reply(&mut daemon, &Reply::Exit { code: 3 }).unwrap();
        assert_eq!(recv_reply(&mut shim).unwrap(), Reply::Exit { code: 3 });
    }

    #[test]
    fn a_malformed_frame_is_rejected() {
        // A rogue client sending non-JSON must be rejected as InvalidData, never
        // silently misparsed into a control command.
        let (a, b) = UnixStream::pair().unwrap();
        let mut a = a;
        a.write_all(b"this is not a frame\n").unwrap();
        let err = recv_frame(&b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn json_and_event_replies_roundtrip() {
        // The two stream/report reply shapes must survive the wire intact.
        let (client, server) = UnixStream::pair().unwrap();
        let mut server = server;
        send_reply(&mut server, &Reply::Json { body: "[]".into() }).unwrap();
        send_reply(
            &mut server,
            &Reply::Event {
                body: "{\"k\":1}".into(),
            },
        )
        .unwrap();
        let mut client = client;
        assert_eq!(
            recv_reply(&mut client).unwrap(),
            Reply::Json { body: "[]".into() }
        );
        assert_eq!(
            recv_reply(&mut client).unwrap(),
            Reply::Event {
                body: "{\"k\":1}".into()
            }
        );
    }

    #[test]
    fn control_frame_roundtrips_without_fds() {
        let (client, daemon) = UnixStream::pair().unwrap();
        let frame = Frame::Approve {
            id: "req-1".into(),
            lease: true,
        };
        send_frame(&client, &frame, &[]).unwrap();
        let (got, fds) = recv_frame(&daemon).unwrap();
        assert_eq!(got, frame);
        assert!(fds.is_empty());

        let mut daemon = daemon;
        let reply = Reply::Control {
            ok: true,
            lines: vec!["approved".into()],
        };
        send_reply(&mut daemon, &reply).unwrap();
        let mut client = client;
        assert_eq!(recv_reply(&mut client).unwrap(), reply);
    }
}
