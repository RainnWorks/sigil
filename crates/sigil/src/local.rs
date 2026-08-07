//! The local unix-socket protocol between the `op` shim, the `sigil` CLI, and
//! the daemon.
//!
//! This is deliberately *not* the end-to-end envelope layer: it is a trusted,
//! same-machine, same-user channel (the socket is 0600). It carries two kinds
//! of traffic, distinguished by a tagged [`Frame`]:
//!
//! * a **run request** from the shim / `sigil <cmd>` primitive, which also passes
//!   the caller's own stdout/stderr file descriptors over SCM_RIGHTS, so the
//!   underlying tool's child writes secrets straight to the caller's terminal or
//!   pipe and the daemon never sees output; and
//! * **control commands** from the CLI (local approve/deny, lease
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

/// The one runtime directory every Sigil socket lives under, resolved with **zero
/// environment** so the daemon, the `op` shim, the `sigil` CLI, and a bare shell
/// all agree on it. This is the fix for the "manual `SIGIL_SOCK` juggling" that a
/// per-context `$TMPDIR` used to force: the GUI (launched by launchd), a login
/// shell, and a subprocess can each see a *different* `$TMPDIR` (or none at all,
/// falling back to `/tmp`), so deriving the socket from `$TMPDIR` made them bind
/// and connect to different names. We instead anchor on the stable per-user temp
/// dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS), which is identical across
/// all of those contexts for one user, then append `sigil/`.
///
/// Callers that want to override (tests, or a bespoke deployment) do so at the
/// socket level via `SIGIL_SOCK` / `SIGIL_SSH_SOCK`, not here, so a single
/// authoritative default stands unless a full path is deliberately supplied.
pub fn runtime_dir() -> PathBuf {
    stable_temp_base().join("sigil")
}

/// The stable per-user temporary directory the [`runtime_dir`] anchors on.
///
/// On macOS this is `confstr(_CS_DARWIN_USER_TEMP_DIR)` (e.g.
/// `/var/folders/xx/…/T/`), which the OS guarantees is the same for a given user
/// whether the process was started by launchd, a GUI app, or a login shell, and
/// which is short enough to keep the socket well under `sun_path`'s limit. It is
/// deliberately NOT the `$TMPDIR` env var, which any of those contexts may strip
/// or override. If the lookup ever fails we fall back to `/tmp` (shared, but at
/// least consistent). On other platforms we keep the historical `$TMPDIR` (then
/// `/tmp`) behavior.
#[cfg(target_os = "macos")]
fn stable_temp_base() -> PathBuf {
    darwin_user_temp_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(not(target_os = "macos"))]
fn stable_temp_base() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Query `confstr(_CS_DARWIN_USER_TEMP_DIR)` for the stable per-user temp dir.
/// Returns `None` if the lookup reports no value (so the caller can fall back).
#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let name = libc::_CS_DARWIN_USER_TEMP_DIR;
    // First call sizes the buffer (including the trailing NUL).
    // SAFETY: a null buffer with length 0 is the documented sizing call.
    let needed = unsafe { libc::confstr(name, std::ptr::null_mut(), 0) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` is `needed` bytes; confstr writes at most that many.
    let got = unsafe { libc::confstr(name, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if got == 0 || got > buf.len() {
        return None;
    }
    // `got` counts the trailing NUL; drop it and anything past the string.
    buf.truncate(got.saturating_sub(1));
    if buf.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(buf)))
}

/// Where the daemon listens. `SIGIL_SOCK` overrides with a full path (tests, a
/// bespoke deployment); otherwise it is `<runtime_dir>/daemon.sock`, the one
/// authoritative default the GUI, shim, and a bare shell all resolve with zero
/// environment (see [`runtime_dir`]).
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SIGIL_SOCK") {
        return PathBuf::from(p);
    }
    runtime_dir().join("daemon.sock")
}

/// A request frame from a client. Tagged so op traffic and the control protocol
/// share one socket unambiguously.
///
/// This is the daemon control protocol — the single machine interface the Mac
/// app speaks directly and the human CLI renders (see `crates/sigil/PROTOCOL.md`).
/// It splits into three groups: read/report queries that return a
/// [`Reply::Json`] body (`Status`, `Doctor`, `LeaseList`, `Pending`, `History`),
/// runtime-control commands that return a [`Reply::Control`] result (`LeaseRevoke`,
/// `Approve`, `Deny`), and the [`Frame::SubscribePending`] stream
/// that emits a [`Reply::Event`] per pending-set change. The `Run` variant is the
/// shim / `sigil <cmd>` separate SCM_RIGHTS secret path and is untouched by the
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
    ///
    /// `proxy_depth` is the caller's `SIGIL_PROXY_DEPTH` (0 when unset), carried so
    /// the daemon can spawn the tool child at depth+1 and fail closed past the
    /// proxy recursion limit — the daemon has no other view of the caller's depth.
    Run {
        argv: Vec<String>,
        cwd: String,
        #[serde(default)]
        proxy_depth: u32,
    },
    /// The full status report (armed state, factor, shim drift, relay, counts).
    /// Returns [`Reply::Json`] of a `StatusJson`.
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

    // --- the Secure-Enclave-wrapped keystore contract -----------------------
    //
    // These four are callable ONLY by the signed Sigil app: the daemon checks
    // the peer's code identity (`crate::peercode`) before acting. They are the
    // only way a wrapped keystore's material reaches the daemon, and the only
    // way it goes back to plaintext.
    //
    // NOTE on secret bytes: no variant here CARRIES material. The material rides
    // as raw bytes immediately after the header frame on the same stream, read
    // straight into a `Zeroizing` buffer by [`recv_frame_with_tail`]. That is
    // deliberate: a serde-deserialized `String`/`Vec` inside a `Debug`-derived
    // enum is one stray `{:?}` away from printing a secret into a log.
    /// The app hands over the material for a wrapped keystore: this header, then
    /// exactly `len` raw bytes. The daemon digests what it received and compares
    /// (constant time) against the expectation it read at startup. Accepted once
    /// per daemon lifetime; a REJECTED attempt does not latch, so a bad frame
    /// cannot wedge the daemon into never being provisionable.
    KeystoreProvision { len: u64 },
    /// Subscribe to keystore ceremony events. The daemon emits a [`Reply::Event`]
    /// when a de-adoption has been requested, and the app answers by unwrapping
    /// and reporting [`Frame::KeystoreUnwrapDone`].
    SubscribeKeystore,
    /// A human asked (via `sigil keystore unwrap --confirm`) to return the
    /// keystore to plaintext. The daemon raises the request on
    /// [`Frame::SubscribeKeystore`] and blocks until the app answers or the wait
    /// runs out. Same-UID gated like every other CLI verb: it cannot itself
    /// unwrap anything, it can only ask the app to, and the app is what holds the
    /// key.
    KeystoreUnwrapRequest,
    /// The app reports the outcome of an unwrap it was asked to perform.
    KeystoreUnwrapDone {
        nonce: String,
        ok: bool,
        #[serde(default)]
        reason: String,
    },
    /// Seal `len` raw bytes (following this header) into the threshold store
    /// under `id`, using the material the daemon holds. `len == 0` removes the
    /// record instead. This is how the CLI seals when it cannot read the keystore
    /// itself, which under a wrapped store is always.
    ///
    /// Peer gating is same-UID only, NOT the app-identity gate: the caller is
    /// `sigil-config`, an unsigned CLI. That is the same trust boundary every
    /// other CLI control verb already has (the socket is 0600), and it is stated
    /// here so nobody mistakes this for an app-only verb.
    SealThreshold { id: String, len: u64 },
}

/// The daemon's reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    /// The `op` exit code to mirror.
    Exit { code: i32 },
    /// A control result: success flag plus display lines. The reply to the
    /// runtime-control commands (`LeaseRevoke`, `Approve`, `Deny`).
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
    let (frame, fds, _tail) = recv_frame_with_tail(stream)?;
    Ok((frame, fds))
}

/// [`recv_frame`], plus whatever arrived after the frame's newline.
///
/// The header-then-raw-bytes verbs need this. One `recvmsg` can return the JSON
/// header AND the first chunk of the payload behind it, so a reader that keeps
/// only the first line silently eats secret bytes; the caller must be handed
/// them. The buffer is `Zeroizing` because those bytes are exactly the material
/// the whole wrapped-keystore design exists to protect: a plain `Vec` would
/// leave 64 KiB of keystore plaintext in a freed allocation.
///
/// Scope of that guarantee, precisely: the TRANSPORT buffers here are
/// `Zeroizing`. What a caller then parses the bytes into is its own business, and
/// today the JSON and base64 products downstream (`serde_json` Strings, decoded
/// blob maps) are NOT zeroized. That is a known residual, conceded rather than
/// papered over, and it sits inside the same-UID RAM reading this design already
/// admits it cannot stop.
pub fn recv_frame_with_tail(
    stream: &UnixStream,
) -> io::Result<(Frame, Vec<OwnedFd>, zeroize::Zeroizing<Vec<u8>>)> {
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    // Up to three descriptors ride a Run frame: the caller's stdin, stdout, and
    // stderr, spliced straight to the tool child (never read by the daemon).
    let (n, fds) = recv_with_fds(stream.as_raw_fd(), &mut buf, 3)?;
    if n == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    let end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let frame = serde_json::from_slice(&buf[..end]).map_err(invalid_data)?;
    // Everything past the newline is payload, not protocol.
    let tail_start = (end + 1).min(n);
    let tail = zeroize::Zeroizing::new(buf[tail_start..n].to_vec());
    Ok((frame, fds, tail))
}

/// Read exactly `len` payload bytes for a header-then-bytes verb: whatever
/// already arrived with the header, plus the rest off the stream.
///
/// Refuses absurd lengths rather than pre-allocating whatever a caller claims,
/// and refuses a short stream rather than handing back a truncated secret (which
/// would fail a digest check anyway, but should fail as "truncated", not as
/// "wrong material"). Everything lands in one `Zeroizing` buffer.
pub fn read_payload(
    stream: &mut UnixStream,
    tail: zeroize::Zeroizing<Vec<u8>>,
    len: u64,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    /// A keystore's material is a few hundred bytes; a megabyte is already
    /// absurd. The cap exists so a bogus header cannot ask us to allocate.
    const MAX_PAYLOAD: u64 = 1 << 20;
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload of {len} bytes is implausible (max {MAX_PAYLOAD})"),
        ));
    }
    let len = len as usize;
    if tail.len() >= len {
        let mut out = tail;
        out.truncate(len);
        return Ok(out);
    }
    // Pre-size to the FULL payload before copying anything in. Growing a Vec
    // reallocates and copies, and the old allocation is freed without
    // `Zeroizing` ever seeing it: for a provision that arrived in one recvmsg,
    // that abandoned copy is the entire keystore material.
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(&tail);
    drop(tail); // wiped here
    let mut chunk = zeroize::Zeroizing::new(vec![0u8; 8192]);
    while out.len() < len {
        let want = (len - out.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "payload ended early",
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// Write a header frame followed immediately by raw payload bytes, the sending
/// half of the header-then-bytes verbs.
pub fn send_frame_with_payload(
    stream: &UnixStream,
    frame: &Frame,
    payload: &[u8],
) -> io::Result<()> {
    let mut line = serde_json::to_vec(frame).map_err(invalid_data)?;
    line.push(b'\n');
    send_with_fds(stream.as_raw_fd(), &line, &[])?;
    (&*stream).write_all(payload)
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
            proxy_depth: 0,
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
    fn socket_path_honors_the_sigil_sock_override() {
        // Tests and bespoke deployments override with a full path; that must win
        // over the computed default.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("SIGIL_SOCK");
        std::env::set_var("SIGIL_SOCK", "/tmp/custom-sigil/x.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/custom-sigil/x.sock"));
        match prev {
            Some(v) => std::env::set_var("SIGIL_SOCK", v),
            None => std::env::remove_var("SIGIL_SOCK"),
        }
    }

    #[test]
    fn daemon_and_ssh_sockets_share_one_authoritative_runtime_dir() {
        // #59: with zero environment, the daemon socket and the ssh-agent socket
        // both resolve under the SAME runtime dir, so the GUI, shim, and a bare
        // shell all meet at one place without SIGIL_SOCK juggling.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev_sock = std::env::var_os("SIGIL_SOCK");
        let prev_ssh = std::env::var_os("SIGIL_SSH_SOCK");
        std::env::remove_var("SIGIL_SOCK");
        std::env::remove_var("SIGIL_SSH_SOCK");

        let dir = runtime_dir();
        let daemon = socket_path();
        let ssh = crate::sshagent::socket_path();
        assert_eq!(daemon.parent(), Some(dir.as_path()));
        assert_eq!(ssh.parent(), Some(dir.as_path()));
        assert_eq!(daemon.file_name().unwrap(), "daemon.sock");
        assert_eq!(ssh.file_name().unwrap(), "ssh-agent.sock");
        // The default must fit sun_path with margin (the whole point of anchoring
        // on the short, stable per-user temp dir rather than a long $TMPDIR).
        assert!(
            crate::service::socket_path_fits().is_ok(),
            "the default socket path must fit sun_path"
        );

        match prev_sock {
            Some(v) => std::env::set_var("SIGIL_SOCK", v),
            None => std::env::remove_var("SIGIL_SOCK"),
        }
        match prev_ssh {
            Some(v) => std::env::set_var("SIGIL_SSH_SOCK", v),
            None => std::env::remove_var("SIGIL_SSH_SOCK"),
        }
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
