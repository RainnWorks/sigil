//! The local unix-socket protocol between the `op` shim and the daemon.
//!
//! This is deliberately *not* the end-to-end envelope layer: it is a trusted,
//! same-machine, same-user channel. Its one non-obvious job is to honour the
//! core invariant that secret bytes never pass through daemon memory. The shim
//! hands the daemon its own stdout and stderr file descriptors over SCM_RIGHTS;
//! the daemon wires the real `op` child straight onto those descriptors, so
//! `op` writes secrets directly to the caller's terminal or pipe. The daemon
//! only ever sees the request metadata and the final exit code, never output.

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

/// The shim's request: the original argv and the caller's working directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRequest {
    pub argv: Vec<String>,
    pub cwd: String,
}

/// The daemon's terminal reply: the `op` exit code to mirror.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalReply {
    pub exit: i32,
}

fn invalid_data<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Send the request line plus the caller's stdout/stderr descriptors.
pub fn send_request(stream: &UnixStream, req: &LocalRequest, fds: &[RawFd]) -> io::Result<()> {
    let mut line = serde_json::to_vec(req).map_err(invalid_data)?;
    line.push(b'\n');
    send_with_fds(stream.as_raw_fd(), &line, fds)
}

/// Receive the request and the passed descriptors. Returns
/// [`io::ErrorKind::UnexpectedEof`] if the peer connected then hung up without
/// sending anything (e.g. a `status` probe), which the caller treats as a
/// quiet no-op.
pub fn recv_request(stream: &UnixStream) -> io::Result<(LocalRequest, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 64 * 1024];
    let (n, fds) = recv_with_fds(stream.as_raw_fd(), &mut buf, 2)?;
    if n == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    let end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let req = serde_json::from_slice(&buf[..end]).map_err(invalid_data)?;
    Ok((req, fds))
}

/// Write the terminal reply line.
pub fn send_reply(stream: &mut UnixStream, reply: &LocalReply) -> io::Result<()> {
    let mut line = serde_json::to_vec(reply).map_err(invalid_data)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Read the terminal reply line.
pub fn recv_reply(stream: &mut UnixStream) -> io::Result<LocalReply> {
    let mut buf = Vec::with_capacity(64);
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
    fn fd_passing_and_reply_roundtrip_over_a_socketpair() {
        // Pass a pipe's write end through the socket; reading the read end
        // proves the descriptor really crossed the process boundary intact.
        let (mut shim, mut daemon) = UnixStream::pair().unwrap();
        let mut pipe_fds = [0 as RawFd; 2];
        // SAFETY: standard pipe(2) with a 2-element array out-param.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe(2) just handed us these two fresh, owned fds.
        let read_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        let req = LocalRequest {
            argv: vec!["op".into(), "read".into()],
            cwd: "/work".into(),
        };
        send_request(&shim, &req, &[write_end.as_raw_fd()]).unwrap();
        drop(write_end);

        let (got, mut fds) = recv_request(&daemon).unwrap();
        assert_eq!(got.argv, req.argv);
        assert_eq!(got.cwd, req.cwd);
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
        send_reply(&mut daemon, &LocalReply { exit: 3 }).unwrap();
        assert_eq!(recv_reply(&mut shim).unwrap().exit, 3);
    }
}
