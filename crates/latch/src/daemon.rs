//! The daemon: accept connections, run `op` on the caller's own descriptors.
//!
//! v0 has no approval gating yet (that lands with the keystore seam). Its job
//! is the plumbing invariant: the `op` child's stdout and stderr are the
//! descriptors the shim passed in, so output never enters this process's
//! memory. The daemon sees only request metadata (which it logs, names not
//! values) and the child's exit code (which it returns to the shim).

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::net::UnixListener;

use crate::local::{self, LocalReply, LocalRequest};
use crate::paths;

/// Build a runtime and serve until interrupted. Blocks the calling thread.
pub fn run() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(serve())
}

async fn serve() -> anyhow::Result<()> {
    let sock = local::socket_path();
    prepare_socket(&sock)?;
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    // 0600: only this user may speak to the daemon.
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", sock.display()))?;

    eprintln!("latch daemon: listening on {}", sock.display());

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("latch daemon: shutting down");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept")?;
                let std_stream = stream.into_std().context("into_std")?;
                std_stream.set_nonblocking(false).context("set_nonblocking")?;
                // Per-connection work is blocking syscalls (recvmsg, spawn,
                // waitpid); keep it off the async workers.
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = handle_conn(std_stream) {
                        eprintln!("latch daemon: connection error: {e}");
                    }
                });
            }
        }
    }

    let _ = fs::remove_file(&sock);
    Ok(())
}

/// Create the socket directory 0700 and clear any stale socket file.
fn prepare_socket(sock: &Path) -> anyhow::Result<()> {
    if let Some(dir) = sock.parent() {
        fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", dir.display()))?;
    }
    if sock.exists() {
        fs::remove_file(sock).with_context(|| format!("removing stale {}", sock.display()))?;
    }
    Ok(())
}

fn handle_conn(mut stream: UnixStream) -> anyhow::Result<()> {
    let (req, fds) = match local::recv_request(&stream) {
        Ok(v) => v,
        // A probe (status/doctor) connects then hangs up; not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    log_request(&req);

    let mut fds = fds.into_iter();
    let stdout = fds.next();
    let stderr = fds.next();
    let exit = run_op(&req, stdout, stderr);

    local::send_reply(&mut stream, &LocalReply { exit })?;
    Ok(())
}

/// Spawn the real `op` with its stdout/stderr wired to the passed descriptors.
fn run_op(req: &LocalRequest, stdout: Option<OwnedFd>, stderr: Option<OwnedFd>) -> i32 {
    let Some(real) = paths::find_real_op() else {
        eprintln!("latch daemon: no real `op` found on PATH");
        return 127;
    };

    let mut cmd = Command::new(&real);
    cmd.args(req.argv.iter().skip(1));
    if !req.cwd.is_empty() {
        cmd.current_dir(&req.cwd);
    }
    if let Some(fd) = stdout {
        cmd.stdout(Stdio::from(fd));
    }
    if let Some(fd) = stderr {
        cmd.stderr(Stdio::from(fd));
    }

    match cmd.status() {
        Ok(s) => s
            .code()
            .or_else(|| s.signal().map(|sig| 128 + sig))
            .unwrap_or(1),
        Err(e) => {
            eprintln!("latch daemon: spawning op failed: {e}");
            127
        }
    }
}

/// Log request metadata: argv (item names, not secret values) and cwd.
fn log_request(req: &LocalRequest) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "latch daemon: [{ts}] op {} · cwd {}",
        req.argv
            .iter()
            .skip(1)
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
        req.cwd
    );
}
