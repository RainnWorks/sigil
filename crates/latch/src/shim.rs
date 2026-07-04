//! Shim mode: the binary invoked as `op`.
//!
//! A dumb pipe. If the daemon is up, forward argv/cwd and the caller's own
//! stdout/stderr descriptors to it and mirror the exit code. If the socket is
//! absent or unreachable, transparently `exec` the real `op` so nothing breaks
//! when the daemon is off. The shim never parses, retains, or logs output; the
//! secret bytes flow from the `op` child straight to the descriptors passed
//! here, never through this process.

use std::ffi::OsString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

use crate::local::{self, Frame, Reply};
use crate::paths;

/// Entry point for shim mode. Never returns.
pub fn run() -> ! {
    match UnixStream::connect(local::socket_path()) {
        // Daemon up: forward. On any protocol error we fail closed rather than
        // silently running `op` locally, to avoid a mutating command slipping
        // past the approval path once one exists.
        Ok(stream) => match forward(stream) {
            Ok(code) => process::exit(code),
            Err(e) => {
                eprintln!("op: latch daemon request failed: {e}");
                process::exit(70);
            }
        },
        // Daemon down: behave exactly like the real `op`.
        Err(_) => exec_real_op(),
    }
}

fn forward(mut stream: UnixStream) -> io::Result<i32> {
    let argv: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let frame = Frame::Op { argv, cwd };

    // Hand the daemon our real stdout and stderr; `op` writes straight to them.
    let out = io::stdout();
    let err = io::stderr();
    local::send_frame(&stream, &frame, &[out.as_raw_fd(), err.as_raw_fd()])?;
    match local::recv_reply(&mut stream)? {
        Reply::Exit { code } => Ok(code),
        // The daemon only ever answers an op frame with an exit code; anything
        // else is a protocol fault, so fail closed rather than run op locally.
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected reply to op request: {other:?}"),
        )),
    }
}

fn exec_real_op() -> ! {
    let Some(real) = paths::find_real_op() else {
        eprintln!("op: no `op` found on PATH (latch shim active, daemon down)");
        process::exit(127);
    };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // exec replaces this process on success; the line after only runs on error.
    let err = Command::new(&real).args(args).exec();
    eprintln!("op: failed to exec {}: {err}", real.display());
    process::exit(127);
}
