//! The transparent-alias / primitive forwarder.
//!
//! A dumb pipe. Given a command invocation (argv[0] is the command name), if the
//! daemon is up it forwards argv/cwd and the caller's own stdout/stderr
//! descriptors to it and mirrors the exit code. If the daemon socket is absent or
//! unreachable, it transparently `exec`s the real underlying tool so nothing
//! breaks when the daemon is off. It never parses, retains, or logs output; the
//! secret bytes flow from the tool's child straight to the descriptors passed
//! here, never through this process.
//!
//! Two entry points funnel here: the transparent PATH shim (a binary named `op`,
//! `gcloud`, … whose argv[0] stem is the command) and the `latch <cmd>` primitive
//! (and its `latch run -- <cmd>` escape hatch). Both are thin fronts over the one
//! [`dispatch`] path; the daemon behind them looks up the command's config and
//! decides whether it is gated.

use std::ffi::OsString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

use crate::local::{self, Frame, Reply};
use crate::paths;

/// Forward a command invocation to the daemon (which gates it), or, if the daemon
/// is down, transparently `exec` the real underlying tool. `argv[0]` is the
/// command name (e.g. `op`), not a path. Never returns.
///
/// A protocol-level error while the daemon *is* up fails closed (exit 70) rather
/// than silently running the tool locally, so a mutating command can never slip
/// past the gate once one exists. Only a *down* daemon triggers the transparent
/// exec fallback.
pub fn dispatch(argv: Vec<String>) -> ! {
    // Recursion fuse: a bug in real-binary resolution (returning one of our own
    // aliases) would fork-bomb. `find_real` excluding our aliases is the real
    // guard; this converts any escape into a bounded, fail-closed abort. See
    // `docs/design/proxy-aliasing.md` problem 1(b).
    if crate::proxy::depth_exceeded() {
        let cmd = argv.first().map(String::as_str).unwrap_or("latch");
        eprintln!(
            "{cmd}: latch proxy recursion guard tripped (depth {}); \
             a real {cmd} could not be resolved apart from the proxy alias",
            crate::proxy::current_depth()
        );
        process::exit(70);
    }
    match UnixStream::connect(local::socket_path()) {
        Ok(stream) => match forward(stream, &argv) {
            Ok(code) => process::exit(code),
            Err(e) => {
                let cmd = argv.first().map(String::as_str).unwrap_or("latch");
                eprintln!("{cmd}: latch daemon request failed: {e}");
                process::exit(70);
            }
        },
        // Daemon down: behave exactly like the real underlying tool.
        Err(_) => exec_real(&argv),
    }
}

fn forward(stream: UnixStream, argv: &[String]) -> io::Result<i32> {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let frame = Frame::Run {
        argv: argv.to_vec(),
        cwd,
    };

    // Hand the daemon our real stdin, stdout, and stderr (in that order); the
    // tool reads/writes straight to them so interactive prompts work, and no
    // caller byte ever passes through the daemon.
    let inp = io::stdin();
    let out = io::stdout();
    let err = io::stderr();
    local::send_frame(
        &stream,
        &frame,
        &[inp.as_raw_fd(), out.as_raw_fd(), err.as_raw_fd()],
    )?;
    let mut stream = stream;
    match local::recv_reply(&mut stream)? {
        Reply::Exit { code } => Ok(code),
        // The daemon only ever answers a run frame with an exit code; anything
        // else is a protocol fault, so fail closed rather than run the tool.
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected reply to run request: {other:?}"),
        )),
    }
}

fn exec_real(argv: &[String]) -> ! {
    let cmd = argv.first().map(String::as_str).unwrap_or("");
    let Some(real) = paths::find_real(cmd) else {
        eprintln!("{cmd}: no `{cmd}` found on PATH (latch shim active, daemon down)");
        process::exit(127);
    };
    let args: Vec<OsString> = argv.iter().skip(1).map(OsString::from).collect();
    // Carry the incremented recursion depth to the real tool. If resolution is
    // buggy and `real` is actually one of our aliases, its dispatch entry sees a
    // higher depth and eventually trips the fuse rather than looping forever.
    // exec replaces this process on success; the line after only runs on error.
    let err = Command::new(&real)
        .args(args)
        .env(crate::proxy::DEPTH_ENV, crate::proxy::next_depth_value())
        .exec();
    eprintln!("{cmd}: failed to exec {}: {err}", real.display());
    process::exit(127);
}
