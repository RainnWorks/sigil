//! The `latch` subcommands. Hand-rolled dispatch: v0 has a handful of verbs
//! with no flags worth a parser dependency.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use latch_proto::{fingerprint_words, DeviceIdentity};

use crate::daemon;
use crate::local;
use crate::paths;
use crate::style::Style;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Dispatch `latch <cmd>`. Returns the process exit code.
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("") {
        "" | "status" => cmd_status(),
        "daemon" => cmd_daemon(),
        "doctor" => cmd_doctor(),
        "pair" => cmd_pair(),
        "shim" => cmd_shim(args.get(1).map(String::as_str)),
        "version" | "--version" | "-V" => {
            println!("latch {VERSION}");
            0
        }
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            eprintln!("latch: unknown command '{other}'\n");
            print_help();
            2
        }
    }
}

fn print_help() {
    println!(
        "latch {VERSION} — remote-approval instrument for 1Password secrets

usage: latch <command>

  status            instrument panel: daemon, shim, op
  daemon            run the approval daemon (foreground)
  doctor            diagnose shim ordering, socket, and op discovery
  pair              show this device's identity and fingerprint words
  shim install      symlink ~/.latch/bin/op at this binary
  version           print version
  help              print this message"
    );
}

/// True if the daemon socket accepts a connection right now.
fn daemon_up() -> bool {
    UnixStream::connect(local::socket_path()).is_ok()
}

fn cmd_status() -> i32 {
    let s = Style::stdout();
    let up = daemon_up();
    let sock = local::socket_path();
    let order = paths::path_order();
    let shim_on_path = order.shim.is_some();
    let real_op = paths::find_real_op();

    let state = if up { s.ok("armed") } else { s.deny("down") };
    println!("{} {} {}", s.cobalt("latch"), s.faint("·"), state);
    println!();

    // daemon
    let (glyph, label, note) = if up {
        (
            s.ok("\u{25cf}"),
            "listening",
            s.dim(&sock.display().to_string()),
        )
    } else {
        (s.deny("\u{2717}"), "down", s.dim("socket not listening"))
    };
    println!("  {}  {glyph} {}  {note}", s.dim("daemon"), pad(label, 13));

    // shim
    let (glyph, label, note) = if shim_on_path {
        let where_ = paths::shim_bin_dir()
            .map(|p| p.join("op").display().to_string())
            .unwrap_or_default();
        (s.ok("\u{2713}"), "on PATH", s.dim(&where_))
    } else {
        (
            s.brass("\u{2717}"),
            "not installed",
            s.dim("run: latch shim install"),
        )
    };
    println!("  {}    {glyph} {}  {note}", s.dim("shim"), pad(label, 13));

    // op
    let (glyph, label, note) = match &real_op {
        Some(p) => (s.ok("\u{2713}"), "found", s.dim(&p.display().to_string())),
        None => (s.deny("\u{2717}"), "missing", s.dim("no `op` on PATH")),
    };
    println!("  {}      {glyph} {}  {note}", s.dim("op"), pad(label, 13));

    println!();
    println!(
        "  {}",
        s.faint("v0: no approval gating yet; the daemon runs op directly")
    );
    0
}

fn cmd_daemon() -> i32 {
    match daemon::run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("latch daemon: {e:#}");
            1
        }
    }
}

fn cmd_doctor() -> i32 {
    let s = Style::stdout();
    println!("{}", s.cobalt("latch doctor"));
    println!();

    let order = paths::path_order();
    let real_op = paths::find_real_op();
    let mut ok = true;

    // 1. shim resolves before the real op.
    let shim_first = match (order.shim, order.real_op) {
        (Some(shim), Some(real)) => shim < real,
        (Some(_), None) => true,
        _ => false,
    };
    ok &= check(
        &s,
        shim_first,
        "shim resolves before real op",
        match (order.shim, order.real_op) {
            (None, _) => "shim not on PATH (run: latch shim install)",
            (Some(shim), Some(real)) if shim >= real => "real op precedes the shim on PATH",
            _ => "",
        },
    );

    // 2. socket reachable.
    let up = daemon_up();
    ok &= check(
        &s,
        up,
        "daemon socket reachable",
        if up { "" } else { "daemon not running" },
    );

    // 3. real op found.
    ok &= check(
        &s,
        real_op.is_some(),
        "real op found",
        if real_op.is_some() {
            ""
        } else {
            "no `op` on PATH"
        },
    );

    println!();
    if ok {
        println!("  {}", s.ok("all checks passed"));
        0
    } else {
        println!("  {}", s.brass("some checks need attention"));
        1
    }
}

fn check(s: &Style, ok: bool, label: &str, hint: &str) -> bool {
    let glyph = if ok {
        s.ok("\u{2713}")
    } else {
        s.deny("\u{2717}")
    };
    if ok || hint.is_empty() {
        println!("  {glyph} {label}");
    } else {
        println!("  {glyph} {label}  {}", s.dim(&format!("— {hint}")));
    }
    ok
}

fn cmd_pair() -> i32 {
    let s = Style::stdout();
    // v0 stub: mint a device identity and show the fingerprint ceremony format.
    // The peer is a placeholder until real pairing transport lands in v1.
    let device = DeviceIdentity::generate();
    let placeholder_peer = DeviceIdentity::generate().peer_identity();
    let words = fingerprint_words(&device.peer_identity(), &placeholder_peer);

    println!("{}", s.cobalt("latch pair"));
    println!();
    println!(
        "  {}",
        s.dim("Generated a fresh device identity (private half stays in memory;")
    );
    println!(
        "  {}",
        s.dim("v0 has no keystore, so it is not persisted).")
    );
    println!();
    println!(
        "  {}",
        s.dim("Fingerprint — confirm these six words on both devices:")
    );
    println!();
    let joined = words.join(&s.faint(" · "));
    println!("    {}", s.cobalt(&joined));
    println!();
    println!(
        "  {}",
        s.faint("Transport (QR exchange, relay, key pinning) lands in v1.")
    );
    0
}

fn cmd_shim(sub: Option<&str>) -> i32 {
    match sub {
        Some("install") => shim_install(),
        _ => {
            eprintln!("usage: latch shim install");
            2
        }
    }
}

fn shim_install() -> i32 {
    let s = Style::stdout();
    let Some(bindir) = paths::shim_bin_dir() else {
        eprintln!("latch: HOME is not set");
        return 1;
    };
    let target = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("latch: cannot resolve own path: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&bindir) {
        eprintln!("latch: cannot create {}: {e}", bindir.display());
        return 1;
    }
    let link: PathBuf = bindir.join("op");
    if link.exists() || link.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&link);
    }
    if let Err(e) = std::os::unix::fs::symlink(&target, &link) {
        eprintln!("latch: cannot symlink {}: {e}", link.display());
        return 1;
    }

    println!("{} shim installed", s.ok("\u{2713}"));
    println!("  {} {}", s.dim("link"), link.display());
    println!("  {} {}", s.dim("->  "), target.display());
    println!();
    println!(
        "  {}",
        s.dim("Add this to your shell profile so the shim wins on PATH:")
    );
    println!();
    println!("    {}", s.cobalt("export PATH=\"$HOME/.latch/bin:$PATH\""));
    println!();
    println!("  {}", s.faint("v0 does not edit your shell rc for you."));
    0
}

/// Left-pad-to-width a plain (unstyled) label so columns line up. Styling is
/// applied to the glyph separately, so widths here are real display widths.
fn pad(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - s.len()))
    }
}
