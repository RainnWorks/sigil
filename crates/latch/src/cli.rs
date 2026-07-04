//! The `latch` subcommands. Hand-rolled dispatch: v0 has a handful of verbs
//! with no flags worth a parser dependency.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use latch_proto::{fingerprint_words, DeviceIdentity};
use zeroize::Zeroizing;

use crate::daemon;
use crate::keystore;
use crate::local::{self, Frame, Reply};
use crate::paths;
use crate::secrets::{self, AccountStore};
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
        "account" => cmd_account(&args[1..]),
        "lease" => cmd_lease(&args[1..]),
        "lockdown" => cmd_lockdown(&args[1..]),
        "approve" => cmd_approve(&args[1..]),
        "deny" => cmd_deny(&args[1..]),
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
  account add       add a service-account token (reads token from stdin)
  account list      list configured accounts and their vault routing
  lease list        list active session leases with countdowns
  lease revoke <p>  revoke leases whose grant-key hex starts with <p>
  lockdown [--clear]  seal the daemon (deny + refuse) or unseal it
  approve --local --id <id> [--lease]  approve a pending request at the Mac
  deny --local --id <id>               deny a pending request at the Mac
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

    // accounts
    let accounts = AccountStore::load().map(|s| s.accounts.len()).unwrap_or(0);
    let (glyph, label, note) = if accounts > 0 {
        (
            s.ok("\u{2713}"),
            "configured",
            s.dim(&format!("{accounts} account(s)")),
        )
    } else {
        (
            s.brass("\u{2717}"),
            "none",
            s.dim("run: latch account add --token-stdin --label <name>"),
        )
    };
    println!("  {} {glyph} {}  {note}", s.dim("accounts"), pad(label, 13));

    println!();
    println!(
        "  {}",
        s.faint("every op request is gated: lease, else a fresh approval; fails closed")
    );
    0
}

/// Connect to the daemon, send one control frame, and return its reply.
fn send_control(frame: &Frame) -> std::io::Result<Reply> {
    let mut stream = UnixStream::connect(local::socket_path())?;
    local::send_frame(&stream, frame, &[])?;
    local::recv_reply(&mut stream)
}

/// Print a control reply's lines and map its ok flag to an exit code.
fn print_control(reply: std::io::Result<Reply>) -> i32 {
    let s = Style::stdout();
    match reply {
        Ok(Reply::Control { ok, lines }) => {
            for line in &lines {
                let glyph = if ok {
                    s.ok("\u{2713}")
                } else {
                    s.brass("\u{2717}")
                };
                println!("  {glyph} {line}");
            }
            i32::from(!ok)
        }
        Ok(other) => {
            eprintln!("latch: unexpected reply: {other:?}");
            1
        }
        Err(e) => {
            eprintln!("latch: daemon unreachable ({e}); is it running?");
            1
        }
    }
}

/// `--flag value` / `--flag=value` extractor over a small arg slice.
fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    let eq = format!("{name}=");
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix(&eq) {
            return Some(v);
        }
        if a == name {
            return it.next().map(String::as_str);
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn cmd_account(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("add") => account_add(&args[1..]),
        Some("list") => account_list(),
        _ => {
            eprintln!("usage: latch account <add|list>");
            2
        }
    }
}

fn account_add(args: &[String]) -> i32 {
    let s = Style::stdout();
    let Some(label) = flag_value(args, "--label").map(str::to_string) else {
        eprintln!("usage: latch account add --token-stdin --label <name>");
        return 2;
    };
    if !has_flag(args, "--token-stdin") {
        eprintln!("latch: refusing to read a token from argv; pass --token-stdin");
        return 2;
    }

    // Read the token from stdin into a wiped buffer; trim one trailing newline.
    let mut token = Zeroizing::new(Vec::new());
    if let Err(e) = std::io::stdin().read_to_end(&mut token) {
        eprintln!("latch: reading token from stdin: {e}");
        return 1;
    }
    while matches!(token.last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    if token.is_empty() {
        eprintln!("latch: empty token on stdin");
        return 1;
    }

    // Unwrap the DEK (biometric on macOS) and encrypt the token under it.
    let ks = keystore::for_host();
    if let Err(e) = ks.ensure_dek() {
        eprintln!("latch: provisioning the DEK: {e}");
        return 1;
    }
    let dek = match ks.unwrap_dek(&format!("Add the {label} service-account token")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("latch: unwrapping the DEK: {e}");
            return 1;
        }
    };

    // Probe the vaults this token can actually route (best effort).
    let vaults = match paths::find_real_op() {
        Some(op) => secrets::probe_vaults(&op, &token).unwrap_or_default(),
        None => Vec::new(),
    };
    if vaults.is_empty() {
        println!(
            "  {} {}",
            s.brass("\u{2717}"),
            s.dim("no vaults visible to this token (service accounts cannot see built-in Personal/Shared vaults)")
        );
    }

    let mut store = match AccountStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("latch: loading account store: {e}");
            return 1;
        }
    };
    if let Err(e) = store.add(&label, &dek, &token, vaults.clone()) {
        eprintln!("latch: {e}");
        return 1;
    }
    if let Err(e) = store.save() {
        eprintln!("latch: saving account store: {e}");
        return 1;
    }

    println!("{} account {} added", s.ok("\u{2713}"), s.cobalt(&label));
    if !vaults.is_empty() {
        println!("  {} {}", s.dim("vaults"), vaults.join(", "));
    }
    0
}

fn account_list() -> i32 {
    let s = Style::stdout();
    let store = match AccountStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("latch: loading account store: {e}");
            return 1;
        }
    };
    if store.accounts.is_empty() {
        println!("  {}", s.dim("no accounts; run: latch account add"));
        return 0;
    }
    println!("{}", s.cobalt("accounts"));
    println!();
    for a in &store.accounts {
        let vaults = if a.vaults.is_empty() {
            s.dim("no vaults probed")
        } else {
            s.dim(&a.vaults.join(", "))
        };
        println!("  {}  {}", pad(&a.label, 20), vaults);
    }
    0
}

fn cmd_lease(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("list") | None => {
            let reply = send_control(&Frame::LeaseList);
            // A lease list with no lines is not a failure; print a note.
            if let Ok(Reply::Control { lines, .. }) = &reply {
                if lines.is_empty() {
                    println!("  {}", Style::stdout().dim("no active leases"));
                    return 0;
                }
            }
            print_control(reply)
        }
        Some("revoke") => {
            let Some(prefix) = args.get(1) else {
                eprintln!("usage: latch lease revoke <grant-hex-prefix>");
                return 2;
            };
            print_control(send_control(&Frame::LeaseRevoke {
                prefix: prefix.clone(),
            }))
        }
        _ => {
            eprintln!("usage: latch lease <list|revoke <prefix>>");
            2
        }
    }
}

fn cmd_lockdown(args: &[String]) -> i32 {
    print_control(send_control(&Frame::Lockdown {
        clear: has_flag(args, "--clear"),
    }))
}

fn cmd_approve(args: &[String]) -> i32 {
    let Some(id) = flag_value(args, "--id").map(str::to_string) else {
        eprintln!("usage: latch approve --local --id <id> [--lease]");
        return 2;
    };
    print_control(send_control(&Frame::Approve {
        id,
        lease: has_flag(args, "--lease"),
    }))
}

fn cmd_deny(args: &[String]) -> i32 {
    let Some(id) = flag_value(args, "--id").map(str::to_string) else {
        eprintln!("usage: latch deny --local --id <id>");
        return 2;
    };
    print_control(send_control(&Frame::Deny { id }))
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
