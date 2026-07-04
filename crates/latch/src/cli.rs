//! The `latch` subcommands. Hand-rolled dispatch: v0 has a handful of verbs
//! with no flags worth a parser dependency.

use std::io::Read;
use std::os::unix::net::UnixStream;

use latch_proto::DeviceIdentity;
use zeroize::Zeroizing;

use crate::daemon;
use crate::keystore;
use crate::local::{self, Frame, Reply};
use crate::paths;
use crate::provider::{OpProvider, SecretProvider};
use crate::secrets::AccountStore;
use crate::style::Style;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Dispatch `latch <cmd>`. Returns the process exit code.
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("") {
        "" | "status" => cmd_status(),
        "daemon" => cmd_daemon(&args[1..]),
        "doctor" => cmd_doctor(),
        "setup" => cmd_setup(&args[1..]),
        "pair" => cmd_pair(&args[1..]),
        "unpair" => cmd_unpair(),
        "start" | "stop" | "restart" => cmd_service(&args[0]),
        "account" => cmd_account(&args[1..]),
        "lease" => cmd_lease(&args[1..]),
        "lockdown" => cmd_lockdown(&args[1..]),
        "approve" => cmd_approve(&args[1..]),
        "deny" => cmd_deny(&args[1..]),
        "ssh" => cmd_ssh(&args[1..]),
        "sshagent" => cmd_sshagent(),
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

  status            instrument panel: daemon, shim, op, factor
  setup             guided first run: shim, PATH, launchd, then pair
  daemon [--dev-insecure]  run the approval daemon (foreground). Without a
                    paired phone or a hardware biometric it fails closed;
                    --dev-insecure enables local self-approval for dev only.
  doctor            diagnose shim drift, factor, relay, socket, and op
  pair --relay <url>   pair a phone over the relay (renders a QR)
  pair list         list paired devices
  unpair            forget the paired phone
  start|stop|restart   control the launchd daemon agent
  account add       add a service-account token (reads token from stdin)
  account list      list configured accounts and their vault routing
  lease list        list active session leases with countdowns
  lease revoke <p>  revoke leases whose grant-key hex starts with <p>
  lockdown [--clear]  seal the daemon (deny + refuse) or unseal it
  approve --local --id <id> [--lease]  approve a pending request at the Mac
  deny --local --id <id>               deny a pending request at the Mac
  ssh add           serve a 1Password SSH key (--vault --item --pubkey-file)
  ssh list          list the SSH keys the agent serves
  ssh remove <item> stop serving an SSH key
  sshagent          print the SSH_AUTH_SOCK to point ssh/git at Latch
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
    let shim = paths::ShimStatus::detect();
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

    // shim (with drift detection)
    let (glyph, label, note) = if shim.healthy() {
        let where_ = paths::shim_bin_dir()
            .map(|p| p.join("op").display().to_string())
            .unwrap_or_default();
        (s.ok("\u{2713}"), "on PATH", s.dim(&where_))
    } else if let Some(issue) = shim.issue() {
        let label = if shim.installed {
            "drift"
        } else {
            "not installed"
        };
        (s.brass("\u{2717}"), label, s.brass(&issue))
    } else {
        (s.brass("\u{2717}"), "unknown", s.dim(""))
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

    // factor: what the daemon would gate with (phone > biometric > fail closed).
    let paired = crate::pairing_store::summary().ok().flatten();
    let biometric = keystore::for_host().is_biometric();
    let (glyph, label, note) = if let Some(p) = &paired {
        (
            s.ok("\u{25cf}"),
            "paired phone",
            s.dim(&format!("via {}", p.relay_url)),
        )
    } else if biometric {
        (
            s.ok("\u{25cf}"),
            "biometric",
            s.dim("hardware Touch ID (Secure Enclave)"),
        )
    } else {
        (
            s.brass("\u{2717}"),
            "fail closed",
            s.brass("no factor; run: latch pair"),
        )
    };
    println!("  {}   {glyph} {}  {note}", s.dim("factor"), pad(label, 13));

    // ssh agent: how many keys it would serve.
    let ssh_count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.keys.len())
        .unwrap_or(0);
    let (glyph, label, note) = if ssh_count > 0 {
        (
            s.ok("\u{25cf}"),
            "serving",
            s.dim(&format!(
                "{ssh_count} key(s) · point SSH_AUTH_SOCK: latch sshagent"
            )),
        )
    } else {
        (
            s.dim("\u{25cb}"),
            "no keys",
            s.dim("add one: latch ssh add --vault <V> --item <I> --pubkey-file <p>"),
        )
    };
    println!("  {}     {glyph} {}  {note}", s.dim("ssh"), pad(label, 13));

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

    // Probe the vaults this token can actually route (best effort), through the
    // provider seam rather than calling `op` directly.
    let vaults = OpProvider::new().probe(&token).unwrap_or_default();
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

fn cmd_daemon(args: &[String]) -> i32 {
    match daemon::run(args) {
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

    let shim = paths::ShimStatus::detect();
    let real_op = paths::find_real_op();
    let mut ok = true;

    // 1. shim health (drift): installed, first on PATH, points at this binary.
    ok &= check(
        &s,
        shim.healthy(),
        "shim wins on PATH and is current",
        &shim.issue().unwrap_or_default(),
    );

    // 2. daemon socket reachable.
    let up = daemon_up();
    ok &= check(
        &s,
        up,
        "daemon socket reachable",
        if up {
            ""
        } else {
            "daemon not running (latch start)"
        },
    );

    // 3. socket path fits sun_path (a too-long path binds a truncated name).
    match crate::service::socket_path_fits() {
        Ok(()) => {
            ok &= check(&s, true, "socket path length ok", "");
        }
        Err(e) => {
            ok &= check(&s, false, "socket path length ok", &e);
        }
    }

    // 4. approving factor: paired phone > biometric > fail closed.
    let paired = crate::pairing_store::summary().ok().flatten();
    let biometric = keystore::for_host().is_biometric();
    let (factor_ok, factor_hint) = match (&paired, biometric) {
        (Some(_), _) => (true, "paired phone (sealed remote approval)".to_string()),
        (None, true) => (true, "hardware biometric (Secure Enclave)".to_string()),
        (None, false) => (
            false,
            "no factor: fails closed. Run `latch pair`, or start `--dev-insecure` for dev".into(),
        ),
    };
    ok &= check(&s, factor_ok, "approving factor resolved", &factor_hint);

    // 5. relay reachable, when a pairing names one.
    if let Some(p) = &paired {
        let reachable = relay_reachable(&p.relay_url);
        ok &= check(
            &s,
            reachable,
            "relay reachable",
            if reachable {
                ""
            } else {
                "cannot reach the paired relay (approvals will time out)"
            },
        );
    }

    // 6. a real op to run.
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

    // 7. ssh-agent: report the socket to point SSH_AUTH_SOCK at and the served
    //    key count. Informational (not a pass/fail gate): serving zero keys is a
    //    valid state until Tom adds one.
    let ssh_sock = crate::sshagent::socket_path();
    let ssh_count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.keys.len())
        .unwrap_or(0);
    println!(
        "  {} ssh-agent socket  {}",
        s.ok("\u{2713}"),
        s.dim(&format!(
            "— {ssh_count} key(s); export SSH_AUTH_SOCK={}",
            ssh_sock.display()
        ))
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

/// Best-effort relay reachability: parse `http(s)://host[:port]` and try a short
/// TCP connect. Dependency-free (no HTTP client in this binary); a successful
/// connect is enough to distinguish "relay down" from "relay up" for the doctor.
fn relay_reachable(url: &str) -> bool {
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    let (rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(r) = url.strip_prefix("wss://") {
        (r, 443u16)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (r, 80u16)
    } else {
        (url, 443u16)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(default_port)),
        None => (authority, default_port),
    };
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
            return true;
        }
    }
    false
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

fn cmd_pair(args: &[String]) -> i32 {
    if args.first().map(String::as_str) == Some("list") {
        return pair_list();
    }
    run_pairing(args)
}

/// `latch pair list` / `latch list-paired-devices`: show the persisted pairing.
fn pair_list() -> i32 {
    let s = Style::stdout();
    match crate::pairing_store::summary() {
        Ok(Some(p)) => {
            println!("{}", s.cobalt("paired devices"));
            println!();
            let words = if p.sas_words.is_empty() {
                s.dim("(no SAS on record)")
            } else {
                s.cobalt(&p.sas_words.join(&s.faint(" \u{00b7} ")))
            };
            println!("  {}  {}", s.dim("phone"), words);
            println!("  {}  {}", s.dim("relay"), s.dim(&p.relay_url));
            println!(
                "  {}  {}",
                s.dim("since"),
                s.dim(&format_unix_ms(p.paired_at))
            );
            0
        }
        Ok(None) => {
            println!(
                "  {}",
                s.dim("no paired phone; run: latch pair --relay <url>")
            );
            0
        }
        Err(e) => {
            eprintln!("latch: reading pairing: {e}");
            1
        }
    }
}

/// The real pairing ceremony: mint a QR, wait on the relay for the phone, verify,
/// confirm SAS, deliver the DEK, and persist. `--relay <url>` or `$LATCH_RELAY_URL`.
fn run_pairing(args: &[String]) -> i32 {
    let s = Style::stdout();
    let relay = flag_value(args, "--relay")
        .map(str::to_string)
        .or_else(|| std::env::var("LATCH_RELAY_URL").ok());
    let Some(relay) = relay else {
        eprintln!(
            "usage: latch pair --relay <url>   (or set LATCH_RELAY_URL)\n\
             \n\
             The relay is the blind mailbox the Mac and phone meet on. Use your\n\
             own (self-hosted) relay URL, e.g. https://relay.example."
        );
        return 2;
    };
    let auto_yes = has_flag(args, "--yes") || has_flag(args, "-y");

    if crate::pairing_store::exists() {
        println!(
            "  {}",
            s.brass(
                "a phone is already paired; re-pairing will replace it (latch unpair to remove)"
            )
        );
    }

    let ks = keystore::for_host();
    let daemon_identity = DeviceIdentity::generate();

    let mut present_qr = |unicode: &str, b64: &str| {
        println!("{}", s.cobalt("latch pair"));
        println!();
        println!(
            "  {}",
            s.dim("Scan this with the Latch approver on your phone:")
        );
        println!();
        println!("{unicode}");
        println!("  {}", s.faint("or paste this pairing code into the app:"));
        println!("  {b64}");
        println!();
        println!("  {}", s.dim("Waiting for the phone to respond..."));
    };
    let mut confirm = |words: &[&'static str; 6]| -> bool {
        println!();
        println!(
            "  {}",
            s.dim("Confirm these six words match your phone's screen:")
        );
        println!("    {}", s.cobalt(&words.join(&s.faint(" \u{00b7} "))));
        if auto_yes {
            println!("  {}", s.faint("(--yes) confirmed"));
            return true;
        }
        print!("  match? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    };
    let mut make_channel = |mailbox: [u8; 32]| crate::pair::relay_channel(&relay, mailbox);

    let opts = crate::pair::CeremonyOpts {
        relay_url: relay.clone(),
        response_timeout: std::time::Duration::from_secs(180),
        flush_grace: std::time::Duration::from_millis(750),
        now: &latch_proto::now_ms,
        make_channel: &mut make_channel,
        present_qr: &mut present_qr,
        confirm_sas: &mut confirm,
    };

    let new_pairing = match crate::pair::run_ceremony(daemon_identity, opts) {
        Ok(np) => np,
        Err(e) => {
            eprintln!("{} pairing failed: {e:#}", s.deny("\u{2717}"));
            return 1;
        }
    };

    if let Err(e) = crate::pairing_store::save(ks.as_ref(), &new_pairing) {
        eprintln!(
            "{} pairing succeeded but could not be saved: {e}",
            s.deny("\u{2717}")
        );
        return 1;
    }

    println!();
    println!("{} phone paired and saved", s.ok("\u{2713}"));
    println!(
        "  {}",
        s.dim("the daemon now gates every request on your phone")
    );
    println!(
        "  {}",
        s.faint("restart the daemon to arm it: latch restart")
    );
    0
}

fn cmd_unpair() -> i32 {
    let s = Style::stdout();
    let ks = keystore::for_host();
    match crate::pairing_store::remove(ks.as_ref()) {
        Ok(true) => {
            println!("{} phone unpaired", s.ok("\u{2713}"));
            println!(
                "  {}",
                s.brass(
                    "the daemon will fail closed until you pair again or provision a biometric"
                )
            );
            println!("  {}", s.faint("restart to apply: latch restart"));
            0
        }
        Ok(false) => {
            println!("  {}", s.dim("no phone was paired"));
            0
        }
        Err(e) => {
            eprintln!("latch: unpair failed: {e}");
            1
        }
    }
}

fn cmd_setup(args: &[String]) -> i32 {
    let s = Style::stdout();
    println!("{}", s.cobalt("latch setup"));
    println!();

    // 1. Keystore DEK. On macOS this needs the Secure Enclave (NEEDS
    //    VERIFICATION); a dev keystore provisions immediately. A failure here is
    //    not fatal to the rest of setup, so we report and continue.
    let ks = keystore::for_host();
    match ks.ensure_dek() {
        Ok(()) => println!("  {} keystore ready", s.ok("\u{2713}")),
        Err(e) => println!(
            "  {} keystore: {}",
            s.brass("\u{2717}"),
            s.dim(&e.to_string())
        ),
    }

    // 2. Install the shim.
    match crate::setup::install_shim() {
        Ok((link, target)) => {
            println!("  {} shim installed", s.ok("\u{2713}"));
            println!(
                "    {} {} -> {}",
                s.dim("link"),
                link.display(),
                target.display()
            );
        }
        Err(e) => {
            eprintln!("  {} shim install failed: {e}", s.deny("\u{2717}"));
            return 1;
        }
    }

    // 3. Put the shim on PATH for interactive shells.
    match crate::setup::ensure_profile_path() {
        Ok(true) => println!(
            "  {} added ~/.latch/bin to your shell profile (open a new shell)",
            s.ok("\u{2713}")
        ),
        Ok(false) => println!("  {} shell profile already has the shim", s.ok("\u{2713}")),
        Err(e) => println!(
            "  {} shell profile: {}",
            s.brass("\u{2717}"),
            s.dim(&e.to_string())
        ),
    }

    // 4. launchd agent (RunAtLoad + KeepAlive) with a shim-first PATH for GUI
    //    tools. Mac-runtime; a bootstrap failure still leaves the plist written.
    match crate::setup::install_and_load_agent() {
        Ok(plist) => {
            println!("  {} launchd agent loaded", s.ok("\u{2713}"));
            println!("    {} {}", s.dim("plist"), plist.display());
        }
        Err(e) => println!(
            "  {} launchd: {} {}",
            s.brass("\u{2717}"),
            s.dim(&e.to_string()),
            s.faint("(you can load it later with: latch start)")
        ),
    }

    // 5. Pairing, if a relay was given; else point the way.
    println!();
    if flag_value(args, "--relay").is_some() || std::env::var_os("LATCH_RELAY_URL").is_some() {
        return run_pairing(args);
    }
    println!("  {}", s.dim("last step: pair your phone"));
    println!("    {}", s.cobalt("latch pair --relay <url>"));
    println!();
    cmd_status()
}

fn cmd_service(verb: &str) -> i32 {
    let s = Style::stdout();
    let result = match verb {
        "start" => crate::service::install_plist()
            .and_then(|p| crate::service::bootstrap(&p).map(|_| "started")),
        "stop" => crate::service::bootout().map(|_| "stopped"),
        "restart" => crate::service::kickstart().map(|_| "restarted"),
        _ => unreachable!("dispatch guards the verb"),
    };
    match result {
        Ok(word) => {
            println!("{} daemon {word}", s.ok("\u{2713}"));
            0
        }
        Err(e) => {
            eprintln!("{} {verb} failed: {e:#}", s.deny("\u{2717}"));
            1
        }
    }
}

/// Format a unix-ms timestamp as a compact local-agnostic UTC date-time.
fn format_unix_ms(ms: u64) -> String {
    // A dependency-free rendering: seconds since epoch as an ISO-ish string is
    // overkill here; show the unix seconds so `pair list` stays informative
    // without pulling `chrono`/`time` into the single binary.
    let secs = ms / 1000;
    format!("unix {secs}")
}

fn cmd_ssh(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("add") => ssh_add(&args[1..]),
        Some("list") | None => ssh_list(),
        Some("remove") | Some("rm") => ssh_remove(args.get(1).map(String::as_str)),
        _ => {
            eprintln!("usage: latch ssh <add|list|remove>");
            2
        }
    }
}

/// `latch ssh add --vault <V> --item <I> [--field <f>] [--comment <c>]
/// (--pubkey-file <path> | --pubkey-stdin)`: register a 1Password SSH key for the
/// agent to serve. Only the public key (not secret) is provided here; the private
/// key is fetched per-signature. v1 accepts ed25519 only.
fn ssh_add(args: &[String]) -> i32 {
    let s = Style::stdout();
    let (Some(vault), Some(item)) = (
        flag_value(args, "--vault").map(str::to_string),
        flag_value(args, "--item").map(str::to_string),
    ) else {
        eprintln!(
            "usage: latch ssh add --vault <V> --item <I> [--field <f>] [--comment <c>] \
             (--pubkey-file <path> | --pubkey-stdin)"
        );
        return 2;
    };
    let field = flag_value(args, "--field")
        .unwrap_or("private key")
        .to_string();
    let comment = flag_value(args, "--comment").unwrap_or("").to_string();

    // The public key line comes from a file or stdin (never secret).
    let public_key = if let Some(path) = flag_value(args, "--pubkey-file") {
        match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("latch: reading {path}: {e}");
                return 1;
            }
        }
    } else if has_flag(args, "--pubkey-stdin") {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("latch: reading public key from stdin: {e}");
            return 1;
        }
        buf
    } else {
        eprintln!("latch: provide the public key with --pubkey-file <path> or --pubkey-stdin");
        return 2;
    };
    let public_key = public_key.trim().to_string();

    let entry = crate::sshagent::SshKeyEntry {
        public_key,
        vault: vault.clone(),
        item: item.clone(),
        field,
        comment,
    };
    // Validate before persisting: it must parse as an ed25519 public key.
    let Some(id) = crate::sshagent::resolve_identity(&entry) else {
        eprintln!(
            "{} not a usable ed25519 public key (v1 serves ed25519 only)",
            s.deny("\u{2717}")
        );
        return 1;
    };

    let mut cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("latch: loading ssh-keys config: {e}");
            return 1;
        }
    };
    if cfg.keys.iter().any(|k| k.vault == vault && k.item == item) {
        eprintln!("latch: op://{vault}/{item} is already served (remove it first to replace)");
        return 1;
    }
    cfg.keys.push(entry);
    if let Err(e) = cfg.save() {
        eprintln!("latch: saving ssh-keys config: {e}");
        return 1;
    }

    println!("{} serving {}", s.ok("\u{2713}"), s.cobalt(&id.label));
    println!("  {}  {}", s.dim("key"), s.dim(&id.fingerprint));
    println!("  {}  {}", s.dim("ref"), s.dim(&id.key_ref));
    println!(
        "  {}",
        s.faint("restart the daemon to serve it: latch restart")
    );
    0
}

fn ssh_list() -> i32 {
    let s = Style::stdout();
    let cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("latch: loading ssh-keys config: {e}");
            return 1;
        }
    };
    if cfg.keys.is_empty() {
        println!(
            "  {}",
            s.dim("no SSH keys served; add one: latch ssh add --vault <V> --item <I> --pubkey-file <p>")
        );
        return 0;
    }
    println!("{}", s.cobalt("ssh keys served"));
    println!();
    for e in &cfg.keys {
        match crate::sshagent::resolve_identity(e) {
            Some(id) => {
                println!("  {}  {}", pad(&id.label, 18), s.dim(&id.fingerprint));
                println!(
                    "  {}  {}",
                    pad("", 18),
                    s.faint(&format!("op://{}/{} · {}", e.vault, e.item, id.comment))
                );
            }
            None => println!(
                "  {}  {}",
                pad(&e.item, 18),
                s.brass("unusable (not an ed25519 public key)")
            ),
        }
    }
    0
}

fn ssh_remove(item: Option<&str>) -> i32 {
    let s = Style::stdout();
    let Some(item) = item else {
        eprintln!("usage: latch ssh remove <item>");
        return 2;
    };
    let mut cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("latch: loading ssh-keys config: {e}");
            return 1;
        }
    };
    let before = cfg.keys.len();
    cfg.keys.retain(|k| k.item != item);
    if cfg.keys.len() == before {
        println!("  {}", s.dim(&format!("no served key named {item}")));
        return 0;
    }
    if let Err(e) = cfg.save() {
        eprintln!("latch: saving ssh-keys config: {e}");
        return 1;
    }
    println!("{} stopped serving {}", s.ok("\u{2713}"), s.cobalt(item));
    println!(
        "  {}",
        s.faint("restart the daemon to apply: latch restart")
    );
    0
}

/// `latch sshagent`: print the SSH_AUTH_SOCK a user points `ssh`/`git` at, plus
/// the served-key count and a guidance line.
fn cmd_sshagent() -> i32 {
    let s = Style::stdout();
    let sock = crate::sshagent::socket_path();
    let count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.keys.len())
        .unwrap_or(0);
    println!("{}", s.cobalt("latch ssh-agent"));
    println!();
    println!(
        "  {}  {}",
        s.dim("socket"),
        s.dim(&sock.display().to_string())
    );
    println!("  {}  {}", s.dim("keys"), s.dim(&format!("{count} served")));
    println!();
    println!(
        "  {}",
        s.dim("Point ssh and git at Latch by exporting this in your shell profile:")
    );
    println!();
    println!(
        "    {}",
        s.cobalt(&format!("export SSH_AUTH_SOCK=\"{}\"", sock.display()))
    );
    println!();
    println!(
        "  {}",
        s.faint("then `ssh-add -l` lists your served keys and `git push` asks your phone.")
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
    let (link, target) = match crate::setup::install_shim() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("latch: {e:#}");
            return 1;
        }
    };

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
    println!(
        "  {}",
        s.faint("or run `latch setup`, which edits your profile and loads the daemon.")
    );
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
