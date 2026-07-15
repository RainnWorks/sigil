//! The `sigil` subcommands. Hand-rolled dispatch: v0 has a handful of verbs
//! with no flags worth a parser dependency.

use std::io::Read;
use std::os::unix::net::UnixStream;

use sigil_proto::DeviceIdentity;
use zeroize::Zeroizing;

use crate::daemon;
use crate::json::{self, ControlResult};
use crate::keystore;
use crate::local::{self, Frame, Reply};
use crate::paths;
use crate::settings::{self, Settings};
use crate::style::Style;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Dispatch the lean `sigil` binary: the runtime/daemon verbs and the
/// `sigil <cmd>` gating primitive. Configuration management (rules, sources,
/// accounts, settings, wipe) is NOT here — it lives in the `sigil-config`
/// binary ([`run_config`]), so a program literally named `config`/`account`/…
/// stays gateable as `sigil <that-name> …`.
///
/// `--json` is a global flag: it is stripped from the args once here (so each
/// subcommand's own flag parsing is unchanged) and threaded to the emitting
/// commands as a bool.
pub fn run_gating() -> i32 {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = extract_flag(&mut args, "--json");
    match args.first().map(String::as_str).unwrap_or("") {
        "" | "status" => cmd_status(),
        "up" => crate::up::cmd_up(),
        "daemon" => cmd_daemon(&args[1..]),
        "doctor" => cmd_doctor(),
        "setup" => cmd_setup(&args[1..]),
        "pair" => cmd_pair(&args[1..], json),
        "qr" => cmd_qr(&args[1..]),
        "unpair" => cmd_unpair(json),
        "start" | "stop" | "restart" => cmd_service(&args[0]),
        "lease" => cmd_lease(&args[1..]),
        "lockdown" => cmd_lockdown(&args[1..]),
        "approve" => cmd_approve(&args[1..]),
        "deny" => cmd_deny(&args[1..]),
        "history" => cmd_history(),
        "pending" => cmd_pending(),
        "ssh" => cmd_ssh(&args[1..]),
        "sshagent" => cmd_sshagent(),
        "shim" => cmd_shim(&args[1..], json),
        "run" => cmd_run(&args[1..]),
        "version" | "--version" | "-V" => {
            println!("sigil {VERSION}");
            0
        }
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            // Not a reserved verb: the `sigil <cmd> [args]` primitive. A leading
            // '-' is a flag typo, not a command, so show help instead of trying
            // to gate a "command" named like an option.
            debug_assert!(
                !is_reserved_verb(other),
                "a reserved verb reached command dispatch; the match above must handle it"
            );
            if other.starts_with('-') {
                eprintln!("sigil: unknown option '{other}'\n");
                print_help();
                return 2;
            }
            dispatch_command(&args)
        }
    }
}

/// Dispatch the `sigil-config` binary: all configuration management. Its verbs
/// are the config engine (`source`/`rule`/`list`/`export`/`import`) plus
/// `account`, `settings`, `mac-approvals`, and `wipe`. It never gates a command;
/// an unknown verb is an error, not a `sigil <cmd>` invocation.
pub fn run_config() -> i32 {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = extract_flag(&mut args, "--json");
    match args.first().map(String::as_str).unwrap_or("") {
        "" | "list" => config_list(json),
        "source" => cmd_config_source(&args[1..], json),
        "rule" => cmd_config_rule(&args[1..], json),
        "export" => config_export(),
        "import" => config_import(json),
        // The one-command convenience desugar (source + rule in one step).
        "add" => config_add(&args[1..], json),
        "remove" | "rm" => config_remove(args.get(1).map(String::as_str), json),
        "proxy" => cmd_proxy(&args[1..], json),
        "settings" => cmd_settings(&args[1..], json),
        "mac-approvals" => cmd_mac_approvals(&args[1..], json),
        "wipe" => cmd_wipe(&args[1..], json),
        "version" | "--version" | "-V" => {
            println!("sigil-config {VERSION}");
            0
        }
        "help" | "--help" | "-h" => {
            print_config_help();
            0
        }
        other => {
            eprintln!("sigil-config: unknown command '{other}'\n");
            print_config_help();
            2
        }
    }
}

/// Whether `cmd` is a reserved verb in the lean `sigil` binary (handled by
/// [`run_gating`]) and therefore takes precedence over the `sigil <cmd>`
/// primitive. The management verbs (config/account/settings/mac-approvals/wipe)
/// are deliberately NOT reserved here — they moved to `sigil-config`, which frees
/// those names to be gated. The escape hatch for a tool named like a residual
/// reserved verb is `sigil run -- <cmd>`.
pub fn is_reserved_verb(cmd: &str) -> bool {
    matches!(
        cmd,
        "" | "status"
            | "up"
            | "daemon"
            | "doctor"
            | "setup"
            | "pair"
            | "qr"
            | "unpair"
            | "start"
            | "stop"
            | "restart"
            | "lease"
            | "lockdown"
            | "approve"
            | "deny"
            | "history"
            | "pending"
            | "ssh"
            | "sshagent"
            | "shim"
            | "run"
            | "version"
            | "--version"
            | "-V"
            | "help"
            | "--help"
            | "-h"
    )
}

/// Forward a `sigil <cmd> [args]` invocation to the daemon (gated), or exec the
/// real tool if the daemon is down. `argv[0]` is the command name. Shared by the
/// primitive dispatch, `sigil run -- <cmd>`, and the transparent shim alias
/// (via [`crate::shim::dispatch`]). Never returns.
fn dispatch_command(argv: &[String]) -> ! {
    crate::shim::dispatch(argv.to_vec())
}

/// `sigil run [--] <cmd> [args]`: the unambiguous escape hatch for a command that
/// collides with a reserved verb (or whose args look like sigil flags). Strips a
/// leading `--`, then dispatches the rest exactly like the `sigil <cmd>`
/// primitive. Never returns (the child's exit code becomes ours).
fn cmd_run(args: &[String]) -> i32 {
    let rest = strip_run_prefix(args);
    if rest.is_empty() {
        eprintln!("usage: sigil run [--] <cmd> [args...]");
        return 2;
    }
    dispatch_command(rest)
}

/// Strip an optional leading `--` from `sigil run`'s arguments, yielding the
/// command and its args. `sigil run -- op ...` and `sigil run op ...` are
/// equivalent; the `--` only matters when the tool's own args would otherwise be
/// eaten as sigil flags.
fn strip_run_prefix(args: &[String]) -> &[String] {
    match args.first().map(String::as_str) {
        Some("--") => &args[1..],
        _ => args,
    }
}

/// Remove every occurrence of `name` from `args`, returning whether it was
/// present. Used to lift the global `--json` flag out before subcommand parsing.
fn extract_flag(args: &mut Vec<String>, name: &str) -> bool {
    let before = args.len();
    args.retain(|a| a != name);
    args.len() != before
}

/// Print a locally-built control result (no daemon round trip) as JSON, and
/// return its exit code.
fn emit_local_control(result: &ControlResult) -> i32 {
    println!("{}", json::to_line(result));
    i32::from(!result.ok)
}

fn print_help() {
    println!(
        "sigil {VERSION} \u{b7} remote-approval instrument: gate any CLI on your phone

usage: sigil <cmd> [args...]   the primitive: gate <cmd>, inject its env, run it
       sigil <verb>            a reserved runtime verb (below)

  <cmd> [args...]   run a command gated on your phone when a rule matches it
                    (e.g. sigil op read op://…, sigil gcloud …). An unmatched
                    command is refused; configure one with: sigil-config add <cmd>
  run -- <cmd>      escape hatch: run <cmd> even if it collides with a verb
  status            instrument panel: daemon, shim, op, factor
  up                ensure everything: install the binary and launchd agent,
                    heal a dead or wedged daemon, wire the shim, check pairing.
                    Idempotent; run it any time something looks off
  setup             guided first run: shim, PATH, launchd, then pair
  daemon [--dev-insecure]  run the approval daemon (foreground). Without a
                    paired phone or a hardware biometric it fails closed;
                    --dev-insecure enables local self-approval for dev only.
  doctor            diagnose shim drift, factor, relay, socket, and op
  pair --relay <url> [--name <label>] [--qr-png <path>]   pair a phone over the
                    relay (renders a QR; --qr-png also writes the pairing code as
                    a scannable PNG). Additive: adds a device without dropping
                    the ones already paired
  pair list         list paired devices
  pair remove <id>  forget one paired device by id (from pair list)
  unpair            forget every paired phone
  qr <data>         render <data> as a QR in the terminal; --stdin reads it from
                    stdin, --png <path> also writes a PNG, --out svg emits SVG,
                    --scale <n> sets pixels per module (PNG/SVG, default 8)
  start|stop|restart   control the launchd daemon agent
  lease list        list active session leases with countdowns
  lease revoke <p>  revoke leases whose grant-key hex starts with <p>
  lockdown [--clear]  seal the daemon (deny + refuse) or unseal it
  approve --local --id <id> [--lease]  approve a pending request at the Mac
  deny --local --id <id>               deny a pending request at the Mac
  history           the decision audit log (names and metadata only)
  pending           requests currently parked for a local decision
  ssh add-file      serve a local key file (--path <key>, signs from ~/.ssh/… [--host h])
  ssh add-stored    seal a private key under threshold, phone-gated (key on stdin, [--host h])
  ssh list          list the SSH keys the agent serves
  ssh remove <id>   stop serving an SSH key (by its path or stored id)
  ssh config        route chosen hosts via ~/.ssh/config (--install / --uninstall)
  sshagent          print the SSH_AUTH_SOCK to point ssh/git at Sigil
  shim install      symlink ~/.sigil/bin/op at this binary
  shim add <cmd>    drop a transparent alias binary for a configured command
  version           print version
  help              print this message

Configuration (rules, sources, accounts, settings, wipe) lives in a separate
binary: run `sigil-config help`. Keeping it off this binary means a program
literally named `config`/`account`/… stays gateable as `sigil <that-name> …`.

The Mac app speaks the daemon control socket directly (see PROTOCOL.md):
status, doctor, lease, lockdown, approve, deny, history, and pending are
socket queries the human CLI renders."
    );
}

/// Help for the `sigil-config` management binary.
fn print_config_help() {
    println!(
        "sigil-config {VERSION} \u{b7} Sigil configuration management

usage: sigil-config <cmd> [args...]   author rules/sources, manage accounts

  add <cmd> --provider <id> [--source <p>] [--account <l>] [--leasable [--lease-max <secs>]]
                    convenience: author a source + rule for one command
                    (providers: 1password, env-file, env)
  source add <name> --provider <id> [--account <l>] [--path <f>]
                    add a named secret source; also: source list|remove
  source env set <name> --key <KEY>    seal one inline env VALUE (read from
                    stdin, never argv) under the DEK; --stdin reads KEY=VALUE
                    lines instead. source env unset <name> --key <KEY> removes
                    one. Values are AES-256-GCM at rest; list/export show only
                    KEY names
  rule add <name> --source <s> [--command <c>] [--subcommand <s>]
                    [--argv-contains <str>...] [--flag <f>...] [--flag-eq <f>=<v>...]
                    [--leasable [--lease-max <secs>]] [--timeout <sec>]
                    a match -> gate + inject rule (default run-once; --leasable
                    allows a session lease up to the cap). also: rule list|remove
  list              summarize sources and rules (--json = the whole config)
  export            print the whole config as JSON (for the desktop to load)
  import            replace the whole config from JSON on stdin
  remove <cmd>      forget a command's rule (and its like-named source)
  proxy add <cmd>   install a transparent PATH alias so a bare <cmd> hits Sigil;
                    also: proxy remove <cmd> [--purge] | list | status |
                    doctor [<cmd>] | env [--shell zsh|bash|fish|nu]
  settings get|set  read or change preferences (timeouts, relay, retention)
  mac-approvals --enable|--phone-only  toggle the Mac local-approval factor
  wipe [--force]    remove pairing, accounts, keys, config, and settings
  version           print version
  help              print this message

--json is for the CLI-only mutation commands the Mac app shells out for
(source/rule/list/export/import, account, settings, wipe, mac-approvals).
Re-run `sigil restart` to apply a config change."
    );
}

/// Fetch the status report. When the daemon is up it is the source of truth
/// (`Frame::Status`); when it is down the CLI computes the host-side view locally
/// via the same [`crate::report`] builder so `sigil status` still works headless.
fn fetch_status() -> json::StatusJson {
    if let Ok(Reply::Json { body }) = send_control(&Frame::Status) {
        if let Ok(st) = serde_json::from_str::<json::StatusJson>(&body) {
            return st;
        }
    }
    crate::report::status(false, crate::report::Runtime::down())
}

fn cmd_status() -> i32 {
    let s = Style::stdout();
    let st = fetch_status();

    let head = if st.locked_down {
        s.brass("locked down")
    } else if st.daemon_up && st.factor.kind != "fail_closed" {
        s.ok("armed")
    } else if st.daemon_up {
        s.brass("idle")
    } else {
        s.deny("down")
    };
    println!("{} {} {}", s.cobalt("sigil"), s.faint("\u{b7}"), head);
    println!();

    // daemon
    let (glyph, label, note) = if st.daemon_up {
        (s.ok("\u{25cf}"), "listening", s.dim(&st.socket))
    } else {
        (s.deny("\u{2717}"), "down", s.dim("socket not listening"))
    };
    println!("  {}  {glyph} {}  {note}", s.dim("daemon"), pad(label, 13));

    // shim (with drift detection)
    let (glyph, label, note) = match st.shim.kind.as_str() {
        "healthy" => (
            s.ok("\u{2713}"),
            "on PATH",
            s.dim(st.shim.path.as_deref().unwrap_or("")),
        ),
        "not_installed" => (
            s.brass("\u{2717}"),
            "not installed",
            s.brass(st.shim.issue.as_deref().unwrap_or("")),
        ),
        "drift" => (
            s.brass("\u{2717}"),
            "drift",
            s.brass(st.shim.issue.as_deref().unwrap_or("")),
        ),
        _ => (s.brass("\u{2717}"), "unknown", s.dim("")),
    };
    println!("  {}    {glyph} {}  {note}", s.dim("shim"), pad(label, 13));

    // op
    let (glyph, label, note) = if st.op.found {
        (
            s.ok("\u{2713}"),
            "found",
            s.dim(st.op.path.as_deref().unwrap_or("")),
        )
    } else {
        (s.deny("\u{2717}"), "missing", s.dim("no `op` on PATH"))
    };
    println!("  {}      {glyph} {}  {note}", s.dim("op"), pad(label, 13));

    // accounts
    let (glyph, label, note) = if st.accounts > 0 {
        (
            s.ok("\u{2713}"),
            "configured",
            s.dim(&format!("{} sealed secret(s)", st.accounts)),
        )
    } else {
        (
            s.brass("\u{2717}"),
            "none",
            s.dim("set inline env values: sigil-config source env set <name> --stdin"),
        )
    };
    println!(
        "  {} {glyph} {}  {note}",
        s.dim("sealed env"),
        pad(label, 13)
    );

    // factor
    let (glyph, label, note) = match st.factor.kind.as_str() {
        "phone" => (
            s.ok("\u{25cf}"),
            "paired phone",
            s.dim(&format!(
                "via {}",
                st.factor.relay.as_deref().unwrap_or("relay")
            )),
        ),
        "biometric" => (
            s.ok("\u{25cf}"),
            "biometric",
            s.dim("hardware Touch ID (Secure Enclave)"),
        ),
        _ => (
            s.brass("\u{2717}"),
            "fail closed",
            s.brass("no factor; run: sigil pair"),
        ),
    };
    println!("  {}   {glyph} {}  {note}", s.dim("factor"), pad(label, 13));

    // ssh agent: how many keys it would serve (a local CLI convenience row; the
    // count is not part of the machine status shape).
    let ssh_count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.files.len() + c.stored.len())
        .unwrap_or(0);
    let (glyph, label, note) = if ssh_count > 0 {
        (
            s.ok("\u{25cf}"),
            "serving",
            s.dim(&format!(
                "{ssh_count} key(s) \u{b7} point SSH_AUTH_SOCK: sigil sshagent"
            )),
        )
    } else {
        (
            s.dim("\u{25cb}"),
            "no keys",
            s.dim("add one: sigil ssh add-file --path <key>"),
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
            eprintln!("sigil: unexpected reply: {other:?}");
            1
        }
        Err(e) => {
            eprintln!("sigil: daemon unreachable ({e}); is it running?");
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

/// Collect every value of a repeatable `--flag value` / `--flag=value` option.
/// Used by the rule matcher flags (`--argv-contains`, `--flag`, `--flag-eq`).
fn flag_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let eq = format!("{name}=");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix(&eq) {
            out.push(v.to_string());
        } else if a == name {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

/// Deserialize a `Reply::Json` array body from a query frame into a typed vec,
/// or `None` when the daemon is unreachable / replied unexpectedly.
fn query_list<T: serde::de::DeserializeOwned>(frame: &Frame) -> Option<Vec<T>> {
    match send_control(frame) {
        Ok(Reply::Json { body }) => serde_json::from_str(&body).ok(),
        _ => None,
    }
}

fn cmd_lease(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("list") | None => {
            let s = Style::stdout();
            let Some(leases) = query_list::<json::LeaseJson>(&Frame::LeaseList) else {
                println!("  {}", s.dim("daemon unreachable; is it running?"));
                return 0;
            };
            if leases.is_empty() {
                println!("  {}", s.dim("no active leases"));
                return 0;
            }
            let now = sigil_proto::now_ms();
            println!("{}", s.cobalt("leases"));
            println!();
            for l in &leases {
                let left = l.expires_ms.saturating_sub(now) / 1000;
                println!(
                    "  {}  {}  {}  {}",
                    s.dim(&l.grant_hex[..12.min(l.grant_hex.len())]),
                    pad(&l.account, 14),
                    l.scope,
                    s.faint(&format!("{left}s left"))
                );
            }
            0
        }
        Some("revoke") => {
            let Some(prefix) = args.get(1) else {
                eprintln!("usage: sigil lease revoke <grant-hex-prefix>");
                return 2;
            };
            print_control(send_control(&Frame::LeaseRevoke {
                prefix: prefix.clone(),
            }))
        }
        _ => {
            eprintln!("usage: sigil lease <list|revoke <prefix>>");
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
        eprintln!("usage: sigil approve --local --id <id> [--lease]");
        return 2;
    };
    print_control(send_control(&Frame::Approve {
        id,
        lease: has_flag(args, "--lease"),
    }))
}

fn cmd_deny(args: &[String]) -> i32 {
    let Some(id) = flag_value(args, "--id").map(str::to_string) else {
        eprintln!("usage: sigil deny --local --id <id>");
        return 2;
    };
    print_control(send_control(&Frame::Deny { id }))
}

/// `sigil history`: the decision audit log, newest-first. Read from the daemon
/// (`Frame::History`) when up, else directly from the on-disk log so it works
/// headless (the log is a read-only file the daemon owns as writer).
fn cmd_history() -> i32 {
    let s = Style::stdout();
    let entries: Vec<json::HistoryJson> = query_list(&Frame::History)
        .unwrap_or_else(|| crate::audit::load().iter().map(|e| e.to_json()).collect());
    if entries.is_empty() {
        println!("  {}", s.dim("no history yet"));
        return 0;
    }
    println!("{}", s.cobalt("history"));
    println!();
    for e in &entries {
        let glyph = match e.decision.as_str() {
            "approved" => s.ok("\u{2713}"),
            "denied" => s.deny("\u{2717}"),
            _ => s.brass("\u{25cb}"),
        };
        println!(
            "  {glyph} {}  {}  {}",
            pad(&e.label, 28),
            s.dim(&e.account),
            s.faint(&format!("{} \u{b7} {}", e.process, e.via))
        );
    }
    0
}

/// `sigil pending`: the requests parked for a local decision. A socket query;
/// the Mac app subscribes to `Frame::SubscribePending` for live updates instead.
fn cmd_pending() -> i32 {
    let s = Style::stdout();
    let Some(items) = query_list::<json::PendingJson>(&Frame::Pending) else {
        println!("  {}", s.dim("daemon unreachable; is it running?"));
        return 0;
    };
    if items.is_empty() {
        println!("  {}", s.dim("nothing awaiting a local decision"));
        return 0;
    }
    println!("{}", s.cobalt("pending"));
    println!();
    for it in &items {
        println!("  {}  {}", s.dim(&it.id), it.command.join(" "));
    }
    0
}

fn cmd_daemon(args: &[String]) -> i32 {
    match daemon::run(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sigil daemon: {e:#}");
            1
        }
    }
}

/// Fetch the doctor checks. Source of truth is the daemon (`Frame::Doctor`) when
/// up; otherwise the CLI runs the same [`crate::report`] builder locally so
/// `sigil doctor` still diagnoses a down daemon.
fn fetch_doctor() -> Vec<json::CheckJson> {
    if let Ok(Reply::Json { body }) = send_control(&Frame::Doctor) {
        if let Ok(checks) = serde_json::from_str::<Vec<json::CheckJson>>(&body) {
            return checks;
        }
    }
    crate::report::doctor(false)
}

fn cmd_doctor() -> i32 {
    let checks = fetch_doctor();
    let s = Style::stdout();
    println!("{}", s.cobalt("sigil doctor"));
    println!();
    let mut ok = true;
    for (i, c) in checks.iter().enumerate() {
        let informational = i + 1 == checks.len(); // the ssh-agent row
        if informational {
            println!(
                "  {} {}  {}",
                s.ok("\u{2713}"),
                c.label,
                s.dim(&format!("\u{b7} {}", c.hint))
            );
        } else {
            ok &= check(&s, c.ok, &c.label, &c.hint);
        }
    }

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
        println!("  {glyph} {label}  {}", s.dim(&format!("\u{b7} {hint}")));
    }
    ok
}

fn cmd_pair(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("list") => return pair_list(json),
        Some("remove") => return pair_remove(&args[1..], json),
        _ => {}
    }
    if json {
        return run_pairing_json(args);
    }
    run_pairing(args)
}

/// `sigil qr <data> [--stdin] [--png <path>] [--out svg] [--scale <n>]`: render
/// arbitrary data as a QR. The terminal (or SVG, with `--out svg`) rendering goes
/// to stdout; `--png <path>` additionally writes a scannable PNG. Data comes from
/// the first positional argument, or from stdin with `--stdin` (preferred for
/// large payloads). Reuses [`crate::qr`], the same renderer the pairing QR uses.
fn cmd_qr(args: &[String]) -> i32 {
    let s = Style::stdout();
    let scale = flag_value(args, "--scale")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(8);
    let png = flag_value(args, "--png");
    let svg = matches!(flag_value(args, "--out"), Some("svg"));

    let data = if has_flag(args, "--stdin") {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("{} reading data from stdin: {e}", s.deny("\u{2717}"));
            return 1;
        }
        // A single trailing newline is the shell's, not the payload's.
        buf.trim_end_matches(['\r', '\n']).to_string()
    } else {
        match qr_positional(args) {
            Some(d) => d,
            None => {
                eprintln!(
                    "usage: sigil qr <data> [--png <path>] [--out svg] [--scale <n>]\n\
                     \x20      sigil qr --stdin [--png <path>]   (read data from stdin)"
                );
                return 2;
            }
        }
    };
    if data.is_empty() {
        eprintln!("{} no data to encode (empty input)", s.deny("\u{2717}"));
        return 2;
    }

    // stdout artifact: SVG on request, otherwise the terminal picture.
    let rendered = if svg {
        crate::qr::render_svg(&data, scale)
    } else {
        crate::qr::render_terminal(&data)
    };
    match rendered {
        Ok(text) => print!("{text}"),
        Err(e) => {
            eprintln!("{} encoding the QR: {e:#}", s.deny("\u{2717}"));
            return 1;
        }
    }

    // --png writes a file in addition to the stdout artifact.
    if let Some(path) = png {
        let path = std::path::Path::new(path);
        if let Err(e) = crate::qr::write_png(&data, path, scale) {
            eprintln!("{} writing the PNG: {e:#}", s.deny("\u{2717}"));
            return 1;
        }
        match crate::qr::png_side_px(&data, scale) {
            Ok(side) => eprintln!(
                "{} wrote {} ({side}x{side} px)",
                s.ok("\u{2713}"),
                path.display()
            ),
            Err(_) => eprintln!("{} wrote {}", s.ok("\u{2713}"), path.display()),
        }
    }
    0
}

/// The first non-flag positional argument to `sigil qr`, skipping the value-taking
/// flags (`--png`, `--out`, `--scale`) and their values and any boolean flag. Kept
/// separate from [`flag_value`] because the QR data is a bare positional, not a
/// flag value.
fn qr_positional(args: &[String]) -> Option<String> {
    const VALUE_FLAGS: [&str; 3] = ["--png", "--out", "--scale"];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some((flag, _)) = a.split_once('=') {
            if VALUE_FLAGS.contains(&flag) {
                continue;
            }
        }
        if VALUE_FLAGS.contains(&a.as_str()) {
            it.next(); // consume the flag's value
            continue;
        }
        if a.starts_with('-') {
            continue; // a boolean flag (e.g. --stdin) or an unknown option
        }
        return Some(a.clone());
    }
    None
}

/// `sigil pair list`: show every persisted device (#36 multi-device). The JSON
/// form carries the full `devices` array plus a `paired` primary for a
/// single-device decoder (back-compat).
fn pair_list(json: bool) -> i32 {
    let s = Style::stdout();
    let devices = match crate::pairing_store::list_devices() {
        Ok(d) => d,
        Err(e) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    false,
                    format!("reading pairing: {e}"),
                ));
            }
            eprintln!("sigil: reading pairing: {e}");
            return 1;
        }
    };

    if json {
        let devices_json: Vec<json::PairedDeviceJson> = devices
            .iter()
            .map(|d| json::PairedDeviceJson {
                device_id: d.device_id.clone(),
                label: device_label(&d.label),
                name: device_label(&d.label),
                sas_words: d.sas_words.clone(),
                relay_url: d.relay_url.clone(),
                paired_ms: d.paired_at,
            })
            .collect();
        let paired = devices.first().map(|d| json::PairedJson {
            name: device_label(&d.label),
            sas_words: d.sas_words.clone(),
            relay_url: d.relay_url.clone(),
            paired_ms: d.paired_at,
        });
        println!(
            "{}",
            json::to_pretty(&json::PairListJson {
                paired,
                devices: devices_json,
            })
        );
        return 0;
    }

    if devices.is_empty() {
        println!(
            "  {}",
            s.dim("no paired phone; run: sigil pair --relay <url>")
        );
        return 0;
    }

    let count = devices.len();
    let heading = if count == 1 {
        "paired devices".to_string()
    } else {
        format!("paired devices ({count})")
    };
    println!("{}", s.cobalt(&heading));
    for d in &devices {
        println!();
        let words = if d.sas_words.is_empty() {
            s.dim("(no SAS on record)")
        } else {
            s.cobalt(&d.sas_words.join(&s.faint(" \u{00b7} ")))
        };
        println!("  {}  {}", s.dim("device"), s.dim(&device_label(&d.label)));
        println!("  {}  {}", s.dim("id    "), s.faint(&d.device_id));
        println!("  {}  {}", s.dim("sas   "), words);
        println!("  {}  {}", s.dim("relay "), s.dim(&d.relay_url));
        println!(
            "  {}  {}",
            s.dim("since "),
            s.dim(&format_unix_ms(d.paired_at))
        );
    }
    0
}

/// A device's display label, falling back to a constant when the ceremony
/// captured no name (the pairing wire does not carry a device name yet).
fn device_label(label: &str) -> String {
    if label.is_empty() {
        "iPhone".to_string()
    } else {
        label.to_string()
    }
}

/// `sigil pair remove <deviceId>`: forget ONE paired device without dropping the
/// others (#36). Bare `sigil unpair` still removes all.
fn pair_remove(args: &[String], json: bool) -> i32 {
    let s = Style::stdout();
    let Some(device_id) = args.iter().find(|a| !a.starts_with('-')).cloned() else {
        if json {
            return emit_local_control(&ControlResult::line(
                false,
                "usage: sigil pair remove <deviceId>",
            ));
        }
        eprintln!("usage: sigil pair remove <deviceId>");
        return 2;
    };
    let ks = keystore::for_host();
    match crate::pairing_store::remove_device(ks.as_ref(), &device_id) {
        Ok(true) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    true,
                    format!("removed device {device_id}"),
                ));
            }
            println!("{} removed device {device_id}", s.ok("\u{2713}"));
            println!("  {}", s.faint("restart to apply: sigil restart"));
            0
        }
        Ok(false) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    true,
                    format!("no device with id {device_id}"),
                ));
            }
            println!("  {}", s.dim(&format!("no device with id {device_id}")));
            0
        }
        Err(e) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    false,
                    format!("remove failed: {e}"),
                ));
            }
            eprintln!("sigil: pair remove failed: {e}");
            1
        }
    }
}

/// The real pairing ceremony: mint a QR, wait on the relay for the phone, verify,
/// confirm SAS, deliver the DEK, and persist. `--relay <url>` or `$SIGIL_RELAY_URL`
/// override; absent both, defaults to [`crate::pair::DEFAULT_RELAY_URL`] (the
/// shared Sigil relay), announced out loud so the human always knows which
/// relay a pairing crossed.
fn run_pairing(args: &[String]) -> i32 {
    let s = Style::stdout();
    let relay = match flag_value(args, "--relay")
        .map(str::to_string)
        .or_else(|| std::env::var("SIGIL_RELAY_URL").ok())
    {
        Some(r) => r,
        None => {
            println!(
                "  {}",
                s.dim(&format!(
                    "Using the Sigil relay ({})",
                    crate::pair::DEFAULT_RELAY_URL
                ))
            );
            crate::pair::DEFAULT_RELAY_URL.to_string()
        }
    };
    let auto_yes = has_flag(args, "--yes") || has_flag(args, "-y");
    // --qr-png also writes the pairing payload as a scannable PNG, so a remote
    // operator can be handed an image of the pairing code (not just terminal art).
    let qr_png = flag_value(args, "--qr-png").map(str::to_string);
    // --name <label> names the added device for `sigil pair list` / removal.
    let device_name = flag_value(args, "--name")
        .map(str::to_string)
        .unwrap_or_else(|| "iPhone".to_string());

    // Pairing is ADDITIVE (#36 multi-device): a new device is added alongside any
    // already paired, not replacing them. Bare `sigil unpair` still removes all.
    let existing = crate::pairing_store::list_devices()
        .map(|d| d.len())
        .unwrap_or(0);
    if existing > 0 {
        println!(
            "  {}",
            s.dim(&format!(
                "{existing} device(s) already paired; this adds another (sigil pair remove <id> to drop one)"
            ))
        );
    }

    let ks = keystore::for_host();
    // Arm the pairing after the human confirms the SAS (never before): prove a
    // live hardware presence (on a Secure Enclave keystore this is the Touch ID
    // prompt, so the biometric gates authorizing this specific confirmed device)
    // and provision the Mac threshold share `m`. Nothing is delivered to the
    // phone: everything at rest is threshold-sealed and opened per-approval.
    let mut arm_after_sas = || -> anyhow::Result<()> {
        if ks.is_biometric() {
            ks.verify_presence("Authorize pairing this phone with Sigil")
                .map_err(|e| anyhow::anyhow!("proving hardware presence: {e}"))?;
        }
        crate::threshold::load_or_create_mac_share(ks.as_ref())
            .map_err(|e| anyhow::anyhow!("provisioning the Mac threshold share: {e}"))?;
        Ok(())
    };
    let daemon_identity = DeviceIdentity::generate();

    let mut present_qr = |unicode: &str, b64: &str| {
        println!("{}", s.cobalt("sigil pair"));
        println!();
        println!(
            "  {}",
            s.dim("Scan this with the Sigil approver on your phone:")
        );
        println!();
        println!("{unicode}");
        println!("  {}", s.faint("or paste this pairing code into the app:"));
        println!("  {b64}");
        if let Some(path) = qr_png.as_deref() {
            match crate::qr::write_png(b64, std::path::Path::new(path), 8) {
                Ok(()) => println!("  {}", s.faint(&format!("scannable PNG written to {path}"))),
                Err(e) => eprintln!("{} writing the pairing QR PNG: {e:#}", s.deny("\u{2717}")),
            }
        }
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
        // Kept in lockstep with proto::PAIRING_SECRET_TTL_MS (see pairing.rs);
        // the QR must not outlive the secret backing it.
        response_timeout: std::time::Duration::from_secs(600),
        flush_grace: std::time::Duration::from_millis(750),
        now: &sigil_proto::now_ms,
        make_channel: &mut make_channel,
        present_qr: &mut present_qr,
        confirm_sas: &mut confirm,
        arm_after_sas: &mut arm_after_sas,
    };

    let new_pairing = match crate::pair::run_ceremony(daemon_identity, opts) {
        Ok(np) => np,
        Err(e) => {
            eprintln!("{} pairing failed: {e:#}", s.deny("\u{2717}"));
            return 1;
        }
    };

    let device_id = match crate::pairing_store::add_device(ks.as_ref(), &new_pairing, &device_name)
    {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "{} pairing succeeded but could not be saved: {e}",
                s.deny("\u{2717}")
            );
            return 1;
        }
    };

    println!();
    println!("{} phone paired and saved", s.ok("\u{2713}"));
    println!("  {}", s.faint(&format!("device id {device_id}")));
    println!(
        "  {}",
        s.dim("the daemon now gates every request on your phone")
    );
    println!(
        "  {}",
        s.faint("restart the daemon to arm it: sigil restart")
    );
    0
}

/// `sigil pair --relay <url> --json`: run the ceremony, streaming NDJSON events
/// (`qr`, `sas`, `paired`, `failed`) one object per line so the GUI renders it
/// live. After the `sas` event this BLOCKS on one line of stdin: the DEK is
/// only sealed and sent once that line reads `confirm` (case-insensitive),
/// which the GUI writes to our stdin after the human taps "match" having
/// compared the six words on both screens. Anything else, or stdin closing
/// (EOF, e.g. the app quit), aborts the ceremony without ever sending the DEK.
/// This is the real MITM backstop; auto-confirming here would seal and hand the
/// DEK to whoever answered the QR before a human ever looked at the words.
fn run_pairing_json(args: &[String]) -> i32 {
    let relay = match flag_value(args, "--relay")
        .map(str::to_string)
        .or_else(|| std::env::var("SIGIL_RELAY_URL").ok())
    {
        Some(r) => r,
        None => {
            // Not an NDJSON event: stdout here is a pure event stream the Mac
            // app parses, so an ad hoc "using the default relay" line would
            // either corrupt that stream or (if it added a new event kind)
            // need app-side decoder changes outside this pathspec. stderr
            // still makes the default honest and discoverable in logs.
            eprintln!(
                "sigil: using the default relay ({})",
                crate::pair::DEFAULT_RELAY_URL
            );
            crate::pair::DEFAULT_RELAY_URL.to_string()
        }
    };

    let ks = keystore::for_host();
    // After the human confirms the SAS, arm the pairing: prove a live hardware
    // presence (Touch ID on a Secure Enclave keystore) and provision the Mac
    // threshold share `m`. Nothing is delivered to the phone; everything at rest
    // is threshold-sealed and opened per-approval with the phone's partial.
    let mut arm_after_sas = || -> anyhow::Result<()> {
        if ks.is_biometric() {
            ks.verify_presence("Authorize pairing this phone with Sigil")
                .map_err(|e| anyhow::anyhow!("proving hardware presence: {e}"))?;
        }
        crate::threshold::load_or_create_mac_share(ks.as_ref())
            .map_err(|e| anyhow::anyhow!("provisioning the Mac threshold share: {e}"))?;
        Ok(())
    };
    let daemon_identity = DeviceIdentity::generate();

    let mut present_qr = |_unicode: &str, b64: &str| {
        emit_ndjson(&serde_json::json!({ "event": "qr", "payload_b64": b64 }));
    };
    let mut confirm = |words: &[&'static str; 6]| -> bool {
        emit_ndjson(&serde_json::json!({ "event": "sas", "words": words.to_vec() }));
        // Block here: the pairing must not be armed until a real human has
        // compared the six words on both screens and confirmed. The GUI writes
        // "confirm\n" to our stdin after the tap; anything else (or the pipe
        // closing) fails the ceremony closed.
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => false,
            Ok(_) => line.trim().eq_ignore_ascii_case("confirm"),
            Err(_) => false,
        }
    };
    let mut make_channel = |mailbox: [u8; 32]| crate::pair::relay_channel(&relay, mailbox);

    let opts = crate::pair::CeremonyOpts {
        relay_url: relay.clone(),
        // Kept in lockstep with proto::PAIRING_SECRET_TTL_MS (see pairing.rs);
        // the QR must not outlive the secret backing it.
        response_timeout: std::time::Duration::from_secs(600),
        flush_grace: std::time::Duration::from_millis(750),
        now: &sigil_proto::now_ms,
        make_channel: &mut make_channel,
        present_qr: &mut present_qr,
        confirm_sas: &mut confirm,
        arm_after_sas: &mut arm_after_sas,
    };

    match crate::pair::run_ceremony(daemon_identity, opts) {
        Ok(np) => {
            let sas: Vec<String> = np.sas_words.to_vec();
            let relay_url = np.relay_url.clone();
            let paired_ms = np.paired_at;
            // Additive (#36): add alongside any already-paired device. The label
            // comes from --name, defaulting to "iPhone".
            let device_name = flag_value(args, "--name")
                .map(str::to_string)
                .unwrap_or_else(|| "iPhone".to_string());
            let device_id = match crate::pairing_store::add_device(ks.as_ref(), &np, &device_name) {
                Ok(id) => id,
                Err(e) => {
                    emit_ndjson(&serde_json::json!({
                        "event": "failed",
                        "reason": format!("paired but could not save: {e}")
                    }));
                    return 1;
                }
            };
            emit_ndjson(&serde_json::json!({
                "event": "paired",
                "name": device_name,
                "device_id": device_id,
                "sas_words": sas,
                "relay_url": relay_url,
                "paired_ms": paired_ms
            }));
            0
        }
        Err(e) => {
            emit_ndjson(&serde_json::json!({ "event": "failed", "reason": format!("{e:#}") }));
            1
        }
    }
}

/// Print one NDJSON event line and flush, so the GUI reading the stream sees
/// each ceremony event as it happens rather than at teardown.
fn emit_ndjson(value: &serde_json::Value) {
    println!("{value}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

fn cmd_unpair(json: bool) -> i32 {
    let s = Style::stdout();
    let ks = keystore::for_host();
    if json {
        let result = match crate::pairing_store::remove(ks.as_ref()) {
            Ok(true) => ControlResult::line(true, "phone unpaired"),
            Ok(false) => ControlResult::line(true, "no phone was paired"),
            Err(e) => ControlResult::line(false, format!("unpair failed: {e}")),
        };
        return emit_local_control(&result);
    }
    match crate::pairing_store::remove(ks.as_ref()) {
        Ok(true) => {
            println!("{} phone unpaired", s.ok("\u{2713}"));
            println!(
                "  {}",
                s.brass(
                    "the daemon will fail closed until you pair again or provision a biometric"
                )
            );
            println!("  {}", s.faint("restart to apply: sigil restart"));
            0
        }
        Ok(false) => {
            println!("  {}", s.dim("no phone was paired"));
            0
        }
        Err(e) => {
            eprintln!("sigil: unpair failed: {e}");
            1
        }
    }
}

fn cmd_setup(args: &[String]) -> i32 {
    let s = Style::stdout();
    println!("{}", s.cobalt("sigil setup"));
    println!();

    // 1. Keystore DEK. On macOS this needs the Secure Enclave (NEEDS
    //    VERIFICATION); a dev keystore provisions immediately. A failure here is
    //    not fatal to the rest of setup, so we report and continue.
    let ks = keystore::for_host();
    match crate::threshold::load_or_create_mac_share(ks.as_ref()) {
        Ok(_) => println!("  {} keystore ready", s.ok("\u{2713}")),
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
            "  {} added ~/.sigil/bin to your shell profile (open a new shell)",
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
            s.faint("(you can load it later with: sigil start)")
        ),
    }

    // 5. Pairing. A relay is now always available (an explicit --relay/
    //    $SIGIL_RELAY_URL override, or the baked-in default), so guided setup
    //    always continues straight into the ceremony.
    println!();
    run_pairing(args)
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
        Some("add-file") => ssh_add_file(&args[1..]),
        Some("add-stored") => ssh_add_stored(&args[1..]),
        Some("list") | None => ssh_list(),
        Some("remove") | Some("rm") => ssh_remove(args.get(1).map(String::as_str)),
        Some("config") => ssh_config(&args[1..]),
        _ => {
            eprintln!("usage: sigil ssh <add-file|add-stored|list|remove|config>");
            2
        }
    }
}

/// `sigil ssh add-file --path <private-key> [--comment <c>]`: serve a local
/// OpenSSH key file (the file-based signer). The sibling `<path>.pub` supplies
/// the public key; the private key is read only at sign time. For users who do
/// not keep their SSH keys in 1Password. v1 serves ed25519 only.
fn ssh_add_file(args: &[String]) -> i32 {
    let s = Style::stdout();
    let Some(path) = flag_value(args, "--path").map(str::to_string) else {
        eprintln!(
            "usage: sigil ssh add-file --path <private-key-path> [--comment <c>] [--host <h> ...]"
        );
        return 2;
    };
    let comment = flag_value(args, "--comment").unwrap_or("").to_string();
    let hosts = flag_values(args, "--host");
    if let Some(code) = reject_bad_hosts(&s, &hosts) {
        return code;
    }
    let entry = crate::sshagent::SshFileEntry {
        path: path.clone(),
        comment,
        hosts,
    };
    // Validate before persisting: the sibling .pub must parse as ed25519.
    let Some(id) = crate::sshagent::resolve_file_identity(&entry) else {
        eprintln!(
            "{} could not read an ed25519 public key at {path}.pub (v1 serves ed25519 only)",
            s.deny("\u{2717}")
        );
        return 1;
    };

    let mut cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: loading ssh-keys config: {e}");
            return 1;
        }
    };
    if cfg.files.iter().any(|f| f.path == path) {
        eprintln!("sigil: {path} is already served (remove it first to replace)");
        return 1;
    }
    let hosts = entry.hosts.clone();
    cfg.files.push(entry);
    if let Err(e) = cfg.save() {
        eprintln!("sigil: saving ssh-keys config: {e}");
        return 1;
    }

    println!("{} serving {}", s.ok("\u{2713}"), s.cobalt(&id.label));
    println!("  {}  {}", s.dim("key"), s.dim(&id.fingerprint));
    println!("  {}  {}", s.dim("file"), s.dim(&path));
    ssh_add_epilogue(&s, &hosts);
    0
}

/// `sigil ssh add-stored [--comment <c>] [--host <h> ...]`: seal an OpenSSH
/// private key (read from stdin) under the v2 threshold, so Sigil holds the key at
/// rest as ciphertext and opens it per-signature only with the phone's partial.
/// This is the "store SSH creds for people without 1Password" source. A Mac-side,
/// human-present ceremony (needs the paired phone's share F and the Mac share m);
/// v1 seals ed25519 only.
fn ssh_add_stored(args: &[String]) -> i32 {
    let s = Style::stdout();
    let comment = flag_value(args, "--comment").unwrap_or("").to_string();
    let hosts = flag_values(args, "--host");
    if let Some(code) = reject_bad_hosts(&s, &hosts) {
        return code;
    }

    // Read the private key from stdin into a wiped buffer (never a file, never a
    // flag). It leaves this function only as threshold ciphertext.
    let mut raw = Zeroizing::new(Vec::new());
    if let Err(e) = std::io::stdin().read_to_end(&mut raw) {
        eprintln!("sigil: reading the private key from stdin: {e}");
        return 1;
    }
    if raw.is_empty() {
        eprintln!(
            "usage: sigil ssh add-stored [--comment <c>] [--host <h> ...]   (OpenSSH private key on stdin)"
        );
        return 2;
    }

    // Decode + validate ed25519, then re-encode to a canonical OpenSSH PEM so what
    // we seal is exactly what the daemon will decode and sign.
    let key = match ssh_key::PrivateKey::from_openssh(&raw[..]) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("{} not a valid OpenSSH private key", s.deny("\u{2717}"));
            return 1;
        }
    };
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        eprintln!(
            "{} only ed25519 keys are served (v1); this key is {}",
            s.deny("\u{2717}"),
            key.algorithm().as_str()
        );
        return 1;
    }
    let pem = match key.to_openssh(ssh_key::LineEnding::LF) {
        Ok(p) => p, // Zeroizing<String>
        Err(e) => {
            eprintln!("sigil: re-encoding the private key: {e}");
            return 1;
        }
    };
    let public_key = match key.public_key().to_openssh() {
        Ok(l) => l.trim().to_string(),
        Err(e) => {
            eprintln!("sigil: encoding the public key: {e}");
            return 1;
        }
    };
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    // The threshold-store id: stable across re-seals of the same key, unique per
    // key, and namespaced so it never collides with an env-source id.
    let account_id = format!("ssh:{fingerprint}");

    // Seal the PEM to the phone's pinned Secure-Enclave share F plus the Mac share
    // m (the same ceremony as sealing an env source's values).
    let ks = keystore::for_host();
    let phone = match crate::pairing_store::load(ks.as_ref()) {
        Ok(Some(pc)) => match pc.phone_share {
            Some(share) => share,
            None => {
                eprintln!(
                    "sigil: this pairing has no phone Secure-Enclave share; re-pair before storing a key"
                );
                return 1;
            }
        },
        Ok(None) => {
            eprintln!("sigil: no phone is paired; run `sigil pair` first");
            return 1;
        }
        Err(e) => {
            eprintln!("sigil: loading the pairing: {e}");
            return 1;
        }
    };
    let m = match crate::threshold::load_or_create_mac_share(ks.as_ref()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sigil: provisioning the Mac threshold share: {e}");
            return 1;
        }
    };
    let mut store = match crate::threshold::ThresholdStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading the threshold store: {e}");
            return 1;
        }
    };
    if let Err(e) =
        crate::threshold::seal_secret(&mut store, &account_id, &m, &phone, pem.as_bytes())
    {
        eprintln!("sigil: sealing the private key: {e}");
        return 1;
    }
    if let Err(e) = store.save() {
        eprintln!("sigil: saving the threshold store: {e}");
        return 1;
    }

    // Register the served entry (public material + the sealed-key id only).
    let entry = crate::sshagent::SshStoredEntry {
        public_key,
        account_id: account_id.clone(),
        comment,
        hosts: hosts.clone(),
    };
    let Some(id) = crate::sshagent::resolve_stored_identity(&entry) else {
        eprintln!(
            "{} could not derive an ed25519 identity from the key",
            s.deny("\u{2717}")
        );
        return 1;
    };
    let mut cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: loading ssh-keys config: {e}");
            return 1;
        }
    };
    // A re-seal of the same key replaces the entry (the store record was upserted).
    cfg.stored.retain(|k| k.account_id != account_id);
    cfg.stored.push(entry);
    if let Err(e) = cfg.save() {
        eprintln!("sigil: saving ssh-keys config: {e}");
        return 1;
    }

    println!("{} storing {}", s.ok("\u{2713}"), s.cobalt(&id.label));
    println!("  {}  {}", s.dim("key"), s.dim(&id.fingerprint));
    println!(
        "  {}  {}",
        s.dim("sealed"),
        s.dim("threshold; opens only with your phone")
    );
    ssh_add_epilogue(&s, &hosts);
    0
}

/// Reject any `--host` token that is not a safe ssh_config `Host` value (a token
/// carrying whitespace or a control character could splice extra directives into
/// the generated config). Returns `Some(exit_code)` to stop the command, or
/// `None` when every token is clean.
fn reject_bad_hosts(s: &Style, hosts: &[String]) -> Option<i32> {
    for h in hosts {
        if !crate::sshconfig::valid_host(h) {
            eprintln!(
                "{} invalid --host {h:?}: no spaces or control characters",
                s.deny("\u{2717}")
            );
            return Some(2);
        }
    }
    None
}

/// Shared closing lines for `ssh add-file`: the restart hint, and, when the key
/// names hosts, the routing hint to (re)generate the ssh config.
fn ssh_add_epilogue(s: &Style, hosts: &[String]) {
    if hosts.is_empty() {
        println!(
            "  {}",
            s.faint("the running daemon serves it within a couple of seconds")
        );
    } else {
        println!("  {}  {}", s.dim("hosts"), s.dim(&hosts.join(" ")));
        println!(
            "  {}",
            s.faint("served automatically; route these hosts with: sigil ssh config --install")
        );
    }
}

fn ssh_list() -> i32 {
    let s = Style::stdout();
    let cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: loading ssh-keys config: {e}");
            return 1;
        }
    };
    if cfg.files.is_empty() && cfg.stored.is_empty() {
        println!(
            "  {}",
            s.dim("no SSH keys served; add one: sigil ssh add-file --path <key>  (or: sigil ssh add-stored)")
        );
        return 0;
    }
    println!("{}", s.cobalt("ssh keys served"));
    println!();
    for e in &cfg.files {
        match crate::sshagent::resolve_file_identity(e) {
            Some(id) => {
                println!("  {}  {}", pad(&id.label, 18), s.dim(&id.fingerprint));
                println!(
                    "  {}  {}",
                    pad("", 18),
                    s.faint(&format!("file · {} · {}", e.path, id.comment))
                );
                if !e.hosts.is_empty() {
                    println!(
                        "  {}  {}",
                        pad("", 18),
                        s.faint(&format!("routed: {}", e.hosts.join(" ")))
                    );
                }
            }
            None => println!(
                "  {}  {}",
                pad(&e.path, 18),
                s.brass("unusable (need an ed25519 key with a sibling .pub)")
            ),
        }
    }
    for e in &cfg.stored {
        match crate::sshagent::resolve_stored_identity(e) {
            Some(id) => {
                println!("  {}  {}", pad(&id.label, 18), s.dim(&id.fingerprint));
                println!(
                    "  {}  {}",
                    pad("", 18),
                    s.faint("stored · threshold-sealed; opens only with your phone")
                );
                if !e.hosts.is_empty() {
                    println!(
                        "  {}  {}",
                        pad("", 18),
                        s.faint(&format!("routed: {}", e.hosts.join(" ")))
                    );
                }
            }
            None => println!(
                "  {}  {}",
                pad(&e.account_id, 18),
                s.brass("unusable (not an ed25519 public key)")
            ),
        }
    }
    0
}

fn ssh_remove(item: Option<&str>) -> i32 {
    let s = Style::stdout();
    let Some(item) = item else {
        eprintln!("usage: sigil ssh remove <item>");
        return 2;
    };
    let mut cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: loading ssh-keys config: {e}");
            return 1;
        }
    };
    // Match a local key-file path (the file source, added by `ssh add-file`) or a
    // stored key by its id (`ssh:<fp>`) or bare fingerprint (`add-stored`).
    let before = cfg.files.len() + cfg.stored.len();
    cfg.files.retain(|f| f.path != item);
    let stored_id = format!("ssh:{item}");
    let mut removed_stored: Vec<String> = Vec::new();
    cfg.stored.retain(|k| {
        let hit = k.account_id == item || k.account_id == stored_id;
        if hit {
            removed_stored.push(k.account_id.clone());
        }
        !hit
    });
    if cfg.files.len() + cfg.stored.len() == before {
        println!("  {}", s.dim(&format!("no served key named {item}")));
        return 0;
    }
    if let Err(e) = cfg.save() {
        eprintln!("sigil: saving ssh-keys config: {e}");
        return 1;
    }
    // Drop the sealed private key(s) from the threshold store too, so removal
    // leaves no ciphertext behind. Best-effort: the config change already stopped
    // it being served; a store error is reported but not fatal.
    if !removed_stored.is_empty() {
        match crate::threshold::ThresholdStore::load() {
            Ok(mut store) => {
                for id in &removed_stored {
                    store.remove(id);
                }
                if let Err(e) = store.save() {
                    eprintln!("sigil: removing the sealed key from the threshold store: {e}");
                }
            }
            Err(e) => eprintln!("sigil: loading the threshold store to drop the sealed key: {e}"),
        }
    }
    println!("{} stopped serving {}", s.ok("\u{2713}"), s.cobalt(item));
    println!(
        "  {}",
        s.faint("the running daemon drops it within a couple of seconds")
    );
    0
}

/// `sigil ssh config [--install | --uninstall]`: manage the `~/.ssh/config`
/// routing that sends chosen hosts through Sigil's agent (1Password-style), while
/// every other host stays on the user's normal agent. With no flag it prints the
/// block to paste by hand; `--install` writes it (with a backup); `--uninstall`
/// removes it and the generated files.
fn ssh_config(args: &[String]) -> i32 {
    let s = Style::stdout();

    if has_flag(args, "--uninstall") {
        match crate::sshconfig::uninstall() {
            Ok(changed) => {
                if changed {
                    println!(
                        "{} removed the Sigil block from ~/.ssh/config",
                        s.ok("\u{2713}")
                    );
                } else {
                    println!("  {}", s.dim("no Sigil block was present in ~/.ssh/config"));
                }
                println!("  {}", s.faint("your normal agent now answers every host"));
                return 0;
            }
            Err(e) => {
                eprintln!("sigil: removing the ssh config block: {e}");
                return 1;
            }
        }
    }

    let cfg = match crate::sshagent::SshKeyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: loading ssh-keys config: {e}");
            return 1;
        }
    };
    let routed = crate::sshconfig::routed_keys(&cfg);
    if routed.is_empty() {
        println!(
            "  {}",
            s.dim("no keys name any hosts to route; add hosts with: sigil ssh add-file --path <key> --host <h>")
        );
        return 0;
    }
    let sock = crate::sshagent::socket_path();

    if has_flag(args, "--install") {
        match crate::sshconfig::install(&cfg, &sock) {
            Ok(report) => {
                println!("{} routing through Sigil", s.ok("\u{2713}"));
                for r in &report.routed {
                    println!("  {}  {}", pad(&r.label, 18), s.dim(&r.hosts.join(" ")));
                }
                if let Some(backup) = &report.backup {
                    println!(
                        "  {}  {}",
                        s.dim("backup"),
                        s.faint(&backup.display().to_string())
                    );
                }
                if !report.ssh_config_changed {
                    println!("  {}", s.faint("~/.ssh/config already current"));
                }
                println!(
                    "  {}",
                    s.faint("every other host stays on your normal agent")
                );
                0
            }
            Err(e) => {
                eprintln!("sigil: installing the ssh config: {e}");
                1
            }
        }
    } else {
        // Default: print the block for manual placement, write nothing.
        println!("{}", s.cobalt("sigil ssh routing (preview)"));
        println!(
            "  {}",
            s.faint("apply with: sigil ssh config --install  (or paste the below by hand)")
        );
        println!();
        print!("{}", crate::sshconfig::preview(&cfg, &sock));
        0
    }
}

/// `sigil sshagent`: print the SSH_AUTH_SOCK a user points `ssh`/`git` at, plus
/// the served-key count and a guidance line.
fn cmd_sshagent() -> i32 {
    let s = Style::stdout();
    let sock = crate::sshagent::socket_path();
    let count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.files.len() + c.stored.len())
        .unwrap_or(0);
    println!("{}", s.cobalt("sigil ssh-agent"));
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
        s.dim("Point ssh and git at Sigil by exporting this in your shell profile:")
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

fn cmd_shim(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("install") => shim_install(json),
        Some("add") => shim_add(args.get(1).map(String::as_str), json),
        _ => {
            eprintln!("usage: sigil shim <install | add <cmd>>");
            2
        }
    }
}

/// `sigil shim add <cmd>`: drop a transparent alias binary (`~/.sigil/bin/<cmd>`)
/// so a bare `<cmd>` on PATH re-enters as `sigil <cmd>`. For callers that cannot
/// be modified (a launcher shelling out to a bare tool, `git` reaching the SSH
/// agent, an AI agent that only knows the real name). The command should already
/// be configured (`sigil-config add <cmd>`); a warning notes it if not.
fn shim_add(cmd: Option<&str>, json: bool) -> i32 {
    let s = Style::stdout();
    let Some(cmd) = cmd else {
        eprintln!("usage: sigil shim add <cmd>");
        return 2;
    };
    let configured = crate::config::Config::load()
        .map(|cfg| cfg.gates_command(cmd))
        .unwrap_or(false);
    let (link, target) = match crate::setup::install_shim_for(cmd) {
        Ok(pair) => pair,
        Err(e) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    false,
                    format!("shim add failed: {e:#}"),
                ));
            }
            eprintln!("sigil: {e:#}");
            return 1;
        }
    };
    if json {
        let mut lines = vec![
            format!("shim alias for {cmd} installed"),
            format!("link {}", link.display()),
            format!("-> {}", target.display()),
        ];
        if !configured {
            lines.push(format!(
                "warning: {cmd} is not configured; run sigil-config add {cmd}"
            ));
        }
        return emit_local_control(&ControlResult::ok(lines));
    }
    println!(
        "{} shim alias for {} installed",
        s.ok("\u{2713}"),
        s.cobalt(cmd)
    );
    println!(
        "  {} {} -> {}",
        s.dim("link"),
        link.display(),
        target.display()
    );
    if !configured {
        println!(
            "  {} {}",
            s.brass("\u{2717}"),
            s.dim(&format!(
                "{cmd} is not configured yet; run: sigil-config add {cmd} --provider <id>"
            ))
        );
    }
    println!(
        "  {}",
        s.faint("ensure ~/.sigil/bin is first on PATH so the alias wins")
    );
    0
}

fn shim_install(json: bool) -> i32 {
    let s = Style::stdout();
    let (link, target) = match crate::setup::install_shim() {
        Ok(pair) => pair,
        Err(e) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    false,
                    format!("shim install failed: {e:#}"),
                ));
            }
            eprintln!("sigil: {e:#}");
            return 1;
        }
    };

    if json {
        return emit_local_control(&ControlResult::ok(vec![
            "shim installed".to_string(),
            format!("link {}", link.display()),
            format!("-> {}", target.display()),
            "add ~/.sigil/bin to PATH so the shim wins".to_string(),
        ]));
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
    println!("    {}", s.cobalt("export PATH=\"$HOME/.sigil/bin:$PATH\""));
    println!();
    println!(
        "  {}",
        s.faint("or run `sigil setup`, which edits your profile and loads the daemon.")
    );
    0
}

/// `sigil-config proxy <add|remove|list|status|doctor|env>`: manage the
/// transparent PATH aliases that let an unmodifiable caller (an agent, a
/// launcher's bare `op`, `git` reaching the SSH agent) hit Sigil without knowing
/// it exists. An alias is a symlink in `~/.sigil/bin` at the `sigil` runtime
/// binary; running the command resolves the alias, which gates on the phone and
/// execs the real tool. See `docs/design/proxy-aliasing.md`.
fn cmd_proxy(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("add") => proxy_add(&args[1..], json),
        Some("remove") | Some("rm") => proxy_remove(&args[1..], json),
        Some("list") | None => proxy_list(json),
        Some("status") => proxy_status(json),
        Some("doctor") => proxy_doctor(args.get(1).map(String::as_str), json),
        Some("env") => proxy_env(&args[1..]),
        _ => {
            eprintln!(
                "usage: sigil-config proxy <add <cmd> | remove <cmd> [--purge] | list | status | doctor [<cmd>] | env [--shell zsh|bash|fish|nu]>"
            );
            2
        }
    }
}

/// `proxy add <cmd> [--force]`: install the alias, ensure the proxy dir is on
/// PATH for this shell, and report the resolved real binary + gating coverage.
/// Warnings (a real binary already ahead on PATH, or no rule gating `<cmd>`) are
/// surfaced but do not block; the alias is still installed.
fn proxy_add(args: &[String], json: bool) -> i32 {
    let s = Style::stdout();
    let Some(cmd) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!("usage: sigil-config proxy add <cmd> [--force]");
        return 2;
    };

    // Gating coverage and the real binary a shell would otherwise resolve.
    let gated = crate::config::Config::load()
        .map(|cfg| cfg.gates_command(&cmd))
        .unwrap_or(false);
    let real = crate::paths::find_real(&cmd);

    let (link, target) = match crate::proxy::install_alias(&cmd) {
        Ok(pair) => pair,
        Err(e) => {
            if json {
                return emit_local_control(&ControlResult::line(
                    false,
                    format!("proxy add failed: {e}"),
                ));
            }
            eprintln!("sigil-config: {e}");
            return 1;
        }
    };

    // Put the proxy dir on PATH for the current shell (one file, like setup).
    let path_added = match crate::proxy::primary_rc_file() {
        Some((file, shell)) => crate::proxy::ensure_path_in(&file, shell)
            .map(|added| (file, added))
            .ok(),
        None => None,
    };
    let session_line = crate::proxy::env_line(crate::proxy::Shell::detect());

    if json {
        let mut lines = vec![
            format!("proxy alias for {cmd} installed"),
            format!("link {}", link.display()),
            format!("-> {}", target.display()),
            match &real {
                Some(p) => format!("real {}", p.display()),
                None => format!("real: no {cmd} found on PATH"),
            },
        ];
        if !gated {
            lines.push(format!(
                "warning: no rule gates {cmd}; every call is refused until you run sigil-config add {cmd}"
            ));
        }
        if let Some((file, true)) = &path_added {
            lines.push(format!("added ~/.sigil/bin to {}", file.display()));
        }
        return emit_local_control(&ControlResult::ok(lines));
    }

    println!(
        "{} proxy alias for {} installed",
        s.ok("\u{2713}"),
        s.cobalt(&cmd)
    );
    println!(
        "  {} {} -> {}",
        s.dim("link"),
        link.display(),
        target.display()
    );
    match &real {
        Some(p) => println!("  {} {}", s.dim("real"), s.dim(&p.display().to_string())),
        None => println!(
            "  {} {}",
            s.brass("\u{2717}"),
            s.brass(&format!(
                "no {cmd} found on PATH; the alias will exit 127 when the daemon is down"
            ))
        ),
    }
    if !gated {
        println!(
            "  {} {}",
            s.brass("\u{2717}"),
            s.brass(&format!(
                "no rule gates {cmd}: every call is refused until you configure it (sigil-config add {cmd} --provider <id>)"
            ))
        );
    }
    match &path_added {
        Some((file, true)) => println!(
            "  {} added ~/.sigil/bin to {}",
            s.ok("\u{2713}"),
            s.dim(&file.display().to_string())
        ),
        Some((_, false)) => println!("  {} ~/.sigil/bin already on PATH", s.ok("\u{2713}")),
        None => {}
    }
    println!();
    println!("  {}", s.dim("open a new shell, or load it now:"));
    println!("    {}", s.cobalt(&format!("eval \"$({session_line})\"")));
    println!(
        "  {}",
        s.faint("for an agent that inherits env without an rc file, put ~/.sigil/bin first in its launcher's PATH (sigil-config proxy env)")
    );
    0
}

/// `proxy remove <cmd> [--purge]`: remove the alias (never the real binary). With
/// `--purge`, once no aliases remain, also strip the managed PATH block.
fn proxy_remove(args: &[String], json: bool) -> i32 {
    let Some(cmd) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!("usage: sigil-config proxy remove <cmd> [--purge]");
        return 2;
    };
    let removed = match crate::proxy::remove_alias(&cmd) {
        Ok(r) => r,
        Err(e) => {
            let r = ControlResult::line(false, format!("proxy remove failed: {e}"));
            return print_config_result(&r, json);
        }
    };
    let mut lines = vec![if removed {
        format!("proxy alias for {cmd} removed")
    } else {
        format!("no proxy alias for {cmd}")
    }];

    // --purge strips the PATH block only when the proxy dir is now empty of
    // aliases, so a shared dir with other aliases keeps its PATH entry.
    if has_flag(args, "--purge") {
        let empty = crate::proxy::list_aliases()
            .map(|a| a.is_empty())
            .unwrap_or(false);
        if empty {
            if let Some((file, _)) = crate::proxy::primary_rc_file() {
                match crate::proxy::strip_path_in(&file) {
                    Ok(true) => {
                        lines.push(format!("stripped ~/.sigil/bin from {}", file.display()))
                    }
                    Ok(false) => {}
                    Err(e) => lines.push(format!("could not strip PATH block: {e}")),
                }
            }
        } else {
            lines.push("kept ~/.sigil/bin on PATH (other aliases remain)".to_string());
        }
    }
    print_config_result(&ControlResult::ok(lines), json)
}

/// `proxy list`: every installed alias with its resolved real target and whether
/// a rule actually gates it (a NO RULE alias refuses every call).
fn proxy_list(json: bool) -> i32 {
    let s = Style::stdout();
    let aliases = match crate::proxy::list_aliases() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sigil-config: listing proxy aliases: {e}");
            return 1;
        }
    };
    if json {
        let lines: Vec<String> = aliases
            .iter()
            .map(|a| {
                format!(
                    "{} -> {} [{}]",
                    a.cmd,
                    a.real
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "no real binary".into()),
                    if a.gated { "gated" } else { "NO RULE" }
                )
            })
            .collect();
        return emit_local_control(&ControlResult::ok(lines));
    }
    if aliases.is_empty() {
        println!(
            "  {}",
            s.dim("no proxy aliases; add one: sigil-config proxy add <cmd>")
        );
        return 0;
    }
    println!("{}", s.cobalt("proxy aliases"));
    println!();
    for a in &aliases {
        let coverage = if a.gated {
            s.ok("gated")
        } else {
            s.brass("NO RULE")
        };
        let real = match &a.real {
            Some(p) => s.dim(&p.display().to_string()),
            None => s.brass("no real binary on PATH"),
        };
        println!("  {}  {}  {}", pad(&a.cmd, 14), coverage, real);
    }
    0
}

/// `proxy status`: is the proxy dir live on PATH for this shell, and how many
/// aliases it serves. The at-a-glance "is interception on" view.
fn proxy_status(json: bool) -> i32 {
    let s = Style::stdout();
    let dir = crate::paths::shim_bin_dir();
    let count = crate::proxy::list_aliases().map(|a| a.len()).unwrap_or(0);

    // Where the proxy dir sits on PATH: present, and first among all entries.
    let (on_path, is_first) = match (&dir, std::env::var_os("PATH")) {
        (Some(d), Some(path)) => {
            let dirs: Vec<_> = std::env::split_paths(&path).collect();
            let idx = dirs.iter().position(|p| p == d);
            (idx.is_some(), idx == Some(0))
        }
        _ => (false, false),
    };

    if json {
        let lines = vec![
            format!("aliases {count}"),
            format!("on_path {on_path}"),
            format!("first {is_first}"),
        ];
        return emit_local_control(&ControlResult::ok(lines));
    }
    println!("{}", s.cobalt("proxy status"));
    println!();
    let (glyph, note) = if is_first {
        (s.ok("\u{25cf}"), s.dim("first on PATH (aliases win)"))
    } else if on_path {
        (
            s.brass("\u{25cf}"),
            s.brass("on PATH but not first; a real binary may win"),
        )
    } else {
        (
            s.deny("\u{25cb}"),
            s.brass("not on PATH in this shell (sigil-config proxy env)"),
        )
    };
    println!("  {}  {glyph} {note}", s.dim("proxy dir"));
    println!(
        "  {}  {}",
        s.dim("aliases  "),
        s.dim(&format!("{count} installed"))
    );
    0
}

/// `proxy doctor [<cmd>]`: deep per-alias diagnosis (PATH order, resolved real
/// binary, drift, and gating coverage). With no argument, every installed alias.
fn proxy_doctor(cmd: Option<&str>, json: bool) -> i32 {
    let cmds: Vec<String> = match cmd {
        Some(c) => vec![c.to_string()],
        None => crate::proxy::list_aliases()
            .map(|a| a.into_iter().map(|x| x.cmd).collect())
            .unwrap_or_default(),
    };
    if cmds.is_empty() {
        let r = ControlResult::ok(vec!["no proxy aliases to diagnose".to_string()]);
        return print_config_result(&r, json);
    }
    let cfg = crate::config::Config::load().unwrap_or_default();
    let s = Style::stdout();
    if !json {
        println!("{}", s.cobalt("proxy doctor"));
        println!();
    }
    let mut all_ok = true;
    let mut lines = Vec::new();
    for c in &cmds {
        let st = crate::proxy::ProxyStatus::detect(c);
        let gated = cfg.gates_command(c);
        let healthy = st.healthy() && gated;
        all_ok &= healthy;
        let real = st.real.as_ref().map(|p| p.display().to_string());
        if json {
            lines.push(format!(
                "{c}: {} · {} · real {}",
                if st.healthy() {
                    "path ok"
                } else {
                    "path drift"
                },
                if gated { "gated" } else { "NO RULE" },
                real.as_deref().unwrap_or("none")
            ));
            continue;
        }
        let glyph = if healthy {
            s.ok("\u{2713}")
        } else {
            s.brass("\u{2717}")
        };
        println!("  {glyph} {}", s.cobalt(c));
        if let Some(issue) = st.issue() {
            println!("      {}", s.brass(&issue));
        }
        if !gated {
            println!(
                "      {}",
                s.brass(&format!(
                    "no rule gates {c}; it refuses every call (sigil-config add {c})"
                ))
            );
        }
        match &real {
            Some(p) => println!("      {} {}", s.dim("real"), s.dim(p)),
            None => println!("      {}", s.brass(&format!("no real {c} on PATH"))),
        }
    }
    if json {
        return emit_local_control(&ControlResult { ok: all_ok, lines });
    }
    println!();
    if all_ok {
        println!("  {}", s.ok("all proxies healthy"));
        0
    } else {
        println!("  {}", s.brass("some proxies need attention"));
        1
    }
}

/// `proxy env [--shell zsh|bash|fish|nu]`: print the PATH-prepend line for the
/// current (or named) shell, for a session or an agent launcher's environment.
fn proxy_env(args: &[String]) -> i32 {
    let shell = match flag_value(args, "--shell") {
        Some(name) => match crate::proxy::Shell::parse(name) {
            Some(sh) => sh,
            None => {
                eprintln!("sigil-config: unknown shell '{name}'; use zsh, bash, fish, or nu");
                return 2;
            }
        },
        None => crate::proxy::Shell::detect(),
    };
    println!("{}", crate::proxy::env_line(shell));
    0
}

/// Load the config store, printing an error and returning `None` on failure.
fn load_config() -> Option<crate::config::Config> {
    match crate::config::Config::load() {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("sigil: loading config: {e}");
            None
        }
    }
}

/// Save the config store, printing an error and returning false on failure.
fn save_config(cfg: &crate::config::Config) -> bool {
    if let Err(e) = cfg.save() {
        eprintln!("sigil: saving config: {e}");
        return false;
    }
    true
}

/// Emit `result` as JSON (control shape) or styled lines, returning its code.
fn print_config_result(result: &ControlResult, json: bool) -> i32 {
    if json {
        return emit_local_control(result);
    }
    let s = Style::stdout();
    for line in &result.lines {
        let glyph = if result.ok {
            s.ok("\u{2713}")
        } else {
            s.brass("\u{2717}")
        };
        println!("  {glyph} {line}");
    }
    i32::from(!result.ok)
}

fn cmd_config_source(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("add") => config_source_add(&args[1..], json),
        Some("list") | None => config_source_list(json),
        Some("remove") | Some("rm") => config_source_remove(args.get(1).map(String::as_str), json),
        Some("env") => cmd_config_source_env(&args[1..], json),
        _ => {
            eprintln!(
                "usage: sigil-config source <add <name> --provider <id> | list | remove <name> | \
                 env <set|unset> <name> ...>"
            );
            2
        }
    }
}

/// Validate a provider id against the shipping registry, so a typo is caught at
/// authoring time rather than as a silent fail-closed at run time.
fn known_provider(provider: &str) -> bool {
    let registry = crate::provider::ProviderRegistry::with_defaults();
    if registry.get(provider).is_none() {
        eprintln!(
            "sigil: unknown provider '{provider}'; known providers: {}",
            registry.ids().join(", ")
        );
        return false;
    }
    true
}

fn config_source_add(args: &[String], json: bool) -> i32 {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!(
            "usage: sigil-config source add <name> --provider <id> [--account <label>] [--path <file>]"
        );
        return 2;
    };
    let Some(provider) = flag_value(args, "--provider").map(str::to_string) else {
        eprintln!("sigil: --provider <id> is required (e.g. 1password, env-file)");
        return 2;
    };
    if !known_provider(&provider) {
        return 2;
    }
    let account = flag_value(args, "--account").map(str::to_string);
    let path = flag_value(args, "--path").map(str::to_string);
    // env-file needs a path; refuse a source that could never inject anything.
    if provider == crate::provider::EnvFileProvider::ID && path.is_none() {
        eprintln!("sigil: the env-file provider needs --path <file> to the KEY=VALUE file");
        return 2;
    }

    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    let src = crate::config::Source {
        name: name.clone(),
        provider: provider.clone(),
        account,
        path,
        // The inline `env` source starts with no keys; values are added securely
        // via `source env set` (which reads them from stdin, never argv).
        keys: Vec::new(),
    };
    if let Err(e) = cfg.add_source(src) {
        eprintln!("sigil: {e}");
        return 1;
    }
    if !save_config(&cfg) {
        return 1;
    }
    let hint = if provider == crate::provider::EnvProvider::ID {
        format!(" (set values: sigil-config source env set {name} --key <KEY>)")
    } else {
        String::new()
    };
    print_config_result(
        &ControlResult::line(true, format!("source {name} added{hint}")),
        json,
    )
}

fn config_source_list(json: bool) -> i32 {
    let cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    if json {
        println!("{}", json::to_pretty(&cfg.sources));
        return 0;
    }
    let s = Style::stdout();
    if cfg.sources.is_empty() {
        println!(
            "  {}",
            s.dim("no sources; add one: sigil-config source add <name> --provider <id>")
        );
        return 0;
    }
    println!("{}", s.cobalt("sources"));
    println!();
    for src in &cfg.sources {
        // For the inline `env` source, show the KEY names (never values, which
        // are not here at all). For others, the account label or env-file path.
        let extra = if src.provider == crate::provider::EnvProvider::ID {
            if src.keys.is_empty() {
                " \u{b7} (no keys set)".to_string()
            } else {
                format!(" \u{b7} {}", src.keys.join(", "))
            }
        } else {
            src.account
                .as_deref()
                .or(src.path.as_deref())
                .map(|x| format!(" \u{b7} {x}"))
                .unwrap_or_default()
        };
        println!(
            "  {}  {}{}",
            pad(&src.name, 16),
            s.dim(&src.provider),
            s.dim(&extra)
        );
    }
    0
}

fn config_source_remove(name: Option<&str>, json: bool) -> i32 {
    let Some(name) = name else {
        eprintln!("usage: sigil-config source remove <name>");
        return 2;
    };
    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    // If this was an inline `env` source, its sealed values must go too, so no
    // orphaned secret ciphertext outlives the source.
    let was_env =
        matches!(cfg.source(name), Some(src) if src.provider == crate::provider::EnvProvider::ID);
    let result = match cfg.remove_source(name) {
        Ok(true) => {
            if !save_config(&cfg) {
                return 1;
            }
            if was_env && !purge_env_blob(name) {
                return 1;
            }
            ControlResult::line(true, format!("source {name} removed"))
        }
        Ok(false) => ControlResult::line(false, format!("no source named {name}")),
        Err(e) => ControlResult::line(false, e),
    };
    print_config_result(&result, json)
}

/// Remove any sealed inline-`env` value blob named `name` from the account store,
/// so removing a source (or clearing its last key) leaves no orphaned ciphertext.
/// A no-op when there is no blob. Returns false (having printed) on a store error.
fn purge_env_blob(name: &str) -> bool {
    let mut store = match crate::threshold::ThresholdStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading the threshold store: {e}");
            return false;
        }
    };
    if store.remove(name) {
        if let Err(e) = store.save() {
            eprintln!("sigil: saving the threshold store: {e}");
            return false;
        }
    }
    true
}

/// Whether `k` is a safe environment variable name to inject: non-empty and free
/// of `=`, NUL, and ASCII whitespace/control, so it can never corrupt the child's
/// env or the sealed wire. Deliberately permissive on the rest (some tools use
/// `.`/`-` in names); the injection is `Command::env`, not a shell.
fn valid_env_key(k: &str) -> bool {
    !k.is_empty()
        && !k
            .bytes()
            .any(|b| b == b'=' || b == 0 || b.is_ascii_whitespace() || b.is_ascii_control())
}

/// Read one secret VALUE from stdin into a wiped buffer (never argv; argv leaks in
/// `ps`). Strips a trailing newline (the shell's, as with token entry), requires
/// UTF-8, and allows empty (a KEY set to ""). `None` (printed) on a read/UTF-8
/// error.
fn read_secret_value_stdin() -> Option<Zeroizing<String>> {
    let mut buf = Zeroizing::new(Vec::new());
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("sigil: reading the value from stdin: {e}");
        return None;
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    match std::str::from_utf8(&buf) {
        Ok(s) => Some(Zeroizing::new(s.to_string())),
        Err(_) => {
            eprintln!("sigil: the value is not valid UTF-8; refusing to store it");
            None
        }
    }
}

fn cmd_config_source_env(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("set") => config_source_env_set(&args[1..], json),
        Some("unset") => config_source_env_unset(&args[1..], json),
        _ => {
            eprintln!(
                "usage: sigil-config source env <set <name> --stdin | set <name> --key <KEY> | \
                 unset <name>>\n  \
                 (set replaces the source's whole sealed set; values are write-only: sealed under \
                 threshold and openable only with the phone, so they are never read back here)"
            );
            2
        }
    }
}

/// Load the config and confirm `name` is an existing inline-`env` source. `None`
/// (printed) otherwise, so the env verbs never touch a non-env source.
fn load_env_source(name: &str) -> Option<crate::config::Config> {
    let cfg = load_config()?;
    match cfg.source(name) {
        Some(src) if src.provider == crate::provider::EnvProvider::ID => Some(cfg),
        Some(src) => {
            eprintln!(
                "sigil: source {name} is a '{}' source, not an inline env source",
                src.provider
            );
            None
        }
        None => {
            eprintln!(
                "sigil: no source named {name}; create one first: \
                 sigil-config source add {name} --provider env"
            );
            None
        }
    }
}

/// Threshold-seal `pairs` as the inline-env source `name`'s sealed record (or
/// remove it when empty), persist the threshold store, then sync the source's
/// public KEY-name list and persist the config. The values seal to the two-party
/// key `K = combine(Z_M, Z_F)`: openable only with the phone's per-request
/// partial, so nothing at rest can release them. Write-only by design: the Mac
/// seals but never reads env values back (opening needs the phone), so a `set`
/// replaces the source's whole sealed set. Returns false (printed) on failure.
fn seal_env_pairs(
    mut cfg: crate::config::Config,
    name: &str,
    pairs: &[(String, Zeroizing<String>)],
) -> bool {
    let mut store = match crate::threshold::ThresholdStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading the threshold store: {e}");
            return false;
        }
    };
    if pairs.is_empty() {
        store.remove(name);
    } else {
        // Seal to the phone's pinned Secure-Enclave share F plus the Mac share m.
        let ks = keystore::for_host();
        let phone = match crate::pairing_store::load(ks.as_ref()) {
            Ok(Some(pc)) => match pc.phone_share {
                Some(s) => s,
                None => {
                    eprintln!(
                        "sigil: this pairing has no phone Secure-Enclave share; \
                         re-pair before sealing env values"
                    );
                    return false;
                }
            },
            Ok(None) => {
                eprintln!("sigil: no phone is paired; run `sigil pair` first");
                return false;
            }
            Err(e) => {
                eprintln!("sigil: loading the pairing: {e}");
                return false;
            }
        };
        let m = match crate::threshold::load_or_create_mac_share(ks.as_ref()) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("sigil: provisioning the Mac threshold share: {e}");
                return false;
            }
        };
        let encoded = crate::provider::encode_env_pairs(pairs);
        if let Err(e) = crate::threshold::seal_secret(&mut store, name, &m, &phone, &encoded) {
            eprintln!("sigil: sealing the env values: {e}");
            return false;
        }
    }
    if let Err(e) = store.save() {
        eprintln!("sigil: saving the threshold store: {e}");
        return false;
    }
    // Sync the public KEY names onto the source (sorted+unique for a stable
    // export), never the values.
    let mut keys: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    keys.sort();
    keys.dedup();
    if let Some(src) = cfg.sources.iter_mut().find(|s| s.name == name) {
        src.keys = keys;
    }
    save_config(&cfg)
}

fn config_source_env_set(args: &[String], json: bool) -> i32 {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!(
            "usage: sigil-config source env set <name> --stdin        (KEY=VALUE lines from stdin)\n       \
             sigil-config source env set <name> --key <KEY>   (one VALUE from stdin)\n  \
             note: set REPLACES the source's whole sealed set (values are write-only under threshold)"
        );
        return 2;
    };
    let Some(cfg) = load_env_source(&name) else {
        return 1;
    };

    // Gather the complete (KEY, VALUE) set from stdin. Two shapes: a single --key
    // with its VALUE on stdin (so a value may hold '='), or --stdin bulk KEY=VALUE
    // lines. Either way values arrive on stdin, never argv, and REPLACE the whole
    // set (threshold-sealed values cannot be read back to merge onto).
    let single_key = flag_value(args, "--key").map(str::to_string);
    let pairs: Vec<(String, Zeroizing<String>)> = if let Some(key) = single_key {
        if !valid_env_key(&key) {
            eprintln!("sigil: '{key}' is not a valid environment variable name");
            return 2;
        }
        let Some(value) = read_secret_value_stdin() else {
            return 1;
        };
        vec![(key, value)]
    } else if has_flag(args, "--stdin") {
        match read_env_pairs_stdin() {
            Some(u) if u.is_empty() => {
                eprintln!("sigil: no KEY=VALUE lines on stdin");
                return 2;
            }
            Some(u) => u,
            None => return 1,
        }
    } else {
        eprintln!(
            "sigil: pass --stdin (KEY=VALUE lines on stdin) or --key <KEY> (one VALUE on stdin)"
        );
        return 2;
    };

    let count = pairs.len();
    if !seal_env_pairs(cfg, &name, &pairs) {
        return 1;
    }
    print_config_result(
        &ControlResult::line(true, format!("sealed {count} value(s) on {name}")),
        json,
    )
}

fn config_source_env_unset(args: &[String], json: bool) -> i32 {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!("usage: sigil-config source env unset <name>");
        return 2;
    };
    let Some(cfg) = load_env_source(&name) else {
        return 1;
    };
    // Threshold-sealed values are write-only, so a single key cannot be dropped
    // while preserving the others (that would require reading them, which needs
    // the phone). `unset` therefore clears the source's whole sealed set; re-set
    // the keys you want to keep with `set --stdin`.
    if flag_value(args, "--key").is_some() {
        eprintln!(
            "sigil: env values are write-only (threshold-sealed); a single key cannot be dropped.\n       \
             `unset <name>` clears the whole source; re-set the keys to keep with `set --stdin`."
        );
        return 2;
    }
    if !seal_env_pairs(cfg, &name, &[]) {
        return 1;
    }
    print_config_result(
        &ControlResult::line(true, format!("cleared all sealed values on {name}")),
        json,
    )
}

/// Read `KEY=VALUE` lines from stdin into wiped buffers for a bulk env set. Blank
/// lines and `#` comments are skipped; the KEY is trimmed and validated; the VALUE
/// is taken verbatim after the first `=` (no trimming or quote-stripping, so it is
/// exactly what the caller sent). `None` (printed) on a read/UTF-8 error or an
/// invalid key.
fn read_env_pairs_stdin() -> Option<Vec<(String, Zeroizing<String>)>> {
    let mut buf = Zeroizing::new(Vec::new());
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("sigil: reading KEY=VALUE lines from stdin: {e}");
        return None;
    }
    let text = match std::str::from_utf8(&buf) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("sigil: stdin is not valid UTF-8; refusing to store it");
            return None;
        }
    };
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // Report the line NUMBER, never its content: a mistakenly-piped secret line
        // must not be echoed to the terminal/logs.
        let Some((key, value)) = line.split_once('=') else {
            eprintln!("sigil: line {}: no '=' found", idx + 1);
            return None;
        };
        let key = key.trim().to_string();
        if !valid_env_key(&key) {
            eprintln!("sigil: '{key}' is not a valid environment variable name");
            return None;
        }
        out.push((key, Zeroizing::new(value.to_string())));
    }
    Some(out)
}

fn cmd_config_rule(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("add") => config_rule_add(&args[1..], json),
        Some("list") | None => config_rule_list(json),
        Some("remove") | Some("rm") => config_rule_remove(args.get(1).map(String::as_str), json),
        _ => {
            eprintln!("usage: sigil-config rule <add <name> --source <src> [match...] | list | remove <name>>");
            2
        }
    }
}

/// Default lease cap when `--leasable` is given without `--lease-max`: 15 minutes.
const DEFAULT_LEASE_MAX_SECS: u32 = 15 * 60;

/// Parse the lease-policy flags. The default is run-once (no lease ever granted);
/// `--leasable` makes the rule leasable with a cap set by `--lease-max <secs>`
/// (defaulting to [`DEFAULT_LEASE_MAX_SECS`]). `Err` on a malformed cap or a
/// `--lease-max` without `--leasable`.
fn lease_flag(args: &[String]) -> Result<sigil_proto::LeasePolicy, i32> {
    let leasable = has_flag(args, "--leasable");
    let max = flag_value(args, "--lease-max");
    if !leasable {
        if max.is_some() {
            eprintln!(
                "sigil: --lease-max is only meaningful with --leasable (default is run-once)"
            );
            return Err(2);
        }
        return Ok(sigil_proto::LeasePolicy::RunOnce);
    }
    let max_secs = match max {
        Some(s) => match s.parse::<u32>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!(
                    "sigil: --lease-max expects a positive whole number of seconds, got '{s}'"
                );
                return Err(2);
            }
        },
        None => DEFAULT_LEASE_MAX_SECS,
    };
    Ok(sigil_proto::LeasePolicy::Leasable { max_secs })
}

/// Build a [`Match`](crate::config::Match) from the rule-matcher flags.
fn build_match(args: &[String]) -> Result<crate::config::Match, i32> {
    let flag_equals = flag_values(args, "--flag-eq")
        .into_iter()
        .map(|fe| match fe.split_once('=') {
            Some((f, v)) => Ok(crate::config::FlagEq {
                flag: f.to_string(),
                value: v.to_string(),
            }),
            None => {
                eprintln!("sigil: --flag-eq expects <flag>=<value>, got '{fe}'");
                Err(2)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::config::Match {
        command: flag_value(args, "--command").map(str::to_string),
        subcommand: flag_value(args, "--subcommand").map(str::to_string),
        argv_contains: flag_values(args, "--argv-contains"),
        flag_present: flag_values(args, "--flag"),
        flag_equals,
        arg_regex: flag_value(args, "--regex").map(str::to_string),
    })
}

fn config_rule_add(args: &[String], json: bool) -> i32 {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!(
            "usage: sigil-config rule add <name> [--source <src> | --allow] [--command <c>] \
             [--subcommand <s>] [--argv-contains <str> ...] [--flag <f> ...] [--flag-eq <f>=<v> ...] \
             [--leasable [--lease-max <secs>]] [--timeout <sec>]\n  \
             --allow makes a passthrough rule (no approval, no injection); the default gates."
        );
        return 2;
    };
    let allow = has_flag(args, "--allow");
    let match_ = match build_match(args) {
        Ok(m) => m,
        Err(code) => return code,
    };
    // Regex is modeled but not yet evaluated (needs the `regex` dependency); a
    // rule that sets it would silently never match, so refuse it at authoring.
    if match_.arg_regex.is_some() {
        eprintln!(
            "sigil: --regex is not implemented yet (needs the regex dependency); \
             use --command/--subcommand/--argv-contains/--flag/--flag-eq"
        );
        return 2;
    }

    // An allow rule is a pure passthrough: it names no source, carries no lease,
    // and has no approval to time out. Reject the gate-only flags rather than
    // silently ignore them, so the intent is unambiguous.
    let action = if allow {
        for gate_flag in ["--source", "--leasable", "--lease-max", "--timeout"] {
            if has_flag(args, gate_flag) || flag_value(args, gate_flag).is_some() {
                eprintln!("sigil: {gate_flag} is not valid with --allow (allow is a passthrough)");
                return 2;
            }
        }
        crate::config::Action {
            mode: crate::config::RuleMode::Allow,
            source: String::new(),
            lease: sigil_proto::LeasePolicy::RunOnce,
            timeout_sec: None,
        }
    } else {
        let Some(source) = flag_value(args, "--source").map(str::to_string) else {
            eprintln!(
                "sigil: --source <name> is required (the source this rule injects from), or pass --allow for a passthrough"
            );
            return 2;
        };
        let lease = match lease_flag(args) {
            Ok(l) => l,
            Err(code) => return code,
        };
        let timeout_sec = match flag_value(args, "--timeout") {
            Some(t) => match t.parse::<u32>() {
                Ok(n) => Some(n),
                Err(_) => {
                    eprintln!("sigil: --timeout expects a whole number of seconds, got '{t}'");
                    return 2;
                }
            },
            None => None,
        };
        crate::config::Action {
            mode: crate::config::RuleMode::Gate,
            source,
            lease,
            timeout_sec,
        }
    };

    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    let rule = crate::config::Rule {
        name: name.clone(),
        match_,
        action,
    };
    if let Err(e) = cfg.add_rule(rule) {
        eprintln!("sigil: {e}");
        return 1;
    }
    if !save_config(&cfg) {
        return 1;
    }
    let s = Style::stdout();
    if !json {
        println!(
            "  {}",
            s.faint("restart the daemon to apply, then: sigil <cmd> <args>")
        );
    }
    print_config_result(
        &ControlResult::line(true, format!("rule {name} added")),
        json,
    )
}

fn config_rule_list(json: bool) -> i32 {
    let cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    if json {
        println!("{}", json::to_pretty(&cfg.rules));
        return 0;
    }
    let s = Style::stdout();
    if cfg.rules.is_empty() {
        println!(
            "  {}",
            s.dim("no rules; add one: sigil-config rule add <name> --source <src> --command <cmd>")
        );
        return 0;
    }
    println!("{}", s.cobalt("rules"));
    println!();
    for r in &cfg.rules {
        // An allow rule is a passthrough (no source, no lease); a gate rule shows
        // its target source and lease policy.
        let (target, policy) = if r.action.mode.is_allow() {
            ("-> allow (passthrough)".to_string(), "allow".to_string())
        } else {
            (
                format!("-> {}", r.action.source),
                crate::config::lease_str(r.action.lease),
            )
        };
        println!(
            "  {}  {}  {}",
            pad(&r.name, 16),
            pad(&target, 22),
            s.dim(&format!("{} \u{b7} {}", policy, describe_match(&r.match_)))
        );
    }
    0
}

/// A one-line human summary of a match's conditions.
fn describe_match(m: &crate::config::Match) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = &m.command {
        parts.push(format!("cmd={c}"));
    }
    if let Some(s) = &m.subcommand {
        parts.push(format!("sub={s}"));
    }
    for a in &m.argv_contains {
        parts.push(format!("has:{a}"));
    }
    for f in &m.flag_present {
        parts.push(format!("flag:{f}"));
    }
    for fe in &m.flag_equals {
        parts.push(format!("{}={}", fe.flag, fe.value));
    }
    if let Some(re) = &m.arg_regex {
        parts.push(format!("regex:{re}"));
    }
    if parts.is_empty() {
        "(no conditions)".to_string()
    } else {
        parts.join(", ")
    }
}

fn config_rule_remove(name: Option<&str>, json: bool) -> i32 {
    let Some(name) = name else {
        eprintln!("usage: sigil-config rule remove <name>");
        return 2;
    };
    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    let removed = cfg.remove_rule(name);
    if removed && !save_config(&cfg) {
        return 1;
    }
    let result = if removed {
        ControlResult::line(true, format!("rule {name} removed"))
    } else {
        ControlResult::line(false, format!("no rule named {name}"))
    };
    print_config_result(&result, json)
}

/// `sigil-config export`: the whole config as pretty JSON on stdout, for the
/// desktop to load or a human to inspect. Inherently machine-readable, so it
/// ignores `--json` and always emits JSON.
fn config_export() -> i32 {
    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    // An inline `env` source carries only its KEY *names* in config.json; the
    // VALUES live in the threshold store, keyed by the source name. An env source
    // with no sealed record is inert dead config (a value was never sealed, or a
    // migration dropped it): the daemon does not inject from it. So the exported
    // view drops its declared keys, presenting it as the plain gate it now
    // behaves as, rather than falsely advertising a key as set. This is a view
    // only; config.json is untouched, so a later `source env set` re-seals it.
    reconcile_unsealed_env_sources(&mut cfg);
    println!("{}", json::to_pretty(&cfg));
    0
}

/// Empty the `keys` of every inline `env` source that has no sealed record in the
/// threshold store, so a source whose value was never sealed (or was dropped by a
/// migration) presents as the plain gate it actually behaves as. Operates on a
/// config VALUE for export/inspection; it never writes config.json. A store that
/// fails to load leaves the config untouched (conservative: show what is there).
fn reconcile_unsealed_env_sources(cfg: &mut crate::config::Config) {
    let store = match crate::threshold::ThresholdStore::load() {
        Ok(s) => s,
        Err(_) => return,
    };
    for src in &mut cfg.sources {
        if src.provider == crate::provider::EnvProvider::ID
            && !src.keys.is_empty()
            && store.get(&src.name).is_none()
        {
            src.keys.clear();
        }
    }
}

/// `sigil-config import`: replace the whole config from a JSON object on stdin
/// (the form `export` emits), so the desktop can save an edited config wholesale.
fn config_import(json: bool) -> i32 {
    let mut buf = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
        eprintln!("sigil: reading the config from stdin: {e}");
        return 1;
    }
    if buf.trim().is_empty() {
        eprintln!("sigil: empty config on stdin (pipe the JSON `sigil-config export` emits)");
        return 2;
    }
    let cfg: crate::config::Config = match serde_json::from_str(&buf) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigil: parsing the config: {e}");
            return 2;
        }
    };
    // Validate referential integrity before persisting: every rule's source must
    // exist and no match may be empty, so an imported config cannot fail closed
    // on every request or dispatch to a non-existent source.
    for rule in &cfg.rules {
        if rule.match_.is_empty() {
            eprintln!("sigil: imported rule {} has no match conditions", rule.name);
            return 2;
        }
        if cfg.source(&rule.action.source).is_none() {
            eprintln!(
                "sigil: imported rule {} references unknown source {}",
                rule.name, rule.action.source
            );
            return 2;
        }
    }
    if !save_config(&cfg) {
        return 1;
    }
    // Prune any sealed env blob whose inline-env source is not in the new config,
    // so an import that drops an env source leaves no orphaned secret ciphertext.
    // (Import carries KEY names + a provider tag only; it can never carry a value,
    // so this only ever removes ciphertext, never introduces plaintext.)
    prune_orphan_env_blobs(&cfg);
    print_config_result(
        &ControlResult::line(
            true,
            format!(
                "imported {} rule(s), {} source(s)",
                cfg.rules.len(),
                cfg.sources.len()
            ),
        ),
        json,
    )
}

/// Remove threshold-sealed env records whose inline-env source is absent from
/// `cfg` (an import dropped it). Best-effort: a store error is logged, not fatal
/// to the import that already succeeded.
fn prune_orphan_env_blobs(cfg: &crate::config::Config) {
    let mut store = match crate::threshold::ThresholdStore::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: pruning orphan env blobs: {e}");
            return;
        }
    };
    let live: std::collections::HashSet<&str> = cfg
        .sources
        .iter()
        .filter(|s| s.provider == crate::provider::EnvProvider::ID)
        .map(|s| s.name.as_str())
        .collect();
    let before = store.secrets.len();
    store
        .secrets
        .retain(|r| live.contains(r.account_id.as_str()));
    if store.secrets.len() != before {
        if let Err(e) = store.save() {
            eprintln!("sigil: saving the threshold store after prune: {e}");
        }
    }
}

/// `sigil-config add <cmd> --provider <id> …`: the convenience desugar. Authors a
/// source named `<cmd>` plus a rule named `<cmd>` matching `command == <cmd>`, so
/// the common "gate this one command" case stays a one-liner. Equivalent to a
/// `config source add <cmd>` + `config rule add <cmd> --command <cmd>`.
fn config_add(args: &[String], json: bool) -> i32 {
    let s = Style::stdout();
    let Some(cmd) = args.first().filter(|a| !a.starts_with('-')).cloned() else {
        eprintln!(
            "usage: sigil-config add <cmd> --provider <id> [--source <path>] [--account <label>] [--leasable [--lease-max <secs>]]"
        );
        return 2;
    };
    let Some(provider) = flag_value(args, "--provider").map(str::to_string) else {
        eprintln!("sigil: --provider <id> is required (e.g. 1password, env-file)");
        return 2;
    };
    if !known_provider(&provider) {
        return 2;
    }
    // Historical spelling: `--source <path>` here is the env-file path (the new
    // `source` verb calls it `--path`); accept either for the desugar.
    let path = flag_value(args, "--source")
        .or_else(|| flag_value(args, "--path"))
        .map(str::to_string);
    let account = flag_value(args, "--account").map(str::to_string);
    let lease = match lease_flag(args) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if provider == crate::provider::EnvFileProvider::ID && path.is_none() {
        eprintln!("sigil: the env-file provider needs --source <path> to the KEY=VALUE file");
        return 2;
    }

    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    let src = crate::config::Source {
        name: cmd.clone(),
        provider: provider.clone(),
        account,
        path: path.clone(),
        keys: Vec::new(),
    };
    if let Err(e) = cfg.add_source(src) {
        eprintln!("sigil: {e}");
        return 1;
    }
    let rule = crate::config::Rule {
        name: cmd.clone(),
        match_: crate::config::Match {
            command: Some(cmd.clone()),
            ..crate::config::Match::default()
        },
        action: crate::config::Action {
            mode: crate::config::RuleMode::Gate,
            source: cmd.clone(),
            lease,
            timeout_sec: None,
        },
    };
    if let Err(e) = cfg.add_rule(rule) {
        eprintln!("sigil: {e}");
        return 1;
    }
    if !save_config(&cfg) {
        return 1;
    }

    if json {
        return emit_local_control(&ControlResult::line(true, format!("configured {cmd}")));
    }
    println!("{} configured {}", s.ok("\u{2713}"), s.cobalt(&cmd));
    println!("  {}  {}", s.dim("provider"), s.dim(&provider));
    if let Some(p) = &path {
        println!("  {}    {}", s.dim("source"), s.dim(p));
    }
    println!(
        "  {}     {}",
        s.dim("lease"),
        s.dim(&crate::config::lease_str(lease))
    );
    println!(
        "  {}",
        s.faint(&format!(
            "restart the daemon to apply, then: sigil {cmd} <args>  (or: sigil shim add {cmd})"
        ))
    );
    0
}

/// `sigil-config list`: a human summary of sources and rules (JSON = the whole
/// config, the same shape `export` emits).
fn config_list(json: bool) -> i32 {
    if json {
        return config_export();
    }
    let cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    if cfg.sources.is_empty() && cfg.rules.is_empty() {
        let s = Style::stdout();
        println!(
            "  {}",
            s.dim("nothing configured; add a command: sigil-config add <cmd> --provider <id>")
        );
        return 0;
    }
    config_source_list(false);
    println!();
    config_rule_list(false)
}

/// `sigil-config remove <cmd>`: the desugar's inverse. Removes the rule named
/// `<cmd>` and then its like-named source (best effort), so a `config add <cmd>`
/// is fully undone by one command.
fn config_remove(cmd: Option<&str>, json: bool) -> i32 {
    let Some(cmd) = cmd else {
        eprintln!("usage: sigil-config remove <cmd>");
        return 2;
    };
    let mut cfg = match load_config() {
        Some(c) => c,
        None => return 1,
    };
    let removed_rule = cfg.remove_rule(cmd);
    // If the like-named source is an inline env source, its sealed values must go
    // too (checked before removal, while the source is still present).
    let was_env =
        matches!(cfg.source(cmd), Some(src) if src.provider == crate::provider::EnvProvider::ID);
    // Remove the like-named source too, but only if nothing else references it.
    let removed_source = matches!(cfg.remove_source(cmd), Ok(true));
    if (removed_rule || removed_source) && !save_config(&cfg) {
        return 1;
    }
    if removed_source && was_env && !purge_env_blob(cmd) {
        return 1;
    }
    let result = if removed_rule || removed_source {
        ControlResult::line(true, format!("removed {cmd}"))
    } else {
        ControlResult::line(false, format!("nothing configured named {cmd}"))
    };
    print_config_result(&result, json)
}

/// `sigil mac-approvals --enable | --phone-only`: toggle the Mac local-approval
/// factor / hardened mode. `--phone-only` persists the hardened intent (every
/// approval degrades to the phone). `--enable` needs the Mac Secure Enclave DEK
/// envelope, whose minting is not yet verified on hardware (task #17): it
/// succeeds on the dev keystores and honestly reports "needs verification" on a
/// real enclave rather than pretending.
fn cmd_mac_approvals(args: &[String], json: bool) -> i32 {
    let s = Style::stdout();
    let enable = has_flag(args, "--enable");
    let phone_only = has_flag(args, "--phone-only");
    if enable == phone_only {
        eprintln!("usage: sigil mac-approvals --enable | --phone-only");
        return 2;
    }

    let mut settings = match Settings::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading settings: {e}");
            return 1;
        }
    };

    if phone_only {
        // Hardened: the phone is strictly required. We persist the intent; the
        // Secure Enclave envelope teardown itself defers to task #17.
        settings.mac_approvals = settings::MAC_APPROVALS_PHONE_ONLY.to_string();
        if let Err(e) = settings.save() {
            eprintln!("sigil: saving settings: {e}");
            return 1;
        }
        if json {
            println!("{}", json::to_line(&json::MacApprovalsJson { ok: true }));
        } else {
            println!(
                "{} mac approvals hardened (phone required)",
                s.ok("\u{2713}")
            );
        }
        return 0;
    }

    // --enable: provision the Mac threshold share and confirm the keystore is
    // usable. The phone is always the approving factor now (there is no local
    // Touch-ID approve path); this only readies the Mac side. On a dev keystore
    // this always succeeds; a real keystore failure is surfaced honestly.
    let ks = keystore::for_host();
    match crate::threshold::load_or_create_mac_share(ks.as_ref()) {
        Ok(_) => {
            settings.mac_approvals = settings::MAC_APPROVALS_ENABLED.to_string();
            if let Err(e) = settings.save() {
                eprintln!("sigil: saving settings: {e}");
                return 1;
            }
            if json {
                println!("{}", json::to_line(&json::MacApprovalsJson { ok: true }));
            } else {
                println!(
                    "{} Mac side readied (the phone remains the approving factor)",
                    s.ok("\u{2713}")
                );
            }
            0
        }
        Err(e) => {
            eprintln!(
                "sigil: cannot ready the Mac side: {e}. The phone remains the approving factor."
            );
            if json {
                println!("{}", json::to_line(&json::MacApprovalsJson { ok: false }));
            }
            1
        }
    }
}

/// `sigil settings get|set`: read or change preferences. `set` takes either a
/// `<key> <value>` pair or, with `--json`, a JSON object patch on stdin (the
/// form the Mac app uses); a patch is *merged*, so unlisted keys are untouched.
fn cmd_settings(args: &[String], json: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("get") | None => settings_get(json),
        Some("set") => settings_set(&args[1..], json),
        _ => {
            eprintln!("usage: sigil settings <get|set <key> <value>>");
            2
        }
    }
}

fn settings_get(json: bool) -> i32 {
    let settings = match Settings::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading settings: {e}");
            return 1;
        }
    };
    if json {
        println!("{}", json::to_pretty(&settings.to_json()));
        return 0;
    }
    let s = Style::stdout();
    println!("{}", s.cobalt("settings"));
    println!();
    println!(
        "  {}  {}",
        pad("approval_timeout_sec", 22),
        s.dim(&settings.approval_timeout_sec.to_string())
    );
    println!(
        "  {}  {}",
        pad("notifications", 22),
        s.dim(&settings.notifications.to_string())
    );
    println!(
        "  {}  {}",
        pad("retention_days", 22),
        s.dim(&settings.retention_days.to_string())
    );
    println!("  {}  {}", pad("relay_url", 22), s.dim(&settings.relay_url));
    println!(
        "  {}  {}",
        pad("reduce_motion", 22),
        s.dim(&settings.reduce_motion.to_string())
    );
    println!(
        "  {}  {}",
        pad("mac_approvals", 22),
        s.dim(&settings.mac_approvals)
    );
    0
}

fn settings_set(args: &[String], json: bool) -> i32 {
    let mut settings = match Settings::load() {
        Ok(st) => st,
        Err(e) => {
            eprintln!("sigil: loading settings: {e}");
            return 1;
        }
    };

    // A positional `<key> <value>` wins; otherwise read a JSON object patch from
    // stdin (the Mac app pipes its five settings fields this way).
    let outcome = match (args.first(), args.get(1)) {
        (Some(key), Some(value)) => settings.set(key, value).map_err(|e| e.to_string()),
        _ => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                Err(format!("reading the settings patch from stdin: {e}"))
            } else if buf.trim().is_empty() {
                Err("usage: sigil settings set <key> <value>  (or pipe a JSON patch)".to_string())
            } else {
                serde_json::from_str::<serde_json::Value>(&buf)
                    .map_err(|e| format!("parsing the settings patch: {e}"))
                    .and_then(|patch| settings.merge_json(&patch).map_err(|e| e.to_string()))
            }
        }
    };

    if let Err(msg) = outcome {
        eprintln!("sigil: {msg}");
        return 2;
    }
    if let Err(e) = settings.save() {
        eprintln!("sigil: saving settings: {e}");
        return 1;
    }

    if json {
        println!("{}", json::to_pretty(&settings.to_json()));
        return 0;
    }
    println!("{} settings saved", Style::stdout().ok("\u{2713}"));
    0
}

/// `sigil wipe [--force]`: remove the pairing, accounts, keys, and settings.
/// The destructive path is explicit: without `--force` it refuses.
fn cmd_wipe(args: &[String], json: bool) -> i32 {
    let s = Style::stdout();
    if !has_flag(args, "--force") {
        if json {
            return emit_local_control(&ControlResult::failed(vec![
                "refusing to wipe without --force".to_string(),
            ]));
        }
        eprintln!(
            "{} sigil wipe removes the pairing, accounts, SSH keys, command config, settings, and history.\n  \
             Re-run with --force to confirm: sigil wipe --force",
            s.brass("\u{2717}")
        );
        return 2;
    }

    let mut lines: Vec<String> = Vec::new();

    // The pairing (config file + the daemon identity blob in the keystore).
    let ks = keystore::for_host();
    match crate::pairing_store::remove(ks.as_ref()) {
        Ok(true) => lines.push("removed pairing".to_string()),
        Ok(false) => {}
        Err(e) => lines.push(format!("pairing: {e}")),
    }

    // The remaining ~/.sigil state files.
    if let Some(home) = paths::sigil_home() {
        for (name, path) in [
            ("accounts", home.join("sigil.db")),
            ("ssh keys", home.join("ssh-keys.json")),
            ("config", home.join("config.json")),
            ("legacy command config", home.join("commands.json")),
            ("settings", home.join("settings.json")),
            ("keystore file", home.join("dev-keystore.json")),
            ("history", home.join("history.jsonl")),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => lines.push(format!("removed {name}")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => lines.push(format!("{name}: {e}")),
            }
        }
    }

    if lines.is_empty() {
        lines.push("nothing to remove".to_string());
    }
    let result = ControlResult::ok(lines);
    if json {
        return emit_local_control(&result);
    }
    for line in &result.lines {
        println!("  {} {line}", s.ok("\u{2713}"));
    }
    println!(
        "  {}",
        s.faint("restart the daemon to apply: sigil restart")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_verbs_take_precedence_over_command_dispatch() {
        // A runtime verb is reserved in the lean binary; a bare tool name (op,
        // gcloud) is not, so it falls through to the `sigil <cmd>` primitive.
        for v in [
            "status", "up", "daemon", "pair", "run", "ssh", "shim", "help", "version",
        ] {
            assert!(is_reserved_verb(v), "{v} must be a reserved verb");
        }
        // Management verbs moved to sigil-config, so they are NOT reserved in the
        // lean binary — which frees those names to be gated as `sigil <name>`.
        for c in [
            "op",
            "gcloud",
            "bw",
            "kubectl",
            "mytool",
            "config",
            "settings",
            "wipe",
            "mac-approvals",
        ] {
            assert!(!is_reserved_verb(c), "{c} must dispatch as a command");
        }
    }

    #[test]
    fn run_escape_hatch_strips_the_optional_double_dash() {
        // `sigil run -- status ...` runs a tool named `status`, not the verb.
        let with = vec!["--".to_string(), "status".to_string(), "-l".to_string()];
        assert_eq!(
            strip_run_prefix(&with),
            &["status".to_string(), "-l".to_string()]
        );
        // `sigil run op read` (no --) is equivalent for a non-colliding name.
        let without = vec!["op".to_string(), "read".to_string()];
        assert_eq!(strip_run_prefix(&without), &without[..]);
    }
}
