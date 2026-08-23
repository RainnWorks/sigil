//! The status and doctor report builders: the single source of truth for the
//! host-side facts (shim drift, `op` discovery, pairing factor, relay
//! reachability, counts) that the `status` and `doctor` control messages carry.
//!
//! The daemon is the source of truth for the machine interface, so it answers
//! `Frame::Status` / `Frame::Doctor` by calling these. The human `sigil` CLI
//! renders the same shapes: when the daemon is up it renders the daemon's reply,
//! and when the daemon is down it falls back to these builders locally (with
//! `daemon_up = false`) so `status`/`doctor` still work headless. One builder,
//! two renderers, no divergence.

use crate::json::{CheckJson, FactorJson, OpJson, ShimJson, StatusJson};
use crate::{keystore, paths};

/// How `op` resolves for a gated run, as the reports must state it: the
/// operator's config pin when there is one, the `PATH` walk otherwise.
///
/// This exists so `status` and `doctor` answer the question the daemon actually
/// asks at spawn time ([`paths::resolve_command`]) rather than a different one
/// that usually agrees. Reporting `op` as missing while a pinned `op` runs fine
/// — or the reverse — is worse than not reporting it, because both rows are read
/// as a verdict on whether Sigil will work.
///
/// A missing/unreadable config is treated as "no pin", not as an error: these
/// builders are diagnostics and must produce a report on a half-installed box.
fn resolve_op() -> Result<std::path::PathBuf, paths::ResolveError> {
    let cfg = crate::config::Config::load().ok();
    paths::resolve_command("op", cfg.as_ref().and_then(|c| c.binary_for("op")))
}

/// Build the full status report. `daemon_up` is whether the control socket is
/// listening (always true when the daemon answers its own `Frame::Status`).
pub fn status(daemon_up: bool) -> StatusJson {
    let shim = paths::ShimStatus::detect();
    let real_op = resolve_op().ok();
    let accounts = crate::threshold::ThresholdStore::load()
        .map(|s| s.secrets.len())
        .unwrap_or(0);

    let shim_kind = if shim.healthy() {
        "healthy"
    } else if !shim.installed {
        "not_installed"
    } else if shim.issue().is_some() {
        "drift"
    } else {
        "unknown"
    };
    let shim_path = paths::shim_bin_dir().map(|p| p.join("op").display().to_string());

    let paired = crate::pairing_store::summary().ok().flatten();
    let biometric = keystore::for_host().is_biometric();
    let factor = match (&paired, biometric) {
        (Some(p), _) => FactorJson {
            kind: "phone".into(),
            relay: Some(p.relay_url.clone()),
        },
        (None, true) => FactorJson {
            kind: "biometric".into(),
            relay: None,
        },
        (None, false) => FactorJson {
            kind: "fail_closed".into(),
            relay: None,
        },
    };
    let relay_url = paired.as_ref().map(|p| p.relay_url.clone());
    let relay_reachable = paired.as_ref().map(|p| relay_reachable(&p.relay_url));

    StatusJson {
        daemon_up,
        socket: crate::local::socket_path().display().to_string(),
        shim: ShimJson {
            kind: shim_kind.into(),
            path: shim_path,
            issue: shim.issue(),
        },
        op: OpJson {
            found: real_op.is_some(),
            path: real_op.map(|p| p.display().to_string()),
        },
        accounts,
        factor,
        relay_reachable,
        relay_url,
        // Lockdown was removed; the field stays on the wire (always false) so an
        // older Mac app that still decodes `locked_down` keeps working.
        locked_down: false,
        // Filled by the daemon, which is the only party that knows: it read the
        // keystore once at startup and holds whether it was provisioned. A CLI
        // computing this locally would be guessing from a file it may not be able
        // to read, so the local path leaves it absent (= unknown).
        keystore_sealed: None,
        keystore_provisioned: None,
    }
}

/// Build the doctor checks. `daemon_up` gates the "daemon socket reachable"
/// check. The final ssh-agent row is informational (always `ok`).
pub fn doctor(daemon_up: bool) -> Vec<CheckJson> {
    let shim = paths::ShimStatus::detect();
    let real_op = resolve_op();
    let mut checks = Vec::new();
    let mut push = |label: &str, ok: bool, hint: &str| {
        checks.push(CheckJson {
            label: label.to_string(),
            ok,
            hint: hint.to_string(),
        });
    };

    // 1. shim health (drift): installed, first on PATH, points at this binary.
    push(
        "shim wins on PATH and is current",
        shim.healthy(),
        &shim.issue().unwrap_or_default(),
    );

    // 2. daemon socket reachable.
    push(
        "daemon socket reachable",
        daemon_up,
        if daemon_up {
            ""
        } else {
            "daemon not running (sigil start)"
        },
    );

    // 3. socket path fits sun_path (a too-long path binds a truncated name).
    match crate::service::socket_path_fits() {
        Ok(()) => push("socket path length ok", true, ""),
        Err(e) => push("socket path length ok", false, &e),
    }

    // 4. approving factor: paired phone > biometric > fail closed.
    let paired = crate::pairing_store::summary().ok().flatten();
    let biometric = keystore::for_host().is_biometric();
    let (factor_ok, factor_hint) = match (&paired, biometric) {
        (Some(_), _) => (true, "paired phone (sealed remote approval)".to_string()),
        (None, true) => (true, "hardware biometric (Secure Enclave)".to_string()),
        (None, false) => (
            false,
            "no factor: fails closed. Run `sigil pair`, or start `--dev-insecure` for dev".into(),
        ),
    };
    push("approving factor resolved", factor_ok, &factor_hint);

    // 5. relay reachable, when a pairing names one.
    if let Some(p) = &paired {
        let reachable = relay_reachable(&p.relay_url);
        push(
            "relay reachable",
            reachable,
            if reachable {
                ""
            } else {
                "cannot reach the paired relay (approvals will time out)"
            },
        );
    }

    // 6. a real op to run. The hint carries the resolver's own words, because
    // "no `op` on PATH" was wrong for every failure a pin can produce and, on a
    // box whose `op` simply lives somewhere unusual, told the operator to fix
    // their `PATH` — which is the one thing that cannot work, since the daemon
    // does not use theirs. `sigil-config binary set op <path>` is the fix, so
    // the hint says so.
    push(
        "real op found",
        real_op.is_ok(),
        &match &real_op {
            Ok(_) => String::new(),
            Err(paths::ResolveError::NotOnPath(_)) => "no `op` in the daemon's own PATH \
                 (/usr/local/bin, /usr/bin, /bin, /usr/sbin, /sbin, plus Homebrew on macOS). \
                 If `op` lives elsewhere, pin it: sigil-config binary set op <absolute path>"
                .to_string(),
            Err(e) => format!("{e}. Fix or clear it: sigil-config binary set|unset op"),
        },
    );

    // 7. ssh-agent: report the socket and served-key count. Informational.
    let ssh_sock = crate::sshagent::socket_path();
    let ssh_count = crate::sshagent::SshKeyConfig::load()
        .map(|c| c.files.len() + c.stored.len())
        .unwrap_or(0);
    push(
        "ssh-agent socket",
        true,
        &format!(
            "{ssh_count} key(s); export SSH_AUTH_SOCK={}",
            ssh_sock.display()
        ),
    );

    checks
}

/// Best-effort relay reachability: parse `http(s)`/`ws(s)://host[:port]` and try
/// a short TCP connect. Dependency-free (no HTTP client in this binary); a
/// successful connect distinguishes "relay down" from "relay up" for the report.
pub fn relay_reachable(url: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reflects_daemon_up() {
        let up = status(true);
        assert!(up.daemon_up);
        // Lockdown was removed; the wire field stays but is always false.
        assert!(!up.locked_down);

        let down = status(false);
        assert!(!down.daemon_up);
        assert!(!down.locked_down);
        // The socket path is reported in both cases.
        assert!(!down.socket.is_empty());
    }

    #[test]
    fn doctor_gates_the_socket_check_on_daemon_up() {
        let up = doctor(true);
        let sock = up
            .iter()
            .find(|c| c.label == "daemon socket reachable")
            .unwrap();
        assert!(sock.ok);

        let down = doctor(false);
        let sock = down
            .iter()
            .find(|c| c.label == "daemon socket reachable")
            .unwrap();
        assert!(!sock.ok);
        // The final row is the informational ssh-agent one.
        assert_eq!(down.last().unwrap().label, "ssh-agent socket");
        assert!(down.last().unwrap().ok);
    }

    #[test]
    fn relay_reachable_rejects_a_dead_port() {
        // Port 1 on localhost is not listening.
        assert!(!relay_reachable("http://127.0.0.1:1"));
    }
}
