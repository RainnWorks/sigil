//! `sigil up`: the one idempotent, self-healing keystone that makes "the
//! daemon is healthy" true, end to end.
//!
//! Everything calls this instead of managing pieces by hand: the Mac app on
//! launch, the Sigil skill at the start of any Sigil work, the human at most
//! once after install. Running it twice in a row is free; the second run
//! reports all-ok and changes nothing. See
//! `docs/design/agent-operated-sigil.md` section 2 for the contract.
//!
//! The chain, in order (each step idempotent):
//!
//! 1. **binary**: the running binary is copied to the install-stable
//!    `~/.sigil/bin/sigil` when the bytes differ, so launchd never depends on
//!    a build checkout path surviving.
//! 2. **plist**: the LaunchAgent plist is re-rendered against the stable
//!    binary (unconditional KeepAlive, shim-first PATH, and no keystore pin:
//!    daemon and CLI share one default) and rewritten only when it differs.
//! 3. **loaded**: the agent is bootstrapped into the GUI domain; a changed
//!    plist is re-bootstrapped (bootout + bootstrap) so launchd reads it.
//! 4. **daemon**: a real `Status` control round trip must answer, bounded by
//!    socket timeouts. This catches the zombie mode (process alive, listeners
//!    gone) that a bare liveness probe or launchd's own view calls healthy.
//!    An unhealthy or restart-needing daemon is kickstarted and re-probed.
//! 5. **ssh agent**: the agent socket accepts a connection (same process;
//!    the kickstart above is the heal).
//! 6. **shim**: `~/.sigil/bin/op` points at the installed runtime and
//!    `~/.sigil/bin` is on PATH in the shell profile.
//! 7. **paired**: a phone pairing exists, else the one thing `up` cannot do
//!    alone is reported as action needed (the ceremony requires the human).

use std::io::Write as _;
use std::time::Duration;

use crate::local::{self, Frame, Reply};
use crate::style::Style;
use crate::{keystore, paths, service, setup, sshagent};

/// How one step of the chain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    /// Already true; nothing done.
    Ok,
    /// Was not true; made true.
    Fixed,
    /// Cannot be made true without the human (e.g. pairing).
    ActionNeeded,
    /// Tried and failed; the note says why.
    Failed,
}

/// One line of the `sigil up` report.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: &'static str,
    pub state: StepState,
    pub note: String,
}

impl Step {
    fn ok(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            state: StepState::Ok,
            note: note.into(),
        }
    }
    fn fixed(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            state: StepState::Fixed,
            note: note.into(),
        }
    }
    fn action(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            state: StepState::ActionNeeded,
            note: note.into(),
        }
    }
    fn failed(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            state: StepState::Failed,
            note: note.into(),
        }
    }
}

/// Per-probe socket timeout: a healthy daemon answers a `Status` in
/// milliseconds; anything slower than this counts as down.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// How many times to re-probe after a kickstart, and the pause between
/// probes. launchd respawn plus daemon arm-up is comfortably under this
/// total (~4.5 s) on a healthy machine.
const PROBE_ATTEMPTS: u32 = 15;
const PROBE_PAUSE: Duration = Duration::from_millis(300);

/// One bounded `Status` round trip on the control socket. `Err` is the
/// human-readable reason the daemon is not healthy. Both connect-refused and
/// connected-but-silent count as down; the latter is the zombie mode.
fn probe_control() -> Result<(), String> {
    let sock = local::socket_path();
    let mut stream = std::os::unix::net::UnixStream::connect(&sock)
        .map_err(|e| format!("control socket not listening ({e})"))?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(PROBE_TIMEOUT)))
        .map_err(|e| format!("probe setup failed ({e})"))?;
    local::send_frame(&stream, &Frame::Status, &[])
        .map_err(|e| format!("control socket accepted but did not read ({e})"))?;
    match local::recv_reply(&mut stream) {
        Ok(Reply::Json { .. }) => Ok(()),
        Ok(other) => Err(format!("unexpected status reply: {other:?}")),
        Err(e) => Err(format!("control socket accepted but did not answer ({e})")),
    }
}

/// The ssh-agent socket accepts a connection. Connect-only: the control round
/// trip above already proves the serve loop; this proves the second listener
/// is bound (the zombie mode dropped both).
fn probe_ssh_agent() -> Result<(), String> {
    let sock = sshagent::socket_path();
    std::os::unix::net::UnixStream::connect(&sock)
        .map(|_| ())
        .map_err(|e| format!("{} not listening ({e})", sock.display()))
}

/// Probe the daemon, kickstarting once if it does not answer, then re-probing
/// with a bounded backoff. `force_restart` kickstarts first regardless (a
/// refreshed binary or plist needs a restart to take effect).
fn ensure_daemon_running(force_restart: bool) -> Step {
    if !force_restart {
        if let Ok(()) = probe_control() {
            return Step::ok("daemon", "answering on the control socket");
        }
    }
    let verb = if force_restart {
        "restarted"
    } else {
        "kickstarted"
    };
    if let Err(e) = service::kickstart() {
        return Step::failed("daemon", format!("kickstart failed: {e:#}"));
    }
    let mut last_err = String::new();
    for _ in 0..PROBE_ATTEMPTS {
        std::thread::sleep(PROBE_PAUSE);
        match probe_control() {
            Ok(()) => return Step::fixed("daemon", format!("{verb}; now answering")),
            Err(e) => last_err = e,
        }
    }
    Step::failed(
        "daemon",
        format!("{verb} but still not answering: {last_err}"),
    )
}

/// The full ensure chain. Every step runs (no early bail), so one report shows
/// everything that is wrong at once; later steps degrade honestly when an
/// earlier one failed.
pub fn ensure_up() -> Vec<Step> {
    let mut steps = Vec::new();

    // 1. The install-stable binary.
    let installed = match service::ensure_installed_binary() {
        Ok((path, true)) => {
            steps.push(Step::fixed(
                "binary",
                format!("installed to {}", path.display()),
            ));
            Some(path)
        }
        Ok((path, false)) => {
            steps.push(Step::ok("binary", path.display().to_string()));
            Some(path)
        }
        Err(e) => {
            steps.push(Step::failed("binary", format!("{e:#}")));
            None
        }
    };

    // 2 + 3. The plist and its bootstrap. A changed plist is re-bootstrapped
    // so launchd actually reads the new definition; an unchanged one is
    // bootstrapped only if not loaded.
    let mut restarted_via_bootstrap = false;
    let mut plist_changed = false;
    match installed.as_deref().map(service::install_plist_for) {
        Some(Ok((plist, changed))) => {
            plist_changed = changed;
            let loaded = service::is_loaded();
            if changed && loaded {
                // Reload the definition. bootout also stops the daemon; the
                // bootstrap (RunAtLoad) starts the new one.
                let result = service::bootout().and_then(|()| service::bootstrap(&plist));
                match result {
                    Ok(()) => {
                        restarted_via_bootstrap = true;
                        steps.push(Step::fixed("launchd", "plist updated and reloaded"));
                    }
                    Err(e) => steps.push(Step::failed("launchd", format!("reload failed: {e:#}"))),
                }
            } else if !loaded {
                match service::bootstrap(&plist) {
                    Ok(()) => {
                        restarted_via_bootstrap = true;
                        steps.push(Step::fixed("launchd", "agent bootstrapped"));
                    }
                    Err(e) => {
                        steps.push(Step::failed("launchd", format!("bootstrap failed: {e:#}")))
                    }
                }
            } else if changed {
                // Written but was not loaded to begin with and bootstrap above
                // covers it; unreachable, kept for exhaustiveness.
                steps.push(Step::fixed("launchd", "plist updated"));
            } else {
                steps.push(Step::ok("launchd", "agent loaded, plist current"));
            }
        }
        Some(Err(e)) => steps.push(Step::failed("launchd", format!("{e:#}"))),
        None => steps.push(Step::failed("launchd", "skipped: no installed binary")),
    }

    // 4. The daemon answers. A refreshed binary needs a restart to run the new
    // bytes unless the re-bootstrap above already restarted it.
    let binary_refreshed = steps
        .iter()
        .any(|s| s.name == "binary" && s.state == StepState::Fixed);
    let force_restart = (binary_refreshed || plist_changed) && !restarted_via_bootstrap;
    if restarted_via_bootstrap {
        // Give the fresh daemon its probe window without forcing a second
        // restart on top of the bootstrap's.
        let mut probe = Step::failed("daemon", "not answering after reload");
        for _ in 0..PROBE_ATTEMPTS {
            match probe_control() {
                Ok(()) => {
                    probe = Step::fixed("daemon", "answering after reload");
                    break;
                }
                Err(e) => probe = Step::failed("daemon", format!("not answering: {e}")),
            }
            std::thread::sleep(PROBE_PAUSE);
        }
        steps.push(probe);
    } else {
        steps.push(ensure_daemon_running(force_restart));
    }

    // 5. The ssh-agent listener (same process; heal was the kickstart above).
    match probe_ssh_agent() {
        Ok(()) => steps.push(Step::ok(
            "ssh-agent",
            sshagent::socket_path().display().to_string(),
        )),
        Err(e) => steps.push(Step::failed("ssh-agent", e)),
    }

    // 6. The shim: alias installed and pointing at the runtime, dir on PATH.
    steps.push(ensure_shim());

    // 7. Pairing: the one step only the human can complete.
    if crate::pairing_store::exists() {
        steps.push(Step::ok("pairing", "phone paired"));
    } else {
        steps.push(Step::action("pairing", "no phone paired; run: sigil pair"));
    }

    // Posture note, always shown: where the daemon's blobs live is something the
    // human should be able to read off one screen. Stated plainly, not as a
    // problem. Under the threshold posture the on-disk store holds no standalone
    // data-decryption secret (`m` is inert without the phone's per-request
    // partial), which is what makes it the right at-rest store for a portable,
    // unsigned daemon. The honest residual (F9) is kept in the same breath: a
    // file reader gets the daemon identity AND `m` together, so a phished
    // approval could decrypt off-box.
    let ks = keystore::for_host();
    steps.push(match ks.backend() {
        "file" => Step::ok(
            "keystore",
            format!(
                "portable on-disk store, threshold-protected: {} ({})",
                keystore::file_keystore_residual(),
                keystore::file_keystore_path().display()
            ),
        ),
        other => Step::ok(
            "keystore",
            format!("SIGIL_KEYSTORE={other} is overriding the default on-disk store; keep it set for every sigil process or unset it everywhere"),
        ),
    });
    // A pairing stranded in the login keychain by an older build is worth one
    // line here: nothing is moved automatically, and silence would read as "your
    // pairing is gone".
    if let Some(note) = keystore::legacy_keychain_notice(ks.as_ref()) {
        steps.push(Step::action("keystore (legacy)", note));
    }
    // An older plist pinned the store into launchd. `up` has just rewritten it
    // without the pin; say so rather than leaving a mystery entry behind.
    if service::installed_dev_keystore_pin().is_some() {
        steps.push(Step::ok(
            "keystore (plist)",
            "removed a leftover keystore pin from the launchd plist; the daemon and the CLI now share one default",
        ));
    }

    steps
}

/// Ensure the `op` shim alias and the profile PATH entry. Fixed-vs-ok keys
/// off what actually changed (the link target, the profile file), never off
/// the calling shell's PATH: `up` may run from a GUI app or a bare exec
/// environment whose PATH says nothing about the human's shells.
fn ensure_shim() -> Step {
    let link_before = paths::shim_bin_dir()
        .map(|d| d.join("op"))
        .and_then(|l| std::fs::read_link(l).ok());
    let link = match setup::install_shim() {
        Ok((link, _target)) => link,
        Err(e) => return Step::failed("shim", format!("install failed: {e:#}")),
    };
    let link_after = std::fs::read_link(&link).ok();
    let relinked = link_before != link_after;
    let profile_added = match setup::ensure_profile_path() {
        Ok(added) => added,
        Err(e) => return Step::failed("shim", format!("profile edit failed: {e:#}")),
    };
    if profile_added {
        Step::fixed(
            "shim",
            "installed; PATH added to profile (open a new shell)",
        )
    } else if relinked {
        Step::fixed("shim", format!("relinked {}", link.display()))
    } else {
        Step::ok("shim", link.display().to_string())
    }
}

/// Render the report and compute the exit code: 0 when everything is ok or
/// fixed, 1 when anything needs the human or failed.
pub fn cmd_up() -> i32 {
    let s = Style::stdout();
    println!("{}", s.cobalt("sigil up"));
    println!();
    let steps = ensure_up();
    let mut code = 0;
    for step in &steps {
        let (glyph, word) = match step.state {
            StepState::Ok => (s.ok("\u{2713}"), "ok"),
            StepState::Fixed => (s.ok("\u{25cf}"), "fixed"),
            StepState::ActionNeeded => (s.brass("\u{2717}"), "action needed"),
            StepState::Failed => (s.deny("\u{2717}"), "failed"),
        };
        if !matches!(step.state, StepState::Ok | StepState::Fixed) {
            code = 1;
        }
        // Pad the plain text, then color it: ANSI escapes inside a width spec
        // would break the column alignment.
        println!(
            "  {} {glyph} {} {}",
            s.dim(&format!("{:<10}", step.name)),
            format_args!("{word:<14}"),
            s.dim(&step.note)
        );
    }
    println!();
    if code == 0 {
        println!("  {}", s.ok("sigil is up"));
    } else {
        println!("  {}", s.brass("sigil needs attention (see above)"));
    }
    let _ = std::io::stdout().flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_control_reports_down_when_nothing_listens() {
        // Point the probe at a socket path that cannot exist; it must fail
        // with a reason, never hang (the timeouts bound it) or panic.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("SIGIL_SOCK");
        std::env::set_var("SIGIL_SOCK", "/nonexistent/sigil-up-test/daemon.sock");
        let r = probe_control();
        match prev {
            Some(v) => std::env::set_var("SIGIL_SOCK", v),
            None => std::env::remove_var("SIGIL_SOCK"),
        }
        let err = r.expect_err("no daemon must read as down");
        assert!(err.contains("not listening"), "honest reason: {err}");
    }

    #[test]
    fn probe_control_calls_a_silent_listener_down() {
        // The zombie mode from the field: something accepts but never answers.
        // The probe must time out to an error, not hang.
        let dir = std::env::temp_dir().join(format!("sigil-up-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("silent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        // Nothing ever accepts/answers; connect succeeds, the reply read must
        // time out.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("SIGIL_SOCK");
        std::env::set_var("SIGIL_SOCK", &sock);
        let started = std::time::Instant::now();
        let r = probe_control();
        match prev {
            Some(v) => std::env::set_var("SIGIL_SOCK", v),
            None => std::env::remove_var("SIGIL_SOCK"),
        }
        assert!(r.is_err(), "a silent listener must read as down");
        assert!(
            started.elapsed() < PROBE_TIMEOUT * 3,
            "the probe must be bounded by its timeouts"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn step_states_map_to_exit_semantics() {
        // fixed is success (up made it true); action/failed are attention.
        assert_eq!(StepState::Ok, StepState::Ok);
        let fixed = Step::fixed("x", "y");
        assert_eq!(fixed.state, StepState::Fixed);
        let action = Step::action("x", "y");
        assert_eq!(action.state, StepState::ActionNeeded);
        let failed = Step::failed("x", "y");
        assert_eq!(failed.state, StepState::Failed);
    }
}
