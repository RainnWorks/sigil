//! The macOS launchd LaunchAgent backend: keep the daemon running across
//! logins and crashes, and give GUI-spawned tools a `PATH` that finds the shim.
//!
//! The daemon must be up whenever Tom is, and must restart itself if it dies,
//! without a terminal babysitting it. That is a per-user launchd LaunchAgent
//! (`~/Library/LaunchAgents/works.rainn.sigil.plist`): `RunAtLoad` starts it at
//! login, unconditional `KeepAlive` respawns it after ANY exit; `sigil stop`
//! still stops it because a bootout unloads the job entirely. The plist's
//! `ProgramArguments` point at the install-stable copy `sigil up` maintains at
//! `~/.sigil/bin/sigil`, never at a build checkout. The plist's
//! `EnvironmentVariables` also pins a `PATH` with `~/.sigil/bin` first, so a
//! tool a GUI app launches (which does not read the shell profile) still
//! resolves the shim ahead of the real `op`.
//!
//! Plist generation and the `PATH` value are pure and unit-tested. The
//! `launchctl` calls are Mac-runtime and are marked NEEDS VERIFICATION; they
//! shell out rather than link a private API.
//!
//! **This module is compiled on every platform, and dispatched to only on
//! macOS** (see the parent module). That is deliberate: everything pure in here
//! is unit-tested, and CI's Rust job runs on Linux. A `cfg(target_os = "macos")`
//! on the module would turn those tests green by deleting them, which is the
//! one way a platform split can quietly cost coverage. The `launchctl` calls are
//! simply never reached off Darwin.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths;
use crate::service::LABEL;

/// Directories a GUI-launched tool must search to find both the shim (first)
/// and a real `op` (Homebrew, system). Prepended with `~/.sigil/bin`.
const BASE_PATH_DIRS: &[&str] = &[
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
];

/// Build the `PATH` value for the plist: the shim dir first, then the standard
/// tool locations. `shim_dir` is `~/.sigil/bin`.
fn plist_path_value(shim_dir: &Path) -> String {
    let mut parts = vec![shim_dir.display().to_string()];
    parts.extend(BASE_PATH_DIRS.iter().map(|s| s.to_string()));
    parts.join(":")
}

/// Render the LaunchAgent plist for a daemon at `sigil_bin`, logging into
/// `logs_dir`, with the shim `PATH` rooted at `shim_dir`.
///
/// Pure and deterministic so it can be unit-tested and diffed. `RunAtLoad`
/// starts the daemon immediately; `KeepAlive` is unconditional `true` so the
/// daemon is respawned after ANY exit (crash, error exit, or a stray clean
/// exit), which is what always-on means. Stopping deliberately still works:
/// `sigil stop` is a bootout (unload), which KeepAlive does not resurrect.
pub fn render_plist(sigil_bin: &Path, logs_dir: &Path, shim_dir: &Path) -> String {
    let program = sigil_bin.display();
    let out_log = logs_dir.join("daemon.out.log");
    let err_log = logs_dir.join("daemon.err.log");
    let path_value = plist_path_value(shim_dir);
    // No keystore variable is pinned here, deliberately. The daemon and the CLI
    // both default to the on-disk store with no environment at all, so there is
    // nothing to keep in sync; pinning one was exactly how a launchd daemon and a
    // plain shell ended up disagreeing about where the pairing lived. An older
    // plist that still carries the pin is simply rewritten without it on the next
    // `sigil up` (the bodies differ, so the file is replaced), and the pin remains
    // harmless in the meantime because it names the same store as the default.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{program}</string>
        <string>daemon</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{path_value}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{out}</string>
    <key>StandardErrorPath</key>
    <string>{err}</string>
</dict>
</plist>
"#,
        out = out_log.display(),
        err = err_log.display(),
    )
}

/// Extract a `SIGIL_DEV_KEYSTORE` pin from an existing plist body. Kept only to
/// RECOGNIZE a plist written by an older build (which pinned the store into the
/// launchd environment); nothing writes the pin anymore. Pure string surgery over
/// a file we rendered ourselves.
fn plist_dev_keystore_pin(body: &str) -> Option<String> {
    let key_at = body.find("<key>SIGIL_DEV_KEYSTORE</key>")?;
    let rest = &body[key_at..];
    let open = rest.find("<string>")? + "<string>".len();
    let close = rest[open..].find("</string>")?;
    let value = &rest[open..open + close];
    (!value.is_empty()).then(|| value.to_string())
}

/// Write the plist to `~/Library/LaunchAgents/works.rainn.sigil.plist` for a
/// daemon at `sigil_bin`, creating the logs dir. Compares before writing so a
/// no-op re-run does not touch the file. Returns `(plist_path, changed)`.
/// Does not (un)load it; that is [`bootstrap`].
pub fn install_definition_for(sigil_bin: &Path) -> Result<(PathBuf, bool)> {
    let logs = paths::logs_dir().context("HOME is not set")?;
    let shim_dir = paths::shim_bin_dir().context("HOME is not set")?;
    std::fs::create_dir_all(&logs).with_context(|| format!("creating {}", logs.display()))?;

    let plist_path = paths::launch_agent_plist().context("HOME is not set")?;
    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let existing = std::fs::read_to_string(&plist_path).ok();
    let body = render_plist(sigil_bin, &logs, &shim_dir);
    if existing.as_deref() == Some(body.as_str()) {
        return Ok((plist_path, false));
    }
    std::fs::write(&plist_path, body)
        .with_context(|| format!("writing {}", plist_path.display()))?;
    Ok((plist_path, true))
}

/// The stale `SIGIL_DEV_KEYSTORE` pin an installed plist still carries, if any.
/// Only a leftover from an older build now: `sigil up` rewrites the plist without
/// it. Surfaced so the report can say the daemon was re-rendered rather than
/// leaving a mystery environment entry in a file the human may read.
pub fn installed_dev_keystore_pin() -> Option<String> {
    let plist = paths::launch_agent_plist()?;
    let body = std::fs::read_to_string(plist).ok()?;
    plist_dev_keystore_pin(&body)
}

/// `gui/<uid>` domain target for launchctl.
fn gui_domain() -> String {
    // SAFETY: getuid is a pure query with no failure mode.
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

/// Load the agent into the user's GUI domain (`launchctl bootstrap`). Idempotent
/// enough for setup: a re-bootstrap of an already-loaded label is reported, not
/// fatal.
///
/// NEEDS VERIFICATION (Mac runtime): confirm with
///   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/works.rainn.sigil.plist
///   launchctl print gui/$(id -u)/works.rainn.sigil
pub fn bootstrap(plist: &Path) -> Result<()> {
    run_launchctl(&["bootstrap", &gui_domain(), &plist.display().to_string()])
}

/// Unload the agent (`launchctl bootout`). A "not loaded" result is not an
/// error. NEEDS VERIFICATION: `launchctl bootout gui/$(id -u)/works.rainn.sigil`.
pub fn bootout() -> Result<()> {
    let target = format!("{}/{LABEL}", gui_domain());
    run_launchctl(&["bootout", &target])
}

/// Restart the running daemon in place (`launchctl kickstart -k`). NEEDS
/// VERIFICATION: `launchctl kickstart -k gui/$(id -u)/works.rainn.sigil`.
pub fn kickstart() -> Result<()> {
    let target = format!("{}/{LABEL}", gui_domain());
    run_launchctl(&["kickstart", "-k", &target])
}

/// Whether the agent is loaded in the user's GUI domain (`launchctl print`
/// succeeds for the label). Loaded says nothing about healthy: a loaded
/// service can hold a wedged process, which is why `sigil up` also does a
/// real control round trip.
pub fn is_loaded() -> bool {
    std::process::Command::new("launchctl")
        .args(["print", &format!("{}/{LABEL}", gui_domain())])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Shell out to `launchctl` with `args`, mapping a nonzero exit to an error that
/// carries stderr. A few benign statuses (already loaded / not loaded) are
/// treated as success so setup and teardown are idempotent.
fn run_launchctl(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .with_context(|| format!("running launchctl {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    // 5 = "Input/output error" surfaces for an already-bootstrapped label;
    // 3 = "No such process" for a bootout of something not loaded. Both mean the
    // desired end state already holds.
    let code = out.status.code().unwrap_or(-1);
    if matches!(code, 3 | 5) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    anyhow::bail!(
        "launchctl {} failed (status {code}): {}",
        args.join(" "),
        stderr.trim()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_has_the_reliability_keys_and_shim_first_path() {
        let plist = render_plist(
            Path::new("/Users/tom/.cargo/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
        );
        assert!(plist.contains("<string>works.rainn.sigil</string>"));
        assert!(plist.contains("<string>/Users/tom/.cargo/bin/sigil</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        // Always-on: unconditional KeepAlive, not the old crash-only dict that
        // left the daemon down after a non-crash exit.
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(!plist.contains("<key>Crashed</key>"));
        // The shim dir must be the FIRST PATH entry so it wins over a real op.
        assert!(plist.contains("<string>/Users/tom/.sigil/bin:/opt/homebrew/bin"));
        assert!(plist.contains("daemon.out.log"));
        assert!(plist.contains("daemon.err.log"));
        // No keystore variable is pinned at all now: daemon and CLI share one
        // default, so there is nothing to keep in sync through launchd.
        assert!(!plist.contains("SIGIL_DEV_KEYSTORE"));
        assert!(!plist.contains("SIGIL_KEYSTORE"));
    }

    #[test]
    fn a_render_never_pins_a_keystore_even_in_a_dev_shell() {
        // The installer's own environment used to leak into the plist. It must
        // not anymore: a developer with the variable set in their shell should
        // still install a plist that behaves like everyone else's.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("SIGIL_DEV_KEYSTORE");
        std::env::set_var("SIGIL_DEV_KEYSTORE", "memory");
        let plist = render_plist(
            Path::new("/Users/tom/.sigil/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
        );
        match prev {
            Some(v) => std::env::set_var("SIGIL_DEV_KEYSTORE", v),
            None => std::env::remove_var("SIGIL_DEV_KEYSTORE"),
        }
        assert!(!plist.contains("SIGIL_DEV_KEYSTORE"));
        assert!(!plist.contains("<key>SIGIL_KEYSTORE</key>"));
    }

    #[test]
    fn an_old_plist_that_still_pins_the_store_is_recognized_and_replaced() {
        // Tolerance for what is already installed: an older plist carrying the
        // pin still parses (so `up` can say it was rewritten), and the body we
        // now render differs from it, which is what replaces the file.
        let fresh = render_plist(
            Path::new("/Users/tom/.sigil/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
        );
        let old = fresh.replace(
            "<key>PATH</key>",
            "<key>SIGIL_DEV_KEYSTORE</key>\n        <string>file</string>\n        <key>PATH</key>",
        );
        assert_eq!(plist_dev_keystore_pin(&old).as_deref(), Some("file"));
        assert_ne!(
            old, fresh,
            "an old plist must not compare equal, so it is rewritten"
        );
        assert_eq!(plist_dev_keystore_pin(&fresh), None);
        // Not fooled by unrelated content or truncation.
        assert_eq!(plist_dev_keystore_pin(""), None);
        assert_eq!(
            plist_dev_keystore_pin("<key>SIGIL_DEV_KEYSTORE</key>"),
            None
        );
    }

    #[test]
    fn path_value_puts_the_shim_dir_first() {
        let p = plist_path_value(Path::new("/home/x/.sigil/bin"));
        assert!(p.starts_with("/home/x/.sigil/bin:"));
        assert!(p.contains("/usr/bin"));
    }
}
