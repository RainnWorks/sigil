//! The macOS launchd LaunchAgent: keep the daemon running across logins and
//! crashes, and give GUI-spawned tools a `PATH` that finds the shim.
//!
//! The daemon must be up whenever Tom is, and must restart itself if it crashes,
//! without a terminal babysitting it. That is a per-user launchd LaunchAgent
//! (`~/Library/LaunchAgents/works.rainn.sigil.plist`): `RunAtLoad` starts it at
//! login, `KeepAlive { Crashed }` respawns it after a crash but leaves it down
//! after a clean `sigil stop`. The plist's `EnvironmentVariables` also pins a
//! `PATH` with `~/.sigil/bin` first, so a tool a GUI app launches (which does
//! not read the shell profile) still resolves the shim ahead of the real `op`.
//!
//! Plist generation and the socket-length check are pure and unit-tested. The
//! `launchctl` calls are Mac-runtime and are marked NEEDS VERIFICATION; they
//! shell out rather than link a private API.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths;

/// The LaunchAgent label. Also the launchd service name under `gui/<uid>`.
pub const LABEL: &str = "works.rainn.sigil";

/// macOS `sun_path` capacity. A unix socket path at or above this length is
/// silently truncated by `bind(2)`, so the daemon and clients would disagree.
const SUN_PATH_MAX: usize = 104;

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
/// starts the daemon immediately; `KeepAlive.Crashed` respawns after a crash but
/// not after a clean exit, so `sigil stop` (a bootout) stays stopped.
pub fn render_plist(
    sigil_bin: &Path,
    logs_dir: &Path,
    shim_dir: &Path,
    dev_keystore: Option<&str>,
) -> String {
    let program = sigil_bin.display();
    let out_log = logs_dir.join("daemon.out.log");
    let err_log = logs_dir.join("daemon.err.log");
    let path_value = plist_path_value(shim_dir);
    // Carry the dev keystore mode into the launchd environment when the installer
    // is running in dev (`SIGIL_DEV_KEYSTORE` set). Without this the launchd-spawned
    // daemon would default to the real Secure Enclave keystore even though the rest
    // of the dev loop uses the file keystore, so pairing/approval would break. In a
    // production install the variable is unset, so nothing is pinned and the daemon
    // uses the hardware keystore.
    let keystore_env = match dev_keystore {
        Some(mode) => {
            format!("\n        <key>SIGIL_DEV_KEYSTORE</key>\n        <string>{mode}</string>")
        }
        None => String::new(),
    };
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
        <string>{path_value}</string>{keystore_env}
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
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

/// Write the plist to `~/Library/LaunchAgents/works.rainn.sigil.plist`, creating the
/// logs dir. Returns the plist path. Does not (un)load it; that is [`bootstrap`].
pub fn install_plist() -> Result<PathBuf> {
    let sigil_bin = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("resolving the sigil binary path")?;
    let logs = paths::logs_dir().context("HOME is not set")?;
    let shim_dir = paths::shim_bin_dir().context("HOME is not set")?;
    std::fs::create_dir_all(&logs).with_context(|| format!("creating {}", logs.display()))?;

    let plist_path = paths::launch_agent_plist().context("HOME is not set")?;
    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Pin the dev keystore mode into the plist when this installer is itself
    // running in dev, so the launchd-spawned daemon matches the dev loop. A
    // production install has this unset and pins nothing.
    let dev_keystore = std::env::var("SIGIL_DEV_KEYSTORE").ok();
    let body = render_plist(&sigil_bin, &logs, &shim_dir, dev_keystore.as_deref());
    std::fs::write(&plist_path, body)
        .with_context(|| format!("writing {}", plist_path.display()))?;
    Ok(plist_path)
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

/// One-generation log rotation: if `path` exceeds `max_bytes`, move it to
/// `path.1` (replacing any previous `.1`). Called on daemon start so the launchd
/// append-mode logs do not grow without bound. Best-effort: any io error is
/// swallowed so logging can never keep the daemon from arming.
fn rotate_one(path: &Path, max_bytes: u64) {
    let too_big = std::fs::metadata(path)
        .map(|m| m.len() > max_bytes)
        .unwrap_or(false);
    if too_big {
        let rolled = path.with_extension("log.1");
        let _ = std::fs::rename(path, rolled);
    }
}

/// Rotate the daemon's out/err logs if they have grown past `max_bytes`.
pub fn rotate_logs(max_bytes: u64) {
    if let Some(dir) = paths::logs_dir() {
        rotate_one(&dir.join("daemon.out.log"), max_bytes);
        rotate_one(&dir.join("daemon.err.log"), max_bytes);
    }
}

/// The default per-start rotation threshold: 5 MiB per log.
pub const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

/// Check that the daemon's socket path fits in `sun_path` with margin. A path at
/// or above the limit is truncated by the kernel, so the daemon and clients bind
/// and connect to different names and never meet. Returns the offending path and
/// its length on failure.
pub fn socket_path_fits() -> Result<(), String> {
    path_fits(&crate::local::socket_path())
}

/// The pure length check behind [`socket_path_fits`].
fn path_fits(sock: &Path) -> Result<(), String> {
    let len = sock.as_os_str().len();
    if len >= SUN_PATH_MAX {
        Err(format!(
            "daemon socket path is {len} bytes (limit {SUN_PATH_MAX}): {}",
            sock.display()
        ))
    } else {
        Ok(())
    }
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
            None,
        );
        assert!(plist.contains("<string>works.rainn.sigil</string>"));
        assert!(plist.contains("<string>/Users/tom/.cargo/bin/sigil</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>Crashed</key>"));
        // The shim dir must be the FIRST PATH entry so it wins over a real op.
        assert!(plist.contains("<string>/Users/tom/.sigil/bin:/opt/homebrew/bin"));
        assert!(plist.contains("daemon.out.log"));
        assert!(plist.contains("daemon.err.log"));
        // A production install pins no dev keystore, so the daemon uses hardware.
        assert!(!plist.contains("SIGIL_DEV_KEYSTORE"));
    }

    #[test]
    fn plist_pins_the_dev_keystore_when_the_installer_is_in_dev() {
        // A dev install (SIGIL_DEV_KEYSTORE set) must bake the mode into the
        // launchd environment, else the launchd-spawned daemon would default to
        // the Secure Enclave keystore and break the file-keystore dev loop.
        let plist = render_plist(
            Path::new("/Users/tom/.sigil/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
            Some("file"),
        );
        assert!(plist.contains("<key>SIGIL_DEV_KEYSTORE</key>"));
        assert!(plist.contains("<string>file</string>"));
    }

    #[test]
    fn path_value_puts_the_shim_dir_first() {
        let p = plist_path_value(Path::new("/home/x/.sigil/bin"));
        assert!(p.starts_with("/home/x/.sigil/bin:"));
        assert!(p.contains("/usr/bin"));
    }

    #[test]
    fn socket_length_check_flags_an_overlong_path() {
        let long = PathBuf::from("/".repeat(200));
        let r = path_fits(&long);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("limit"));
    }

    #[test]
    fn socket_length_check_passes_for_a_short_path() {
        assert!(path_fits(Path::new("/tmp/sigil/d.sock")).is_ok());
    }

    #[test]
    fn log_rotation_moves_an_oversized_file() {
        let dir = std::env::temp_dir().join(format!("sigil-logrot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("daemon.err.log");
        std::fs::write(&f, vec![b'x'; 100]).unwrap();
        rotate_one(&f, 10);
        assert!(!f.exists(), "the oversized log was rolled away");
        assert!(
            f.with_extension("log.1").exists(),
            "the .1 generation exists"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
