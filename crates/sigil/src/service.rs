//! The macOS launchd LaunchAgent: keep the daemon running across logins and
//! crashes, and give GUI-spawned tools a `PATH` that finds the shim.
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
/// starts the daemon immediately; `KeepAlive` is unconditional `true` so the
/// daemon is respawned after ANY exit (crash, error exit, or a stray clean
/// exit), which is what always-on means. Stopping deliberately still works:
/// `sigil stop` is a bootout (unload), which KeepAlive does not resurrect.
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

/// The install-stable home of the daemon binary: `~/.sigil/bin/sigil`. The
/// plist's `ProgramArguments` and the shim aliases point HERE, never at
/// wherever the binary happened to be built (a `target/release` inside a git
/// checkout is one branch switch away from not existing, which strands
/// launchd). Anchored to `HOME` like [`paths::shim_bin_dir`] so a `SIGIL_HOME`
/// test override never moves the path launchd was told about.
pub fn installed_bin() -> Result<PathBuf> {
    Ok(paths::shim_bin_dir()
        .context("HOME is not set")?
        .join("sigil"))
}

/// Ensure `~/.sigil/bin/sigil` is a real, byte-identical copy of the running
/// binary, copying (unlink-then-copy, mode 0755) when it differs, is absent,
/// or is a symlink (a symlink into a build checkout is exactly the fragility
/// this replaces). Returns `(installed_path, refreshed)`. Explicit contract:
/// the binary you run this from becomes the installed runtime, so the dev
/// loop is `cargo build --release && target/release/sigil up`. Running from
/// the installed copy itself is a no-op.
///
/// Also refreshes a sibling `sigil-config` copy, best-effort, when one sits
/// next to the running binary: the management CLI should survive the checkout
/// moving just like the runtime, but its absence never fails the daemon
/// ensure.
pub fn ensure_installed_binary() -> Result<(PathBuf, bool)> {
    let current = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("resolving the running binary path")?;
    let installed = installed_bin()?;
    let refreshed = install_copy(&current, &installed)?;
    // Best-effort sibling: `sigil-config` built next to the running binary.
    if let Some(config_src) = current.parent().map(|d| d.join("sigil-config")) {
        if config_src.is_file() && config_src != installed.with_file_name("sigil-config") {
            let _ = install_copy(&config_src, &installed.with_file_name("sigil-config"));
        }
    }
    Ok((installed, refreshed))
}

/// Copy `src` to `dst` (unlink-then-copy, 0755) unless `dst` is already a
/// real file with identical bytes. Returns whether a copy happened. A `dst`
/// that IS `src` (running from the installed copy) is left alone; a symlink
/// at `dst` is always replaced with a real file, even if it points at
/// identical bytes, because the symlink's target path is the fragility.
fn install_copy(src: &Path, dst: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let dst_is_symlink = std::fs::symlink_metadata(dst)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if !dst_is_symlink {
        // Running from the installed copy itself: nothing to do.
        if dst.canonicalize().ok().as_deref() == Some(src) {
            return Ok(false);
        }
        let up_to_date = match (std::fs::read(src), std::fs::read(dst)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if up_to_date {
            return Ok(false);
        }
    }
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Unlink first: overwriting a running executable's inode in place is how
    // macOS kills future execs of it; a fresh inode leaves any running daemon
    // on the old bytes until the kickstart.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).with_context(|| format!("installing {}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", dst.display()))?;
    Ok(true)
}

/// Extract the `SIGIL_DEV_KEYSTORE` pin from an existing plist body, so a
/// re-render from a clean shell carries the pin forward instead of silently
/// stripping it (which would orphan the daemon identity the dev keystore
/// holds). Pure string surgery over a file we rendered ourselves.
fn plist_dev_keystore_pin(body: &str) -> Option<String> {
    let key_at = body.find("<key>SIGIL_DEV_KEYSTORE</key>")?;
    let rest = &body[key_at..];
    let open = rest.find("<string>")? + "<string>".len();
    let close = rest[open..].find("</string>")?;
    let value = &rest[open..open + close];
    (!value.is_empty()).then(|| value.to_string())
}

/// The dev-keystore mode to pin into a fresh plist render: the installer's own
/// environment wins; otherwise any pin already present in `existing_plist` is
/// carried forward. A production install (no env, no prior pin) pins nothing
/// and the daemon uses the hardware keystore.
fn dev_keystore_pin(existing_plist: Option<&str>) -> Option<String> {
    std::env::var("SIGIL_DEV_KEYSTORE")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| existing_plist.and_then(plist_dev_keystore_pin))
}

/// Write the plist to `~/Library/LaunchAgents/works.rainn.sigil.plist` for a
/// daemon at `sigil_bin`, creating the logs dir. Compares before writing so a
/// no-op re-run does not touch the file. Returns `(plist_path, changed)`.
/// Does not (un)load it; that is [`bootstrap`].
pub fn install_plist_for(sigil_bin: &Path) -> Result<(PathBuf, bool)> {
    let logs = paths::logs_dir().context("HOME is not set")?;
    let shim_dir = paths::shim_bin_dir().context("HOME is not set")?;
    std::fs::create_dir_all(&logs).with_context(|| format!("creating {}", logs.display()))?;

    let plist_path = paths::launch_agent_plist().context("HOME is not set")?;
    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let existing = std::fs::read_to_string(&plist_path).ok();
    let dev_keystore = dev_keystore_pin(existing.as_deref());
    let body = render_plist(sigil_bin, &logs, &shim_dir, dev_keystore.as_deref());
    if existing.as_deref() == Some(body.as_str()) {
        return Ok((plist_path, false));
    }
    std::fs::write(&plist_path, body)
        .with_context(|| format!("writing {}", plist_path.display()))?;
    Ok((plist_path, true))
}

/// Write the plist for the install-stable binary (copying the running binary
/// into `~/.sigil/bin/sigil` first). Returns the plist path. The legacy
/// entrypoint `sigil start` and `sigil setup` share with `sigil up`.
pub fn install_plist() -> Result<PathBuf> {
    let (installed, _) = ensure_installed_binary()?;
    let (plist_path, _) = install_plist_for(&installed)?;
    Ok(plist_path)
}

/// The `SIGIL_DEV_KEYSTORE` pin the installed plist currently carries, if
/// any. `sigil up` surfaces this in its report (sec-review F1): the pin is
/// deliberately self-perpetuating (see [`dev_keystore_pin`]) and the daemon's
/// own banner now prints once per process, so without this line the
/// plaintext-share posture would be invisible on the surfaces anyone reads.
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
        // Always-on: unconditional KeepAlive, not the old crash-only dict that
        // left the daemon down after a non-crash exit.
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(!plist.contains("<key>Crashed</key>"));
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
    fn dev_keystore_pin_is_parsed_out_of_an_existing_plist() {
        // A re-render from a clean shell must carry an existing pin forward,
        // never silently strip it (the dev keystore holds the daemon identity;
        // losing the pin orphans the pairing until someone notices).
        let pinned = render_plist(
            Path::new("/Users/tom/.sigil/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
            Some("file"),
        );
        assert_eq!(plist_dev_keystore_pin(&pinned).as_deref(), Some("file"));

        let unpinned = render_plist(
            Path::new("/Users/tom/.sigil/bin/sigil"),
            Path::new("/Users/tom/.sigil/logs"),
            Path::new("/Users/tom/.sigil/bin"),
            None,
        );
        assert_eq!(plist_dev_keystore_pin(&unpinned), None);
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
    fn install_copy_replaces_symlinks_and_stale_bytes_but_not_identical_files() {
        let dir = std::env::temp_dir().join(format!(
            "sigil-installcopy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src-bin");
        std::fs::write(&src, b"new bytes").unwrap();
        let dst = dir.join("installed");

        // Absent -> copied.
        assert!(install_copy(&src, &dst).unwrap());
        assert_eq!(std::fs::read(&dst).unwrap(), b"new bytes");
        // A real file with identical bytes -> untouched.
        assert!(!install_copy(&src, &dst).unwrap());
        // Stale bytes -> refreshed.
        std::fs::write(&dst, b"old bytes").unwrap();
        assert!(install_copy(&src, &dst).unwrap());
        assert_eq!(std::fs::read(&dst).unwrap(), b"new bytes");
        // A symlink is ALWAYS replaced with a real file, even when it points
        // at identical bytes: the symlink's target path is the fragility.
        std::fs::remove_file(&dst).unwrap();
        std::os::unix::fs::symlink(&src, &dst).unwrap();
        assert!(install_copy(&src, &dst).unwrap());
        assert!(
            !std::fs::symlink_metadata(&dst)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the installed runtime is a real file"
        );
        std::fs::remove_dir_all(&dir).ok();
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
