//! Supervision: keep the daemon running across logins and crashes, and pin a
//! `PATH` that finds the shim ahead of a real `op`.
//!
//! This module is the platform-agnostic seam `sigil up` drives. The two
//! backends behind it answer the same five questions:
//!
//! - [`install_definition_for`]: write the supervision definition for a given
//!   binary, and say whether it changed.
//! - [`is_loaded`]: is the supervision layer in place?
//! - [`bootstrap`] / [`bootout`] / [`kickstart`]: start it, stop it, restart the
//!   daemon in place.
//!
//! On macOS that is a launchd LaunchAgent ([`launchd`]). Everywhere else it is
//! a Sigil supervisor process ([`supervisor`]). `docs/design/linux-lifecycle.md`
//! records why the obvious Linux answer (a systemd unit) is not the answer
//! here, and what the supervisor guarantees instead.
//!
//! `up` stays the one entry point either way: nothing in this split adds a verb
//! (`docs/design/agent-operated-sigil.md` section 2), and the supervisor process
//! is reached as `sigil daemon --supervise`, which `up` starts.
//!
//! Both backend modules are compiled on every platform and only DISPATCHED to
//! per platform. That is deliberate. Everything pure in them is unit-tested,
//! CI's Rust job runs on Linux and its Mac job does not run tests, so a
//! `cfg(target_os)` on either module would turn its tests green by deleting
//! them. The platform-specific syscalls are simply never reached off their
//! platform.
//!
//! What lives HERE is what has no platform in it at all: the install-stable
//! binary copy, log rotation, and the socket-length check.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths;

pub mod launchd;
pub mod supervisor;

/// The service label. Also the launchd service name under `gui/<uid>`.
pub const LABEL: &str = "works.rainn.sigil";

/// macOS `sun_path` capacity. A unix socket path at or above this length is
/// silently truncated by `bind(2)`, so the daemon and clients would disagree.
/// Checked on every platform: Linux's limit is 108, so the stricter number is
/// the portable one and a path that passes here passes everywhere.
const SUN_PATH_MAX: usize = 104;

/// What the supervision step is called in the `sigil up` report. The report is
/// read by a human diagnosing their own box, so it names the thing they would
/// actually go and look at.
#[cfg(target_os = "macos")]
pub const SUPERVISION: &str = "launchd";
#[cfg(not(target_os = "macos"))]
pub const SUPERVISION: &str = "supervisor";

/// Whether a refreshed binary requires the supervision layer itself to be
/// reloaded, rather than just the daemon restarted.
///
/// On macOS it does not: launchd is the operating system's, it is not the bytes
/// `up` just replaced, and a `kickstart` runs the new binary. Off macOS the
/// supervisor IS one of those bytes, so an update that only cycled the daemon
/// would leave the supervisor running the previous build forever. This is the
/// difference between borrowing the platform's supervisor and shipping one.
#[cfg(target_os = "macos")]
pub const RELOAD_ON_BINARY_REFRESH: bool = false;
#[cfg(not(target_os = "macos"))]
pub const RELOAD_ON_BINARY_REFRESH: bool = true;

/// Write the supervision definition for a daemon at `sigil_bin`, creating the
/// logs dir. Compares before writing so a no-op re-run does not touch the file.
/// Returns `(definition_path, changed)`. Does not load it; that is
/// [`bootstrap`].
pub fn install_definition_for(sigil_bin: &Path) -> Result<(PathBuf, bool)> {
    #[cfg(target_os = "macos")]
    {
        launchd::install_definition_for(sigil_bin)
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::install_definition_for(sigil_bin)
    }
}

/// Write the definition for the install-stable binary (copying the running
/// binary into `~/.sigil/bin/sigil` first). Returns the definition path. The
/// legacy entrypoint `sigil start` and `sigil setup` share with `sigil up`.
pub fn install_definition() -> Result<PathBuf> {
    let (installed, _) = ensure_installed_binary()?;
    let (def_path, _) = install_definition_for(&installed)?;
    Ok(def_path)
}

/// Whether the supervision layer is in place. Loaded says nothing about
/// healthy: it can be holding a wedged process, which is why `sigil up` also
/// does a real control round trip.
pub fn is_loaded() -> bool {
    #[cfg(target_os = "macos")]
    {
        launchd::is_loaded()
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::is_loaded()
    }
}

/// Load the supervision definition and start the daemon. Idempotent: an
/// already-loaded service is success, so setup can call it blind.
pub fn bootstrap(definition: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        launchd::bootstrap(definition)
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::bootstrap(definition)
    }
}

/// Unload the supervision definition and stop the daemon. A service that is
/// not loaded is not an error. The stop is deliberate, so nothing respawns.
pub fn bootout() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        launchd::bootout()
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::bootout()
    }
}

/// Restart the running daemon in place, starting the supervision layer first if
/// it is not up. This is `up`'s heal.
pub fn kickstart() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        launchd::kickstart()
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::kickstart()
    }
}

/// Run the supervisor process: `sigil daemon --supervise`. Off macOS this is
/// the process [`bootstrap`] starts. On macOS it is not how the daemon is
/// supervised, and says so rather than starting a second supervision scheme
/// beside launchd.
pub fn supervise(args: &[String]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = args;
        anyhow::bail!(
            "--supervise is not used on macOS: launchd supervises the daemon. Run `sigil up`."
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        supervisor::run(args)
    }
}

/// The stale `SIGIL_DEV_KEYSTORE` pin an installed launchd plist still carries,
/// if any. A macOS-only leftover from an older build: nothing has ever written
/// such a pin off Darwin, so this is `None` there rather than a check that
/// cannot fire.
pub fn installed_dev_keystore_pin() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        launchd::installed_dev_keystore_pin()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The install-stable home of the daemon binary: `~/.sigil/bin/sigil`. The
/// supervision definition and the shim aliases point HERE, never at wherever
/// the binary happened to be built (a `target/release` inside a git checkout is
/// one branch switch away from not existing, which strands the supervisor).
/// Anchored to `HOME` like [`paths::shim_bin_dir`] so a `SIGIL_HOME` test
/// override never moves the path the supervisor was told about.
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
    // on the old bytes until the restart.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).with_context(|| format!("installing {}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", dst.display()))?;
    Ok(true)
}

/// One-generation log rotation: if `path` exceeds `max_bytes`, move it to
/// `path.1` (replacing any previous `.1`). Called on daemon start so the
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

    /// The seam itself: exactly one backend is dispatched to, and the two
    /// platform constants agree about which one. A build where `SUPERVISION`
    /// says "launchd" but the reload rule is the supervisor's would produce a
    /// report that describes a different mechanism from the one running.
    #[test]
    fn the_platform_constants_describe_the_same_backend() {
        // Compared as one value, so the pair cannot drift apart: naming launchd
        // while reloading like the supervisor (or the reverse) would produce a
        // report describing a different mechanism from the one running.
        let backend = (SUPERVISION, RELOAD_ON_BINARY_REFRESH);
        if cfg!(target_os = "macos") {
            // launchd is the OS's, not the bytes `up` just replaced: a
            // kickstart is enough to pick up a refreshed binary.
            assert_eq!(backend, ("launchd", false));
        } else {
            // The supervisor IS one of those bytes, so it must be reloaded too
            // or the update is silently half-applied.
            assert_eq!(backend, ("supervisor", true));
        }
    }
}
