//! Filesystem discovery: the real `op`, the shim install location, where the
//! shim sits relative to `op` on `PATH`, and the `~/.sigil` layout (config,
//! logs, the launchd plist).

use std::path::{Path, PathBuf};

/// The Sigil home directory: `$SIGIL_HOME` when set (tests and alternate
/// installs), else `~/.sigil`. `None` only if neither `SIGIL_HOME` nor `HOME`
/// is set, which no real login shell allows.
pub fn sigil_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("SIGIL_HOME") {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".sigil"))
}

/// `~/.sigil/bin`, where `sigil shim install` drops the `op` symlink.
pub fn shim_bin_dir() -> Option<PathBuf> {
    // Kept anchored to `~/.sigil/bin` (not `sigil_home()/bin`) so `SIGIL_HOME`
    // test overrides never move the PATH entry a real profile points at.
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".sigil").join("bin"))
}

/// `<sigil_home>/pairing.json`: the persisted phone-pairing config (public
/// parts; the daemon identity lives in the keystore). See `pairing_store`.
pub fn pairing_path() -> Option<PathBuf> {
    sigil_home().map(|h| h.join("pairing.json"))
}

/// `<sigil_home>/push.json`: the persisted phone push-notification
/// registrations, keyed by mailbox id. See `push_store`. Beside `pairing.json`
/// and, like it, 0600; a device token is not a credential but is kept private.
pub fn push_path() -> Option<PathBuf> {
    sigil_home().map(|h| h.join("push.json"))
}

/// `<sigil_home>/logs`, where the launchd agent's stdout/stderr are rotated.
pub fn logs_dir() -> Option<PathBuf> {
    sigil_home().map(|h| h.join("logs"))
}

/// The launchd LaunchAgent plist for the daemon.
pub fn launch_agent_plist() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/LaunchAgents/works.rainn.sigil.plist"))
}

/// True if `p` is a regular file with any execute bit set.
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

/// The canonical path of this running binary, if resolvable.
fn own_binary() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

/// Locate the real `<cmd>`: the first `cmd` on `PATH` that is not one of our
/// proxy aliases. This is the resolver that actually chooses what to `exec`
/// (daemon-down) or spawn (daemon-up, WITH an injected credential), so getting
/// its exclusion right is security-relevant: a candidate mistaken for the real
/// tool would be run with the approved secret.
///
/// Two independent exclusion rules, either sufficient (the design doc's "hard
/// problem 1(a)"):
///   1. the candidate canonicalises to a Sigil binary an alias points at (the
///      running binary, or the sibling `sigil` runtime the manager installs
///      aliases at). Catches a symlink alias in any directory.
///   2. the candidate lives inside the proxy dir (`~/.sigil/bin`). Catches a
///      NON-symlink alias too (a script, or a hard copy of the binary) that
///      canonicalisation cannot see. Without this, a same-UID-planted non-sigil
///      executable in the proxy dir would be spawned with the injected token
///      (sec-review-1 Finding A); it also keeps `list`/`doctor` diagnostics
///      correct when called from the `sigil-config` binary (Finding B).
pub fn find_real(cmd: &str) -> Option<PathBuf> {
    find_real_in(
        cmd,
        std::env::var_os("PATH").as_deref(),
        own_binary(),
        crate::proxy::alias_target(),
        shim_bin_dir().and_then(|d| d.canonicalize().ok()),
    )
}

/// The pure core of [`find_real`]: everything reads from the explicit inputs plus
/// the filesystem, so tests drive it with synthetic dirs and no process-global
/// env mutation. `own`/`alias_target` are canonical Sigil-binary paths to
/// exclude (rule 1); `proxy_dir` is the canonical `~/.sigil/bin` (rule 2).
fn find_real_in(
    cmd: &str,
    path: Option<&std::ffi::OsStr>,
    own: Option<PathBuf>,
    alias_target: Option<PathBuf>,
    proxy_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    for dir in std::env::split_paths(path?) {
        let cand = dir.join(cmd);
        if !is_executable(&cand) {
            continue;
        }
        // Rule 2: anything resident in the proxy dir is ours, symlink or not.
        if let (Some(pd), Ok(parent)) = (&proxy_dir, dir.canonicalize()) {
            if &parent == pd {
                continue;
            }
        }
        // Rule 1: an alias symlink living outside the proxy dir resolves to a
        // Sigil binary; exclude both the running binary and the alias target.
        if let Ok(canon) = cand.canonicalize() {
            if own.as_ref() == Some(&canon) || alias_target.as_ref() == Some(&canon) {
                continue;
            }
        }
        return Some(cand);
    }
    None
}

/// Locate the real `op`: [`find_real`] specialised to `op`. Kept as a named
/// helper because the 1Password provider and the `op`-specific paths reference
/// it directly.
pub fn find_real_op() -> Option<PathBuf> {
    find_real("op")
}

/// The health of the `op` shim install, as seen from the running binary.
///
/// The daemon and `sigil doctor` read this to catch **shim drift**: the shim
/// silently ceasing to be the `op` a shell resolves, which would route requests
/// straight to the real `op` with no approval gate. Three drifts are caught: the
/// link never installed / removed, another `op` winning on `PATH`, and the link
/// pointing at a stale `sigil` binary (e.g. after a rebuild to a new path).
#[derive(Debug, Clone)]
pub struct ShimStatus {
    /// `~/.sigil/bin/op` exists as a symlink.
    pub installed: bool,
    /// `~/.sigil/bin` is present somewhere on `PATH`.
    pub dir_on_path: bool,
    /// The first `op` a `PATH` walk resolves lives in the shim dir (the shim
    /// wins over any real `op`).
    pub first_on_path: bool,
    /// The shim link resolves to the currently running `sigil` binary. `false`
    /// means it points at a stale binary or is broken.
    pub resolves_to_current: bool,
    /// What `~/.sigil/bin/op` canonicalises to, if it resolves.
    pub link_target: Option<PathBuf>,
    /// The first `op` on `PATH` that is not the shim, if any.
    pub real_op: Option<PathBuf>,
}

impl ShimStatus {
    /// Compute the shim health from the current process, `PATH`, and filesystem.
    pub fn detect() -> Self {
        Self::detect_with(
            own_binary(),
            shim_bin_dir(),
            std::env::var_os("PATH").as_deref(),
        )
    }

    /// The pure core of [`detect`](Self::detect): everything reads from the
    /// three explicit inputs (the running binary, the shim dir, and `PATH`) plus
    /// the filesystem, so tests can drive it with synthetic dirs and no
    /// process-global env mutation.
    pub fn detect_with(
        own: Option<PathBuf>,
        shim_dir: Option<PathBuf>,
        path: Option<&std::ffi::OsStr>,
    ) -> Self {
        let link = shim_dir.as_ref().map(|d| d.join("op"));
        let installed = link
            .as_ref()
            .map(|l| l.symlink_metadata().is_ok())
            .unwrap_or(false);
        let link_target = link.as_ref().and_then(|l| l.canonicalize().ok());
        let resolves_to_current = matches!((&link_target, &own), (Some(t), Some(o)) if t == o);

        let mut first_op_dir: Option<PathBuf> = None;
        let mut real_op: Option<PathBuf> = None;
        let mut dir_on_path = false;
        if let Some(path) = path {
            for dir in std::env::split_paths(path) {
                let is_shim_dir = shim_dir.as_ref() == Some(&dir);
                if is_shim_dir {
                    dir_on_path = true;
                }
                let cand = dir.join("op");
                if !is_executable(&cand) {
                    continue;
                }
                if first_op_dir.is_none() {
                    first_op_dir = Some(dir.clone());
                }
                if !is_shim_dir && real_op.is_none() {
                    real_op = Some(cand);
                }
            }
        }
        let first_on_path = matches!((&first_op_dir, &shim_dir), (Some(f), Some(sd)) if f == sd);

        ShimStatus {
            installed,
            dir_on_path,
            first_on_path,
            resolves_to_current,
            link_target,
            real_op,
        }
    }

    /// True when the shim is installed, wins on `PATH`, and points at this
    /// binary. Anything else is drift.
    pub fn healthy(&self) -> bool {
        self.installed && self.first_on_path && self.resolves_to_current
    }

    /// A one-line description of the first drift found, with the fix, or `None`
    /// when healthy.
    pub fn issue(&self) -> Option<String> {
        if !self.installed {
            return Some("shim not installed (run: sigil setup, or sigil shim install)".into());
        }
        if !self.first_on_path {
            if !self.dir_on_path {
                return Some(
                    "~/.sigil/bin is not on PATH (add it to your shell profile so the shim wins)"
                        .into(),
                );
            }
            return Some("a real op precedes the shim on PATH".into());
        }
        if !self.resolves_to_current {
            return Some(match &self.link_target {
                Some(t) => format!(
                    "shim points at a stale binary ({}); re-run: sigil shim install",
                    t.display()
                ),
                None => "shim link is broken; re-run: sigil shim install".into(),
            });
        }
        None
    }
}

/// Where on `PATH` the shim and the real `op` first appear, as indices.
pub struct PathOrder {
    pub shim: Option<usize>,
    pub real_op: Option<usize>,
}

/// Walk `PATH` once, recording the first index that resolves to our shim and
/// the first that resolves to a real `op`.
pub fn path_order() -> PathOrder {
    let own = own_binary();
    let mut order = PathOrder {
        shim: None,
        real_op: None,
    };
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return order,
    };
    for (i, dir) in std::env::split_paths(&path).enumerate() {
        let cand = dir.join("op");
        if !is_executable(&cand) {
            continue;
        }
        let is_shim = matches!(
            (&own, cand.canonicalize().ok()),
            (Some(own), Some(canon)) if &canon == own
        );
        if is_shim {
            order.shim.get_or_insert(i);
        } else {
            order.real_op.get_or_insert(i);
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-shim-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write an executable stub `op` into `dir` and return the dir.
    fn op_in(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join("op");
        std::fs::write(&p, "#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir.to_path_buf()
    }

    fn path_of(dirs: &[&Path]) -> OsString {
        std::env::join_paths(dirs.iter().map(|d| d.to_path_buf())).unwrap()
    }

    /// Write an executable stub named `name` into `dir`.
    fn exe_in(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn find_real_skips_a_non_symlink_planted_in_the_proxy_dir() {
        // sec-review-1 Finding A: a NON-symlink executable resident in the proxy
        // dir under a tool's name must NOT be resolved as the real tool (the
        // daemon-up path would otherwise spawn it WITH the injected credential).
        // Rule 1 (canonicalisation) cannot see it; rule 2 (inside the proxy dir)
        // must.
        let root = tmp("findreal-planted");
        let proxy_dir = root.join("bin");
        exe_in(&proxy_dir, "op"); // a plain script, not a symlink to sigil
        let real_dir = root.join("real");
        let real = exe_in(&real_dir, "op");

        // Proxy dir FIRST on PATH: rule 2 must skip it and fall through to real.
        let path = path_of(&[&proxy_dir, &real_dir]);
        let got = find_real_in(
            "op",
            Some(path.as_os_str()),
            None,
            None,
            proxy_dir.canonicalize().ok(),
        );
        assert_eq!(
            got.and_then(|p| p.canonicalize().ok()),
            real.canonicalize().ok(),
            "the real op must win over a non-symlink planted in the proxy dir"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_real_excludes_via_own_and_alias_target() {
        // Rule 1: a symlink alias OUTSIDE the proxy dir resolves to a Sigil
        // binary. From sigil-config, `own` is the manager but the alias points at
        // the sibling runtime (alias_target); excluding both is what keeps
        // resolution and diagnostics correct (Finding B).
        let root = tmp("findreal-alias");
        let runtime = exe_in(&root, "sigil"); // stand-in runtime binary
        let runtime = runtime.canonicalize().unwrap();
        let manager = exe_in(&root, "sigil-config").canonicalize().unwrap();

        // A stray alias symlink to the runtime, in a dir on PATH (not the proxy
        // dir), plus the real op after it.
        let stray = root.join("stray");
        std::fs::create_dir_all(&stray).unwrap();
        std::os::unix::fs::symlink(&runtime, stray.join("op")).unwrap();
        let real = exe_in(&root.join("real"), "op");

        let path = path_of(&[&stray, &root.join("real")]);
        // Called "from sigil-config": own = manager, alias_target = runtime.
        let got = find_real_in(
            "op",
            Some(path.as_os_str()),
            Some(manager),
            Some(runtime),
            None,
        );
        assert_eq!(
            got.and_then(|p| p.canonicalize().ok()),
            real.canonicalize().ok(),
            "a stray alias to the runtime must be excluded even when own != runtime"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn healthy_when_shim_is_installed_first_and_points_at_current() {
        let root = tmp("healthy");
        let shim_dir = root.join("shimbin");
        let real_dir = op_in(&root.join("realbin"));
        std::fs::create_dir_all(&shim_dir).unwrap();

        // A stand-in "current binary" and the shim symlink pointing at it.
        let current = root.join("sigil-bin");
        std::fs::write(&current, "#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755)).unwrap();
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("op")).unwrap();

        // Shim dir first, real op dir second.
        let path = path_of(&[&shim_dir, &real_dir]);
        let s = ShimStatus::detect_with(Some(own), Some(shim_dir), Some(&path));
        assert!(s.installed);
        assert!(s.first_on_path);
        assert!(s.resolves_to_current);
        assert!(s.healthy(), "issue: {:?}", s.issue());
        assert!(s.issue().is_none());
        assert!(
            s.real_op.is_some(),
            "the real op behind the shim is still found"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn drift_when_a_real_op_precedes_the_shim() {
        let root = tmp("precede");
        let shim_dir = root.join("shimbin");
        let real_dir = op_in(&root.join("realbin"));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let current = root.join("sigil-bin");
        std::fs::write(&current, "x").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755)).unwrap();
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("op")).unwrap();

        // Real op dir FIRST: the shim no longer wins.
        let path = path_of(&[&real_dir, &shim_dir]);
        let s = ShimStatus::detect_with(Some(own), Some(shim_dir), Some(&path));
        assert!(s.installed);
        assert!(!s.first_on_path);
        assert!(!s.healthy());
        assert_eq!(
            s.issue().as_deref(),
            Some("a real op precedes the shim on PATH")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn drift_when_the_link_points_at_a_stale_binary() {
        let root = tmp("stale");
        let shim_dir = root.join("shimbin");
        std::fs::create_dir_all(&shim_dir).unwrap();

        // The shim points at an OLD binary; the daemon now runs a different one.
        let old = root.join("sigil-old");
        std::fs::write(&old, "old").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(old.canonicalize().unwrap(), shim_dir.join("op")).unwrap();
        let current = root.join("sigil-new");
        std::fs::write(&current, "new").unwrap();
        let own = current.canonicalize().unwrap();

        let path = path_of(&[&shim_dir]);
        let s = ShimStatus::detect_with(Some(own), Some(shim_dir), Some(&path));
        assert!(s.installed);
        assert!(s.first_on_path, "shim is still first on PATH");
        assert!(!s.resolves_to_current, "but it points at a stale binary");
        assert!(!s.healthy());
        assert!(s.issue().unwrap().contains("stale binary"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn not_installed_when_the_link_is_absent() {
        let root = tmp("absent");
        let shim_dir = root.join("shimbin");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let path = path_of(&[&shim_dir]);
        let s = ShimStatus::detect_with(Some(root.join("sigil")), Some(shim_dir), Some(&path));
        assert!(!s.installed);
        assert!(!s.healthy());
        assert!(s.issue().unwrap().contains("not installed"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dir_off_path_is_reported_distinctly() {
        let root = tmp("offpath");
        let shim_dir = root.join("shimbin");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let current = root.join("sigil-bin");
        std::fs::write(&current, "x").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755)).unwrap();
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("op")).unwrap();

        // Installed, points at current, but the shim dir is NOT on PATH.
        let other = op_in(&root.join("otherbin"));
        let path = path_of(&[&other]);
        let s = ShimStatus::detect_with(Some(own), Some(shim_dir), Some(&path));
        assert!(s.installed);
        assert!(!s.dir_on_path);
        assert!(!s.first_on_path);
        assert!(s.issue().unwrap().contains("not on PATH"));
        std::fs::remove_dir_all(&root).ok();
    }
}
