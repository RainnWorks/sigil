//! The auto-aliasing proxy: the Sigil-managed shim directory, PATH durability,
//! per-command drift detection, and the recursion fuse.
//!
//! A caller that cannot be modified (an AI agent, a launcher shelling out to a
//! bare `op`, `git` reaching the SSH agent) hits Sigil transparently: the proxy
//! directory `~/.sigil/bin` sits first on `PATH` and holds one symlink alias per
//! intercepted command, each pointing at the multicall binary. Running `op`
//! resolves the alias, which re-enters as `sigil op ...` (see `main.rs` /
//! `shim::dispatch`), gates on the phone, and execs the *real* `op`. The caller
//! sees `op` behaving normally and never learns Sigil is there.
//!
//! This module is the management + diagnosis layer behind `sigil proxy
//! add|remove|list|status|doctor|env`. The individual alias install/removal
//! reuses [`crate::setup::install_shim_for`] and [`crate::paths`]; what lives
//! here is the generality the `op`-specific helpers lack: per-command drift
//! detection ([`ProxyStatus`]), multi-shell PATH durability, the printable env
//! line for agent launchers, and the [`DEPTH_ENV`] recursion fuse.
//!
//! See `docs/design/proxy-aliasing.md`.

use std::path::{Path, PathBuf};

use crate::paths;

/// The inherited depth counter that fuses a resolution-bug fork-bomb into a
/// bounded, fail-closed error. Read at alias dispatch entry; set to `n+1` on the
/// process Sigil execs next. See `docs/design/proxy-aliasing.md` problem 1(b).
///
/// This is a liveness fuse, never the recursion *mechanism*: correctness rests
/// on [`paths::find_real`] excluding our own aliases. The fuse only guarantees a
/// bug there loops finitely rather than forever.
pub const DEPTH_ENV: &str = "SIGIL_PROXY_DEPTH";

/// The depth past which Sigil aborts a proxy dispatch. Legitimate nesting (a
/// gated tool invoking another gated tool) is realistically < 5 deep; a
/// resolution bug reaches this in milliseconds.
pub const MAX_DEPTH: u32 = 40;

/// The current proxy dispatch depth from the inherited environment (0 when
/// unset or unparseable).
pub fn current_depth() -> u32 {
    std::env::var(DEPTH_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Whether the depth fuse has blown: this dispatch is at or past [`MAX_DEPTH`],
/// so Sigil must fail closed rather than exec another layer.
pub fn depth_exceeded() -> bool {
    current_depth() >= MAX_DEPTH
}

/// The value to set [`DEPTH_ENV`] to on the process Sigil execs next: the current
/// depth plus one, saturating so it can never wrap.
pub fn next_depth_value() -> String {
    current_depth().saturating_add(1).to_string()
}

/// The path a proxy alias should point at: the `sigil` **runtime** binary that
/// serves the gating hot path. Every alias is a symlink to it, so canonical
/// equality against this both excludes aliases from real-binary resolution and
/// tells drift detection that an alias is current.
///
/// The runtime binary is named `sigil` and installed as a sibling of
/// `sigil-config` in the same directory (post-split convention). So we resolve
/// the sibling `sigil` next to the running binary: in the manager
/// (`sigil-config`) that is the runtime; in the runtime itself it is the running
/// binary. An alias installed by `sigil-config` must exec the runtime, never the
/// manager, which is why this is not simply `current_exe`. Centralised so the
/// convention lives in one function.
///
/// `None` when the sibling `sigil` cannot be resolved (e.g. an unusual layout);
/// callers fail closed with a clear error rather than pointing an alias at the
/// wrong binary.
pub fn alias_target() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let sibling = exe.parent()?.join("sigil");
    sibling.canonicalize().ok()
}

/// True if `p` is a regular file with any execute bit set.
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

/// Per-command health of the proxy install, generalising the `op`-specific
/// `paths::ShimStatus` to any intercepted command for `sigil proxy doctor`.
///
/// The security-relevant drift is `first_on_path == false`: a real `<cmd>`
/// preceding the alias routes an intercepted command **ungated**.
#[derive(Debug, Clone)]
pub struct ProxyStatus {
    /// The command this status is about.
    pub cmd: String,
    /// `~/.sigil/bin/<cmd>` exists as a symlink.
    pub installed: bool,
    /// The proxy dir is present somewhere on `PATH`.
    pub dir_on_path: bool,
    /// The first `<cmd>` a `PATH` walk resolves is the alias (the alias wins).
    pub first_on_path: bool,
    /// The alias resolves to the currently running binary (not a stale build).
    pub resolves_to_current: bool,
    /// What the alias canonicalises to, if it resolves.
    pub link_target: Option<PathBuf>,
    /// The first real `<cmd>` on `PATH` that is not the alias, if any.
    pub real: Option<PathBuf>,
}

impl ProxyStatus {
    /// Detect the proxy health for `cmd` from the current process, `PATH`, and
    /// filesystem.
    pub fn detect(cmd: &str) -> Self {
        Self::detect_with(
            cmd,
            alias_target(),
            paths::shim_bin_dir(),
            std::env::var_os("PATH").as_deref(),
        )
    }

    /// The pure core of [`detect`](Self::detect): everything reads from the
    /// explicit inputs plus the filesystem, so tests drive it with synthetic
    /// dirs and no process-global env mutation.
    pub fn detect_with(
        cmd: &str,
        own: Option<PathBuf>,
        shim_dir: Option<PathBuf>,
        path: Option<&std::ffi::OsStr>,
    ) -> Self {
        let link = shim_dir.as_ref().map(|d| d.join(cmd));
        let installed = link
            .as_ref()
            .map(|l| l.symlink_metadata().is_ok())
            .unwrap_or(false);
        let link_target = link.as_ref().and_then(|l| l.canonicalize().ok());
        let resolves_to_current = matches!((&link_target, &own), (Some(t), Some(o)) if t == o);

        let mut first_dir: Option<PathBuf> = None;
        let mut real: Option<PathBuf> = None;
        let mut dir_on_path = false;
        if let Some(path) = path {
            for dir in std::env::split_paths(path) {
                let is_shim_dir = shim_dir.as_ref() == Some(&dir);
                if is_shim_dir {
                    dir_on_path = true;
                }
                let cand = dir.join(cmd);
                if !is_executable(&cand) {
                    continue;
                }
                if first_dir.is_none() {
                    first_dir = Some(dir.clone());
                }
                // "Real" excludes both the proxy dir and anything that
                // canonicalises to our own binary (a copy planted elsewhere).
                let is_own = matches!(
                    (&own, cand.canonicalize().ok()),
                    (Some(o), Some(c)) if &c == o
                );
                if !is_shim_dir && !is_own && real.is_none() {
                    real = Some(cand);
                }
            }
        }
        let first_on_path = matches!((&first_dir, &shim_dir), (Some(f), Some(sd)) if f == sd);

        ProxyStatus {
            cmd: cmd.to_string(),
            installed,
            dir_on_path,
            first_on_path,
            resolves_to_current,
            link_target,
            real,
        }
    }

    /// True when the alias is installed, wins on `PATH`, and points at this
    /// binary. Anything else is drift.
    pub fn healthy(&self) -> bool {
        self.installed && self.first_on_path && self.resolves_to_current
    }

    /// A one-line description of the first drift found, with the fix, or `None`
    /// when healthy. Ordered by severity: a bypass (real precedes alias) outranks
    /// a stale link.
    pub fn issue(&self) -> Option<String> {
        let cmd = &self.cmd;
        if !self.installed {
            return Some(format!(
                "no proxy alias for {cmd} (run: sigil-config proxy add {cmd})"
            ));
        }
        if !self.first_on_path {
            if !self.dir_on_path {
                return Some(
                    "~/.sigil/bin is not on PATH (run: sigil-config proxy env, then re-source)"
                        .into(),
                );
            }
            return Some(format!(
                "a real {cmd} precedes the proxy on PATH (requests would be ungated)"
            ));
        }
        if !self.resolves_to_current {
            return Some(match &self.link_target {
                Some(t) => format!(
                    "the {cmd} alias points at a stale binary ({}); re-run: sigil-config proxy add {cmd}",
                    t.display()
                ),
                None => format!("the {cmd} alias is broken; re-run: sigil-config proxy add {cmd}"),
            });
        }
        None
    }
}

/// One installed proxy alias: the command, the real binary it currently resolves
/// to (proxy dir excluded), its health, and whether a rule actually gates it.
#[derive(Debug, Clone)]
pub struct Alias {
    pub cmd: String,
    pub real: Option<PathBuf>,
    pub status: ProxyStatus,
    /// A gating rule is keyed to this command. `false` is a live footgun: the
    /// alias intercepts `<cmd>` but every call is refused (fail-closed, correct)
    /// so the real tool is unreachable through the shell. `proxy list`/`doctor`
    /// surface it as "NO RULE".
    pub gated: bool,
}

/// Every installed proxy alias: the entries of `~/.sigil/bin` that are symlinks
/// to this binary. Sorted by command for stable output. `Ok(vec![])` when the
/// proxy dir does not exist yet.
pub fn list_aliases() -> std::io::Result<Vec<Alias>> {
    let Some(dir) = paths::shim_bin_dir() else {
        return Ok(Vec::new());
    };
    let own = alias_target();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    // One config load answers gating coverage for every alias. Best-effort: a
    // missing/broken config means "no rules", so every alias reads as NO RULE
    // rather than the listing failing.
    let config = crate::config::Config::load().unwrap_or_default();
    let mut aliases = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Only symlinks that resolve to our own binary are Sigil aliases.
        if path
            .symlink_metadata()
            .map(|m| !m.file_type().is_symlink())
            .unwrap_or(true)
        {
            continue;
        }
        let is_ours = matches!(
            (&own, path.canonicalize().ok()),
            (Some(o), Some(c)) if &c == o
        );
        if !is_ours {
            continue;
        }
        let Some(cmd) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        aliases.push(Alias {
            real: paths::find_real(&cmd),
            status: ProxyStatus::detect(&cmd),
            gated: config.gates_command(&cmd),
            cmd,
        });
    }
    aliases.sort_by(|a, b| a.cmd.cmp(&b.cmd));
    Ok(aliases)
}

/// A shell whose PATH-prepend syntax Sigil knows how to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// zsh, bash, and POSIX `sh` all share `export PATH=...`.
    Posix,
    Fish,
    Nushell,
}

impl Shell {
    /// Best-effort detection from `$SHELL`, defaulting to POSIX (the macOS zsh
    /// default) for anything unrecognised.
    pub fn detect() -> Self {
        Self::from_shell_path(std::env::var("SHELL").unwrap_or_default().as_str())
    }

    /// Classify a `$SHELL`-style path (`/opt/homebrew/bin/fish` -> `Fish`).
    pub fn from_shell_path(shell: &str) -> Self {
        if shell.ends_with("fish") {
            Shell::Fish
        } else if shell.ends_with("nu") {
            Shell::Nushell
        } else {
            Shell::Posix
        }
    }

    /// Parse an explicit `--shell` flag value. `None` on an unknown name so the
    /// caller can reject it rather than silently defaulting.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "zsh" | "bash" | "sh" | "posix" => Some(Shell::Posix),
            "fish" => Some(Shell::Fish),
            "nu" | "nushell" => Some(Shell::Nushell),
            _ => None,
        }
    }
}

/// The single line that prepends the proxy dir to `PATH` for `shell`, for the
/// current session or an agent launcher's environment. Uses `$HOME` (not an
/// absolute path) so it stays portable across machines and users.
pub fn env_line(shell: Shell) -> String {
    match shell {
        Shell::Posix => "export PATH=\"$HOME/.sigil/bin:$PATH\"".to_string(),
        Shell::Fish => "fish_add_path --prepend $HOME/.sigil/bin".to_string(),
        Shell::Nushell => {
            "$env.PATH = ($env.PATH | prepend $\"($env.HOME)/.sigil/bin\")".to_string()
        }
    }
}

/// The current shell's primary startup file plus the [`Shell`] whose prepend
/// syntax it uses, chosen from `$SHELL`. `sigil-config proxy add` edits this one
/// file (conservative, like `sigil setup`) and points at the env line + the
/// agent-env story for anything else. `None` only if `$HOME` is unset.
pub fn primary_rc_file() -> Option<(PathBuf, Shell)> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let (rel, kind) = if shell.ends_with("fish") {
        (".config/fish/config.fish", Shell::Fish)
    } else if shell.ends_with("nu") {
        (".config/nushell/config.nu", Shell::Nushell)
    } else if shell.ends_with("bash") {
        // .bashrc is the file interactive bash reads; most .bash_profile source
        // it, so it is the single best target.
        (".bashrc", Shell::Posix)
    } else {
        // zsh (the macOS default) and anything else: ~/.zshrc.
        (".zshrc", Shell::Posix)
    };
    Some((home.join(rel), kind))
}

/// The startup files a given shell reads, under `home`, that should carry the
/// PATH prepend. bash gets both `.bashrc` (interactive non-login) and
/// `.bash_profile` (login), which is why interactive-only edits miss agents.
pub fn rc_files_for(shell: Shell, home: &Path) -> Vec<PathBuf> {
    match shell {
        Shell::Posix => {
            // We cannot tell zsh from bash from `$SHELL` alone here, so edit the
            // union that a POSIX login/interactive shell might read. Each edit is
            // idempotent and guarded, so touching a file an unused shell reads is
            // harmless.
            vec![
                home.join(".zshrc"),
                home.join(".bashrc"),
                home.join(".bash_profile"),
                home.join(".profile"),
            ]
        }
        Shell::Fish => vec![home.join(".config/fish/config.fish")],
        Shell::Nushell => vec![home.join(".config/nushell/config.nu")],
    }
}

/// The marker that brackets Sigil's managed block, so edits target exactly our
/// own lines and never duplicate them. Kept byte-compatible with the legacy
/// `setup.rs` block via the `.sigil/bin` idempotency check below.
const BLOCK_START: &str = "# >>> sigil proxy (managed) >>>";
const BLOCK_END: &str = "# <<< sigil proxy (managed) <<<";

/// True if `contents` already puts the proxy dir on `PATH`: our managed block,
/// the legacy `setup.rs` block, or a hand-written line. Prevents a duplicate
/// append. Matching the bare `.sigil/bin` substring keeps us from fighting the
/// older `# >>> sigil shim (managed) >>>` block.
fn block_present(contents: &str) -> bool {
    contents.contains(BLOCK_START) || contents.contains(".sigil/bin")
}

/// The managed block for `shell`.
fn managed_block(shell: Shell) -> String {
    format!("{BLOCK_START}\n{}\n{BLOCK_END}\n", env_line(shell))
}

/// Ensure the proxy dir is on `PATH` in `file` for `shell`. `Ok(true)` if the
/// file was modified, `Ok(false)` if it already had it. Idempotent: a second
/// call is a no-op, and a file another shell already covers is left alone. The
/// file (and any missing parent, e.g. `~/.config/fish`) is created if absent.
pub fn ensure_path_in(file: &Path, shell: Shell) -> std::io::Result<bool> {
    let existing = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if block_present(&existing) {
        return Ok(false);
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&managed_block(shell));
    std::fs::write(file, updated)?;
    Ok(true)
}

/// Strip our own managed block from `contents`, returning the new text if it
/// changed. Only our `BLOCK_START..BLOCK_END` block is removed; a hand-written
/// `.sigil/bin` line or the legacy `# >>> sigil shim (managed) >>>` block is
/// left alone, because we cannot know the user did not add those deliberately.
fn strip_block(contents: &str) -> Option<String> {
    let start = contents.find(BLOCK_START)?;
    // Include the trailing newline after BLOCK_END so we do not leave a blank
    // line behind; fall back to end-of-block if the marker ends the file.
    let after_marker = start + contents[start..].find(BLOCK_END)? + BLOCK_END.len();
    let end = contents[after_marker..]
        .find('\n')
        .map(|i| after_marker + i + 1)
        .unwrap_or(contents.len());
    let mut out = String::with_capacity(contents.len());
    out.push_str(&contents[..start]);
    out.push_str(&contents[end..]);
    Some(out)
}

/// Remove our managed PATH block from `file`. `Ok(true)` if the file changed,
/// `Ok(false)` if it had no managed block (or does not exist). Used by
/// `proxy remove --purge` once no aliases remain.
pub fn strip_path_in(file: &Path) -> std::io::Result<bool> {
    let existing = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match strip_block(&existing) {
        Some(updated) => {
            std::fs::write(file, updated)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Install a proxy alias for `cmd`: symlink `dir/<cmd>` at `target`, replacing
/// any stale link, creating `dir` if needed. Returns the link path. The pure
/// core of [`install_alias`], driven with explicit dir/target by tests.
fn install_alias_in(dir: &Path, target: &Path, cmd: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let link = dir.join(cmd);
    // Replace any existing entry (a stale link, or an old install pointing at a
    // prior binary). We only ever overwrite our own alias slot, never a real
    // binary: the proxy dir holds nothing but aliases.
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link)?;
    }
    std::os::unix::fs::symlink(target, &link)?;
    Ok(link)
}

/// Install a transparent proxy alias for `cmd` in `~/.sigil/bin`, pointing at the
/// [`alias_target`] (the `sigil` runtime binary). Returns `(link, target)`. This
/// is what `sigil-config proxy add` calls; the caller is responsible for the
/// PATH edit ([`ensure_path_in`]) and the gating-rule coverage warning.
pub fn install_alias(cmd: &str) -> std::io::Result<(PathBuf, PathBuf)> {
    let dir = paths::shim_bin_dir()
        .ok_or_else(|| std::io::Error::other("HOME is not set; cannot locate ~/.sigil/bin"))?;
    let target = alias_target()
        .ok_or_else(|| std::io::Error::other("cannot resolve the sigil runtime binary path"))?;
    let link = install_alias_in(&dir, &target, cmd)?;
    Ok((link, target))
}

/// The pure core of [`remove_alias`]: remove `dir/<cmd>` only if it is one of our
/// aliases (a symlink resolving to `target`). Returns whether it was removed.
/// Refuses to delete anything that is not our alias, so a real binary someone
/// placed in the proxy dir is never destroyed.
fn remove_alias_in(dir: &Path, target: Option<&Path>, cmd: &str) -> std::io::Result<bool> {
    let link = dir.join(cmd);
    let Ok(meta) = link.symlink_metadata() else {
        return Ok(false); // nothing there
    };
    if !meta.file_type().is_symlink() {
        return Ok(false); // not our alias; leave it
    }
    let is_ours = matches!(
        (target, link.canonicalize().ok()),
        (Some(t), Some(c)) if c == t
    );
    // A broken symlink (canonicalize fails) that still lives in the proxy dir is
    // ours by location: the proxy dir holds only aliases. Remove it too.
    let broken_in_proxy_dir = link.canonicalize().is_err();
    if is_ours || broken_in_proxy_dir {
        std::fs::remove_file(&link)?;
        return Ok(true);
    }
    Ok(false)
}

/// Remove the proxy alias for `cmd` from `~/.sigil/bin`, if present and ours.
/// Returns whether one was removed. Never touches the real binary.
pub fn remove_alias(cmd: &str) -> std::io::Result<bool> {
    let Some(dir) = paths::shim_bin_dir() else {
        return Ok(false);
    };
    remove_alias_in(&dir, alias_target().as_deref(), cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-proxy-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write an executable stub named `name` into `dir`.
    fn exe_in(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn path_of(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs.iter().map(|d| d.to_path_buf())).unwrap()
    }

    #[test]
    fn healthy_when_alias_is_first_and_points_at_current() {
        let root = tmp("healthy");
        let shim_dir = root.join("shimbin");
        let real_dir = root.join("realbin");
        exe_in(&real_dir, "gcloud");
        std::fs::create_dir_all(&shim_dir).unwrap();

        let current = exe_in(&root, "sigil-bin");
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("gcloud")).unwrap();

        let path = path_of(&[&shim_dir, &real_dir]);
        let s = ProxyStatus::detect_with("gcloud", Some(own), Some(shim_dir), Some(&path));
        assert!(s.healthy(), "issue: {:?}", s.issue());
        assert!(
            s.real.is_some(),
            "the real gcloud behind the alias is found"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn drift_when_a_real_binary_precedes_the_alias_is_a_bypass() {
        let root = tmp("precede");
        let shim_dir = root.join("shimbin");
        let real_dir = root.join("realbin");
        exe_in(&real_dir, "op");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let current = exe_in(&root, "sigil-bin");
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("op")).unwrap();

        // Real op dir FIRST: the alias no longer wins.
        let path = path_of(&[&real_dir, &shim_dir]);
        let s = ProxyStatus::detect_with("op", Some(own), Some(shim_dir), Some(&path));
        assert!(!s.healthy());
        assert!(s.issue().unwrap().contains("precedes the proxy"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_stray_alias_symlink_outside_the_proxy_dir_is_not_the_real_tool() {
        // Our aliases are symlinks to the binary. One appearing on PATH *outside*
        // the proxy dir (a leftover, a second install) would be a recursion trap
        // if resolved as the real op. Canonical-path equality to our own binary
        // excludes it wherever it lives. (A hard *copy* of the binary is not
        // caught here by design; the depth fuse backstops that exotic case.)
        let root = tmp("stray");
        let shim_dir = root.join("shimbin");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let current = exe_in(&root, "sigil-bin");
        let own = current.canonicalize().unwrap();
        std::os::unix::fs::symlink(&own, shim_dir.join("op")).unwrap();

        // A stray alias symlink to the same binary, in another dir on PATH.
        let stray_dir = root.join("stray");
        std::fs::create_dir_all(&stray_dir).unwrap();
        std::os::unix::fs::symlink(&own, stray_dir.join("op")).unwrap();

        let path = path_of(&[&shim_dir, &stray_dir]);
        let s = ProxyStatus::detect_with("op", Some(own), Some(shim_dir), Some(&path));
        assert!(
            s.real.is_none(),
            "a symlink to our own binary must not be treated as the real tool"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn depth_fuse_reads_and_increments() {
        // Mutating a process-global env var: serialize against other env tests.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // No env set: depth 0, not exceeded, next is 1.
        std::env::remove_var(DEPTH_ENV);
        assert_eq!(current_depth(), 0);
        assert!(!depth_exceeded());
        assert_eq!(next_depth_value(), "1");

        std::env::set_var(DEPTH_ENV, MAX_DEPTH.to_string());
        assert!(depth_exceeded(), "at the bound the fuse has blown");
        std::env::set_var(DEPTH_ENV, "garbage");
        assert_eq!(current_depth(), 0, "an unparseable counter reads as 0");
        std::env::remove_var(DEPTH_ENV);
    }

    #[test]
    fn env_line_per_shell() {
        assert!(env_line(Shell::Posix).contains("export PATH=\"$HOME/.sigil/bin:$PATH\""));
        assert!(env_line(Shell::Fish).contains("fish_add_path --prepend $HOME/.sigil/bin"));
        assert!(env_line(Shell::Nushell).contains("prepend"));
    }

    #[test]
    fn shell_detection_and_parse() {
        assert_eq!(Shell::from_shell_path("/bin/zsh"), Shell::Posix);
        assert_eq!(
            Shell::from_shell_path("/opt/homebrew/bin/fish"),
            Shell::Fish
        );
        assert_eq!(Shell::parse("BASH"), Some(Shell::Posix));
        assert_eq!(Shell::parse("fish"), Some(Shell::Fish));
        assert_eq!(Shell::parse("tcsh"), None);
    }

    #[test]
    fn path_edit_is_idempotent_and_creates_missing_parents() {
        let dir = tmp("rc");
        // A fish config under a not-yet-existing ~/.config/fish.
        let cfg = dir.join(".config/fish/config.fish");
        assert!(ensure_path_in(&cfg, Shell::Fish).unwrap());
        assert!(cfg.exists());
        let body = std::fs::read_to_string(&cfg).unwrap();
        assert!(body.contains("fish_add_path --prepend $HOME/.sigil/bin"));
        // Second run is a no-op.
        assert!(!ensure_path_in(&cfg, Shell::Fish).unwrap());
        assert_eq!(
            std::fs::read_to_string(&cfg)
                .unwrap()
                .matches(".sigil/bin")
                .count(),
            1
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_edit_defers_to_a_legacy_shim_block() {
        // The older setup.rs block uses the same `.sigil/bin` line; we must not
        // append a second block over it.
        let dir = tmp("legacy");
        let rc = dir.join(".zshrc");
        std::fs::write(
            &rc,
            "# >>> sigil shim (managed) >>>\nexport PATH=\"$HOME/.sigil/bin:$PATH\"\n# <<< sigil shim (managed) <<<\n",
        )
        .unwrap();
        assert!(!ensure_path_in(&rc, Shell::Posix).unwrap());
        assert!(!std::fs::read_to_string(&rc).unwrap().contains(BLOCK_START));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rc_files_cover_bash_login_and_interactive() {
        let home = Path::new("/home/tom");
        let posix = rc_files_for(Shell::Posix, home);
        assert!(posix.contains(&home.join(".bashrc")));
        assert!(posix.contains(&home.join(".bash_profile")));
        assert!(posix.contains(&home.join(".zshrc")));
    }

    #[test]
    fn strip_removes_only_our_block_and_leaves_the_rest() {
        let rc = format!(
            "export EDITOR=vim\n{BLOCK_START}\n{}\n{BLOCK_END}\nalias ll='ls -l'\n",
            env_line(Shell::Posix)
        );
        let stripped = strip_block(&rc).expect("our block is present");
        assert!(stripped.contains("export EDITOR=vim"));
        assert!(stripped.contains("alias ll='ls -l'"));
        assert!(!stripped.contains(".sigil/bin"), "our line is gone");
        assert!(!stripped.contains(BLOCK_START));
        // A file without our block is unchanged (None).
        assert!(strip_block("export EDITOR=vim\n").is_none());
        // The legacy shim block is NOT ours to strip.
        let legacy = "# >>> sigil shim (managed) >>>\nexport PATH=\"$HOME/.sigil/bin:$PATH\"\n# <<< sigil shim (managed) <<<\n";
        assert!(strip_block(legacy).is_none());
    }

    #[test]
    fn install_then_remove_alias_round_trips_and_spares_real_binaries() {
        let root = tmp("install");
        let proxy_dir = root.join("bin");
        let target = exe_in(&root, "sigil-bin");
        let target = target.canonicalize().unwrap();

        // Install: the alias is a symlink to the target.
        let link = install_alias_in(&proxy_dir, &target, "op").unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(link.canonicalize().unwrap(), target);

        // Re-install replaces cleanly (no error, still one link).
        let link2 = install_alias_in(&proxy_dir, &target, "op").unwrap();
        assert_eq!(link, link2);

        // A real binary that someone dropped in the dir must NOT be removed.
        let real = exe_in(&proxy_dir, "gcloud");
        assert!(
            !remove_alias_in(&proxy_dir, Some(&target), "gcloud").unwrap(),
            "a non-symlink real binary is spared"
        );
        assert!(real.exists(), "the real binary is untouched");

        // Removing our alias works and is idempotent.
        assert!(remove_alias_in(&proxy_dir, Some(&target), "op").unwrap());
        assert!(link.symlink_metadata().is_err());
        assert!(!remove_alias_in(&proxy_dir, Some(&target), "op").unwrap());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn remove_reclaims_a_broken_alias_in_the_proxy_dir() {
        // An alias left dangling (its target rebuilt/moved away) still lives in
        // the proxy dir and must be removable by `proxy remove`.
        let root = tmp("broken");
        let proxy_dir = root.join("bin");
        std::fs::create_dir_all(&proxy_dir).unwrap();
        std::os::unix::fs::symlink(root.join("gone-sigil"), proxy_dir.join("op")).unwrap();
        assert!(proxy_dir.join("op").canonicalize().is_err(), "dangling");
        assert!(
            remove_alias_in(&proxy_dir, Some(&root.join("some-target")), "op").unwrap(),
            "a broken alias in the proxy dir is reclaimed"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
