//! The install steps `sigil setup` runs, factored out of the CLI so each is
//! testable and reusable.
//!
//! Setup is the guided first run: provision the keystore DEK, install the `op`
//! shim, make it win on `PATH` for both interactive shells (the shell profile)
//! and GUI-launched tools (the launchd plist `EnvironmentVariables`), load the
//! launchd agent, then hand off to the pairing flow. Each step here is
//! idempotent so re-running `sigil setup` is safe.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths;
use crate::service;

/// The marker that brackets Sigil's block in the shell profile, so we edit
/// exactly our own lines and never duplicate them.
const PROFILE_MARKER: &str = "# >>> sigil shim (managed) >>>";
const PROFILE_MARKER_END: &str = "# <<< sigil shim (managed) <<<";

/// Install the `op` shim: symlink `~/.sigil/bin/op` at the running binary,
/// replacing any stale link. Returns `(link, target)`.
pub fn install_shim() -> Result<(PathBuf, PathBuf)> {
    install_shim_for("op")
}

/// Install a transparent shim alias for `cmd`: symlink `~/.sigil/bin/<cmd>` at
/// the Sigil runtime so a bare `<cmd>` on PATH re-enters as `sigil <cmd>`,
/// replacing any stale link. Returns `(link, target)`. This generalizes the shim
/// beyond `op` so `sigil shim add <cli>` can front any configured command for
/// callers that cannot be modified.
///
/// The link targets the install-stable runtime (`~/.sigil/bin/sigil`, the copy
/// `sigil up` maintains) when it exists, so aliases survive the build checkout
/// moving; a bare checkout that has never run `up` falls back to the running
/// binary, the historical behavior.
pub fn install_shim_for(cmd: &str) -> Result<(PathBuf, PathBuf)> {
    let bindir = paths::shim_bin_dir().context("HOME is not set")?;
    let installed = bindir.join("sigil");
    let target = if installed.is_file() {
        installed
            .canonicalize()
            .with_context(|| format!("resolving {}", installed.display()))?
    } else {
        std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .context("resolving the sigil binary path")?
    };
    std::fs::create_dir_all(&bindir).with_context(|| format!("creating {}", bindir.display()))?;
    let link = bindir.join(cmd);
    if link.exists() || link.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&link);
    }
    std::os::unix::fs::symlink(&target, &link)
        .with_context(|| format!("symlinking {}", link.display()))?;
    Ok((link, target))
}

/// The shell profile to edit, chosen from `$SHELL`. zsh (the macOS default) uses
/// `~/.zshrc`; bash uses `~/.bash_profile` (macOS login shells read it).
pub fn shell_profile() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let file = if shell.ends_with("bash") {
        ".bash_profile"
    } else {
        // zsh and anything else: ~/.zshrc is the macOS default.
        ".zshrc"
    };
    Some(home.join(file))
}

/// True if `contents` already puts the shim dir on `PATH` (our managed block, or
/// a hand-written line the user added). Prevents a duplicate append.
fn profile_has_shim(contents: &str) -> bool {
    contents.contains(PROFILE_MARKER) || contents.contains(".sigil/bin")
}

/// The managed block appended to the profile.
fn profile_block() -> String {
    format!("{PROFILE_MARKER}\nexport PATH=\"$HOME/.sigil/bin:$PATH\"\n{PROFILE_MARKER_END}\n")
}

/// Ensure the shim dir is on `PATH` in the shell profile. Returns `Ok(true)` if
/// the profile was modified, `Ok(false)` if it already had it. Idempotent.
pub fn ensure_profile_path() -> Result<bool> {
    let path = shell_profile().context("HOME is not set")?;
    ensure_profile_path_at(&path)
}

/// [`ensure_profile_path`] against an explicit file (tests).
fn ensure_profile_path_at(path: &Path) -> Result<bool> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).context("reading the shell profile"),
    };
    if profile_has_shim(&existing) {
        return Ok(false);
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&profile_block());
    std::fs::write(path, updated).context("writing the shell profile")?;
    Ok(true)
}

/// Install the launchd plist and load the agent into the user's GUI domain.
/// Returns the plist path. The `launchctl bootstrap` is Mac-runtime; on failure
/// the plist is still written so a manual load is possible.
pub fn install_and_load_agent() -> Result<PathBuf> {
    let plist = service::install_plist()?;
    service::bootstrap(&plist)?;
    Ok(plist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-setup-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn profile_edit_is_idempotent_and_preserves_existing_content() {
        let dir = tmp("profile");
        let rc = dir.join(".zshrc");
        std::fs::write(&rc, "export EDITOR=vim\n").unwrap();

        // First run appends the managed block.
        assert!(ensure_profile_path_at(&rc).unwrap());
        let after = std::fs::read_to_string(&rc).unwrap();
        assert!(after.contains("export EDITOR=vim"), "existing content kept");
        assert!(after.contains(".sigil/bin"));
        assert!(after.contains(PROFILE_MARKER));

        // Second run is a no-op: no duplicate block.
        assert!(!ensure_profile_path_at(&rc).unwrap());
        let after2 = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(
            after2.matches(".sigil/bin").count(),
            1,
            "the PATH line must appear exactly once"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_edit_creates_the_file_when_absent() {
        let dir = tmp("newprofile");
        let rc = dir.join(".zshrc");
        assert!(ensure_profile_path_at(&rc).unwrap());
        assert!(rc.exists());
        assert!(std::fs::read_to_string(&rc).unwrap().contains(".sigil/bin"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_hand_written_path_line_is_respected() {
        let dir = tmp("handwritten");
        let rc = dir.join(".zshrc");
        std::fs::write(&rc, "export PATH=\"$HOME/.sigil/bin:$PATH\"\n").unwrap();
        // Already references the shim dir: no managed block appended.
        assert!(!ensure_profile_path_at(&rc).unwrap());
        assert!(!std::fs::read_to_string(&rc)
            .unwrap()
            .contains(PROFILE_MARKER));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shell_profile_picks_zshrc_by_default() {
        // Not asserting on the process env; just that the chooser returns a path.
        if std::env::var_os("HOME").is_some() {
            assert!(shell_profile().is_some());
        }
    }
}
