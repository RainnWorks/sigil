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

/// The shell profile to edit, chosen from `$SHELL` **and** from which candidate
/// files the home directory already has. `None` only if `$HOME` is unset.
pub fn shell_profile() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    Some(shell_profile_in(&shell, &home))
}

/// [`shell_profile`] against an explicit shell and home (tests).
///
/// zsh (the macOS default) uses `~/.zshrc`, which shadows nothing: zsh does not
/// read `~/.profile` of its own accord. bash is the case that has to be
/// resolved against the filesystem, because the file bash reads at login
/// depends on which of `~/.bash_profile`, `~/.bash_login` and `~/.profile`
/// already exist. See [`paths::bash_login_profile`]; picking the name blind is
/// how `sigil up` created a `~/.bash_profile` on a Linux box and took that
/// box's `~/.profile` out of service without saying so.
///
/// `$SHELL` alone is not a reliable platform signal and is not used as one
/// here: it picks the *chain*, and the filesystem picks the *file*.
fn shell_profile_in(shell: &str, home: &Path) -> PathBuf {
    if shell.ends_with("bash") {
        paths::bash_login_profile(home)
    } else {
        // zsh and anything else: ~/.zshrc is the macOS default.
        home.join(".zshrc")
    }
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

/// Install the supervision definition and load it. Returns the definition path:
/// the launchd plist on macOS, `~/.sigil/supervisor.conf` elsewhere. On a
/// bootstrap failure the definition is still written, so a manual load and a
/// later `sigil up` both still have something to work from.
pub fn install_and_load_agent() -> Result<PathBuf> {
    let definition = service::install_definition()?;
    service::bootstrap(&definition)?;
    Ok(definition)
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

    /// The box measured on RAI-49: a `~/.profile` from 2019 and a `~/.bashrc`,
    /// no `~/.bash_profile`. The chooser used to name `.bash_profile` blind,
    /// which created it and so stopped bash login shells reading `.profile` at
    /// all. The user's login environment disappeared with no message.
    #[test]
    fn bash_edits_the_existing_profile_instead_of_shadowing_it() {
        let home = tmp("bash-has-profile");
        std::fs::write(home.join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();

        let chosen = shell_profile_in("/bin/bash", &home);
        assert_eq!(chosen, home.join(".profile"), "the file bash reads");

        assert!(ensure_profile_path_at(&chosen).unwrap());
        assert!(
            !home.join(".bash_profile").exists(),
            "creating ~/.bash_profile here would demote the existing ~/.profile"
        );
        let after = std::fs::read_to_string(home.join(".profile")).unwrap();
        assert!(after.contains("export EDITOR=vim"), "existing content kept");
        assert!(after.contains(".sigil/bin"));
        assert_eq!(
            std::fs::read_to_string(home.join(".bashrc")).unwrap(),
            "alias ll='ls -l'\n",
            "~/.bashrc is not the login file and is left alone"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// The macOS-shaped case the old code assumed: `~/.bash_profile` is already
    /// there, so it is what bash reads and what we edit. `~/.profile` is not
    /// touched, because bash stops before reaching it.
    #[test]
    fn bash_prefers_an_existing_bash_profile() {
        let home = tmp("bash-has-bash-profile");
        std::fs::write(home.join(".bash_profile"), "export A=1\n").unwrap();
        std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();

        let chosen = shell_profile_in("/bin/bash", &home);
        assert_eq!(chosen, home.join(".bash_profile"));

        assert!(ensure_profile_path_at(&chosen).unwrap());
        assert!(std::fs::read_to_string(&chosen)
            .unwrap()
            .contains("export A=1"));
        assert_eq!(
            std::fs::read_to_string(home.join(".profile")).unwrap(),
            "export EDITOR=vim\n",
            "bash never reads ~/.profile when ~/.bash_profile exists"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// `~/.bash_login` is the middle of bash's chain and beats `~/.profile`.
    #[test]
    fn bash_login_beats_profile() {
        let home = tmp("bash-login");
        std::fs::write(home.join(".bash_login"), "export A=1\n").unwrap();
        std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();
        assert_eq!(
            shell_profile_in("/bin/bash", &home),
            home.join(".bash_login")
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// With no login file at all, creating `~/.bash_profile` is correct: there
    /// is nothing left for it to shadow. `~/.bashrc` is not in the login chain,
    /// so it keeps working exactly as before.
    #[test]
    fn bash_creates_bash_profile_only_when_there_is_nothing_to_shadow() {
        let home = tmp("bash-bare");
        std::fs::write(home.join(".bashrc"), "alias ll='ls -l'\n").unwrap();

        let chosen = shell_profile_in("/bin/bash", &home);
        assert_eq!(chosen, home.join(".bash_profile"));

        assert!(ensure_profile_path_at(&chosen).unwrap());
        assert!(chosen.exists());
        assert_eq!(
            std::fs::read_to_string(home.join(".bashrc")).unwrap(),
            "alias ll='ls -l'\n",
            "a login shell did not read ~/.bashrc before this and still does not"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// bash tests readability, so a dangling `~/.bash_profile` symlink is not a
    /// file bash reads, and it must not be one we edit either.
    #[test]
    fn a_dangling_bash_profile_symlink_does_not_count_as_present() {
        let home = tmp("bash-dangling");
        std::os::unix::fs::symlink(home.join(".nowhere"), home.join(".bash_profile")).unwrap();
        std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();
        assert_eq!(shell_profile_in("/bin/bash", &home), home.join(".profile"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// zsh is unchanged by any of this: it does not read `~/.profile` of its
    /// own accord, so `~/.zshrc` shadows nothing.
    #[test]
    fn zsh_and_the_default_still_pick_zshrc() {
        let home = tmp("zsh-profile");
        std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();
        assert_eq!(shell_profile_in("/bin/zsh", &home), home.join(".zshrc"));
        assert_eq!(shell_profile_in("", &home), home.join(".zshrc"));
        std::fs::remove_dir_all(&home).ok();
    }
}
