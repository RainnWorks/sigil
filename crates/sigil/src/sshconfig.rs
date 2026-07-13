//! Generating and installing the Sigil-managed `~/.ssh/config` block that routes
//! chosen SSH hosts through Sigil's phone-gated agent, the way the 1Password app
//! generates an ssh config pointing specific hosts at its own agent.
//!
//! ## The layering model
//!
//! Sigil's agent ([`crate::sshagent`]) already serves only the keys you
//! registered. Which *hosts* use that agent is a pure client-side
//! `~/.ssh/config` concern, so nothing here touches the daemon, the wire, or any
//! key material: this module turns the `hosts` field on each served key into
//! `Host` stanzas that point `IdentityAgent` at Sigil's socket, and leaves every
//! other host on the user's normal agent.
//!
//! We own one file, `~/.sigil/ssh/config` (plus a `keys/` dir of public-key
//! files), and insert exactly one marked block into `~/.ssh/config`:
//!
//! ```text
//! # >>> sigil ssh (managed) >>>
//! Include /Users/you/.sigil/ssh/config
//! # <<< sigil ssh (managed) <<<
//! ```
//!
//! at the TOP of the file, because OpenSSH takes the *first* value seen for a
//! per-host keyword, so our `IdentityAgent` / `IdentitiesOnly` win for the routed
//! hosts. Removal takes out exactly our own marked block and preserves the
//! surrounding content; the one normalization is that any blank lines the file
//! led with are collapsed on install (idempotence needs a fixed point), so the
//! whole-file round-trip is not byte-identical when the original began with
//! whitespace. The untouched original is copied to `~/.ssh/config.sigil-backup`
//! on the first install regardless.
//!
//! Only public material is ever written. The `Include` and the stanzas are inert
//! routing hints; the phone gate on every signature is unchanged.

use std::io;
use std::path::{Path, PathBuf};

use crate::sshagent::SshKeyConfig;

/// The marker bracketing our block in `~/.ssh/config`. Distinct from the proxy
/// PATH markers so the two managed blocks never collide.
const BLOCK_START: &str = "# >>> sigil ssh (managed) >>>";
const BLOCK_END: &str = "# <<< sigil ssh (managed) <<<";

/// `~/.sigil/ssh`, the directory holding our generated config and public keys.
pub fn managed_dir() -> Option<PathBuf> {
    crate::paths::sigil_home().map(|h| h.join("ssh"))
}

/// `~/.sigil/ssh/config`, the file `~/.ssh/config` includes.
pub fn generated_config_path() -> Option<PathBuf> {
    managed_dir().map(|d| d.join("config"))
}

/// `~/.sigil/ssh/keys`, holding one `<slug>.pub` per routed key.
fn keys_dir() -> Option<PathBuf> {
    managed_dir().map(|d| d.join("keys"))
}

/// The user's `~/.ssh/config`. `SIGIL_SSH_USER_CONFIG` overrides it (tests).
fn user_ssh_config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SIGIL_SSH_USER_CONFIG") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh").join("config"))
}

/// One key that has hosts to route: its display label, the hosts, and its public
/// key line (never any secret). Resolved from a [`SshKeyConfig`] entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routed {
    pub label: String,
    pub hosts: Vec<String>,
    pub pub_line: String,
}

/// True if `h` is a safe ssh_config `Host` token: non-empty and free of any
/// whitespace or control character. This is the barrier against config
/// injection: a host carrying a newline (e.g. `github.com\n    ProxyCommand …`)
/// would otherwise splice arbitrary directives into the generated file and run a
/// command on the next `ssh`. Host *patterns* (globs `*` `?`, negation `!`) stay
/// legal; only whitespace and control bytes are refused. The CLI rejects a bad
/// token at add time; [`routed_keys`] also drops one defensively, so a
/// hand-edited or imported `ssh-keys.json` can never inject either.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

/// Collect the served keys that name at least one host, from both sources.
/// Entries that fail to resolve to a usable ed25519 key (the same check the
/// agent applies) or whose `.pub` is unreadable are skipped, so a broken entry
/// never poisons the whole config. Host tokens are filtered through
/// [`valid_host`], so an injected token is dropped rather than written.
pub fn routed_keys(cfg: &SshKeyConfig) -> Vec<Routed> {
    let mut out = Vec::new();
    for e in &cfg.keys {
        let hosts = safe_hosts(&e.hosts);
        if hosts.is_empty() {
            continue;
        }
        let Some(id) = crate::sshagent::resolve_identity(e) else {
            continue;
        };
        out.push(Routed {
            label: id.label,
            hosts,
            pub_line: e.public_key.trim().to_string(),
        });
    }
    for e in &cfg.files {
        let hosts = safe_hosts(&e.hosts);
        if hosts.is_empty() {
            continue;
        }
        let Some(id) = crate::sshagent::resolve_file_identity(e) else {
            continue;
        };
        let Ok(line) = std::fs::read_to_string(format!("{}.pub", e.path)) else {
            continue;
        };
        out.push(Routed {
            label: id.label,
            hosts,
            pub_line: line.trim().to_string(),
        });
    }
    out
}

/// Keep only the host tokens that pass [`valid_host`].
fn safe_hosts(hosts: &[String]) -> Vec<String> {
    hosts.iter().filter(|h| valid_host(h)).cloned().collect()
}

/// A filesystem-safe slug for a public-key filename, keeping `[A-Za-z0-9._-]` and
/// collapsing everything else to `-`. Empty input yields `key`.
fn slug(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "key".to_string()
    } else {
        s
    }
}

/// Assign each routed key a unique `<slug>.pub` filename, disambiguating repeats
/// with a numeric suffix so two keys labelled the same never clobber each other.
fn assign_pub_names(routed: &[Routed]) -> Vec<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut names = Vec::with_capacity(routed.len());
    for r in routed {
        let base = slug(&r.label);
        let mut name = format!("{base}.pub");
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}-{n}.pub");
            n += 1;
        }
        names.push(name);
    }
    names
}

/// Render the `~/.sigil/ssh/config` text: one `Host` stanza per routed key,
/// pinning the agent socket and offering only that key for its hosts. `pub_paths`
/// are the absolute `<keys_dir>/<slug>.pub` paths, parallel to `routed`.
fn render_config(routed: &[Routed], sock: &Path, pub_paths: &[PathBuf]) -> String {
    let mut s = String::new();
    s.push_str("# Managed by Sigil. Do not edit; regenerate with `sigil ssh config --install`.\n");
    s.push_str(
        "# Each host below is routed through Sigil's phone-gated agent; every other host is untouched.\n\n",
    );
    for (r, pub_path) in routed.iter().zip(pub_paths) {
        s.push_str(&format!("Host {}\n", r.hosts.join(" ")));
        s.push_str(&format!("    IdentityAgent {}\n", sock.display()));
        s.push_str(&format!("    IdentityFile {}\n", pub_path.display()));
        s.push_str("    IdentitiesOnly yes\n\n");
    }
    s
}

/// The marked `Include` block for `~/.ssh/config`, pointing at `generated`.
fn include_block(generated: &Path) -> String {
    format!(
        "{BLOCK_START}\nInclude {}\n{BLOCK_END}\n",
        generated.display()
    )
}

/// Strip our own `BLOCK_START..BLOCK_END` block (and the newline after it) from
/// `contents`, or `None` if it is not present. Only our block is touched.
fn strip_block(contents: &str) -> Option<String> {
    let start = contents.find(BLOCK_START)?;
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

/// Compose the new `~/.ssh/config` contents with our block at the top: strip any
/// prior managed block, drop the leading blank lines it left, and prepend a fresh
/// block. A fixed point, so a second identical install is a no-op.
fn compose_with_block(existing: &str, generated: &Path) -> String {
    let base = strip_block(existing).unwrap_or_else(|| existing.to_string());
    let base = base.trim_start();
    let mut out = include_block(generated);
    if !base.is_empty() {
        out.push('\n');
        out.push_str(base);
    }
    out
}

/// The result of an [`install`], for a truthful report to the user.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallReport {
    /// The routed keys written (label + hosts), for the summary.
    pub routed: Vec<Routed>,
    /// True if `~/.ssh/config` was modified (false when the block was already
    /// current).
    pub ssh_config_changed: bool,
    /// The backup path, set only when a first-time backup was taken this call.
    pub backup: Option<PathBuf>,
}

/// Generate the managed files from `cfg` and insert the `Include` into
/// `~/.ssh/config`. Writes `~/.sigil/ssh/config` and one `keys/<slug>.pub` per
/// routed key, then adds our marked block at the top of `~/.ssh/config`, backing
/// the original up to `<config>.sigil-backup` on the first insertion.
///
/// `sock` is the agent socket the stanzas pin (normally
/// [`crate::sshagent::socket_path`]). Only public material is written.
pub fn install(cfg: &SshKeyConfig, sock: &Path) -> io::Result<InstallReport> {
    use std::os::unix::fs::PermissionsExt;

    let routed = routed_keys(cfg);
    let dir = managed_dir().ok_or_else(|| io::Error::other("no SIGIL_HOME/HOME"))?;
    let kdir = keys_dir().ok_or_else(|| io::Error::other("no SIGIL_HOME/HOME"))?;
    let generated =
        generated_config_path().ok_or_else(|| io::Error::other("no SIGIL_HOME/HOME"))?;

    // Rewrite the keys dir from scratch so a removed route leaves no stale .pub.
    if kdir.exists() {
        std::fs::remove_dir_all(&kdir)?;
    }
    std::fs::create_dir_all(&kdir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let names = assign_pub_names(&routed);
    let mut pub_paths = Vec::with_capacity(routed.len());
    for (r, name) in routed.iter().zip(&names) {
        let p = kdir.join(name);
        std::fs::write(&p, format!("{}\n", r.pub_line))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644))?;
        pub_paths.push(p);
    }

    let config_text = render_config(&routed, sock, &pub_paths);
    std::fs::write(&generated, config_text)?;
    std::fs::set_permissions(&generated, std::fs::Permissions::from_mode(0o600))?;

    let (ssh_config_changed, backup) = insert_include(&generated)?;
    Ok(InstallReport {
        routed,
        ssh_config_changed,
        backup,
    })
}

/// Insert (or refresh) the `Include` block at the top of `~/.ssh/config`. Returns
/// `(changed, backup_taken_this_call)`. Creates `~/.ssh` (0700) if absent and
/// backs the original up to `<config>.sigil-backup` the first time it edits a
/// non-empty file.
fn insert_include(generated: &Path) -> io::Result<(bool, Option<PathBuf>)> {
    use std::os::unix::fs::PermissionsExt;

    let file =
        user_ssh_config_path().ok_or_else(|| io::Error::other("no HOME for ~/.ssh/config"))?;
    let existing = match std::fs::read_to_string(&file) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let updated = compose_with_block(&existing, generated);
    if updated == existing {
        return Ok((false, None));
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    // Back up the original the first time we edit a non-empty config.
    let mut backup_taken = None;
    if !existing.is_empty() {
        let backup = with_extension_suffix(&file, "sigil-backup");
        if !backup.exists() {
            std::fs::write(&backup, &existing)?;
            std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600))?;
            backup_taken = Some(backup);
        }
    }
    // Atomic replace: write a sibling temp, set its mode, then rename over the
    // target. A crash mid-write leaves the original config intact (the rename is
    // atomic on the same filesystem), rather than a truncated file recoverable
    // only from the once-taken backup.
    let tmp = with_extension_suffix(&file, "sigil-tmp");
    std::fs::write(&tmp, updated)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &file)?;
    Ok((true, backup_taken))
}

/// `<path>.<suffix>` (e.g. `~/.ssh/config` -> `~/.ssh/config.sigil-backup`).
fn with_extension_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Remove our managed block from `~/.ssh/config` and delete the generated files.
/// Returns true if `~/.ssh/config` changed. The backup, if any, is left in place
/// for the user to restore or discard.
pub fn uninstall() -> io::Result<bool> {
    let changed = match user_ssh_config_path() {
        Some(file) => match std::fs::read_to_string(&file) {
            Ok(existing) => match strip_block(&existing) {
                Some(updated) if updated != existing => {
                    // Drop the single separator newline install prepended before
                    // the user's content, so removal is byte-clean rather than
                    // leaving a leading blank line. Only one is removed, so a
                    // blank line the user themselves put first survives.
                    let updated = updated.strip_prefix('\n').unwrap_or(&updated);
                    std::fs::write(&file, updated)?;
                    true
                }
                _ => false,
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        },
        None => false,
    };
    if let Some(dir) = managed_dir() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
    }
    Ok(changed)
}

/// The text a user would paste to route these hosts by hand: the generated
/// `~/.sigil/ssh/config` stanzas plus the `Include` line, without writing
/// anything. For `sigil ssh config` (no `--install`).
pub fn preview(cfg: &SshKeyConfig, sock: &Path) -> String {
    let routed = routed_keys(cfg);
    let kdir = keys_dir().unwrap_or_else(|| PathBuf::from("~/.sigil/ssh/keys"));
    let names = assign_pub_names(&routed);
    let pub_paths: Vec<PathBuf> = names.iter().map(|n| kdir.join(n)).collect();
    let generated = generated_config_path().unwrap_or_else(|| PathBuf::from("~/.sigil/ssh/config"));
    let mut s = String::new();
    s.push_str("# --- add to the top of ~/.ssh/config ---\n");
    s.push_str(&include_block(&generated));
    s.push_str("\n# --- contents of ");
    s.push_str(&generated.display().to_string());
    s.push_str(" ---\n");
    s.push_str(&render_config(&routed, sock, &pub_paths));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sshagent::{SshFileEntry, SshKeyConfig, SshKeyEntry};

    /// A config with one op-backed routed key and its generated ed25519 pub line.
    fn one_routed_op(hosts: Vec<String>) -> (SshKeyConfig, String) {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pub_line = key.public_key().to_openssh().unwrap();
        let cfg = SshKeyConfig {
            keys: vec![SshKeyEntry {
                public_key: pub_line.clone(),
                vault: "Engineering".to_string(),
                item: "GitHub".to_string(),
                field: "private key".to_string(),
                comment: String::new(),
                hosts,
            }],
            files: Vec::new(),
        };
        (cfg, pub_line)
    }

    #[test]
    fn routed_keys_only_returns_entries_with_hosts() {
        let (cfg, _) = one_routed_op(vec!["github.com".into(), "gist.github.com".into()]);
        let routed = routed_keys(&cfg);
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].hosts, vec!["github.com", "gist.github.com"]);

        let (cfg_none, _) = one_routed_op(vec![]);
        assert!(
            routed_keys(&cfg_none).is_empty(),
            "a key with no hosts is served but not routed"
        );
    }

    #[test]
    fn valid_host_refuses_injection_but_allows_patterns() {
        assert!(valid_host("github.com"));
        assert!(valid_host("*.prod.rowm.co"), "globs are legal patterns");
        assert!(
            valid_host("!bastion.rowm.co"),
            "negation is a legal pattern"
        );
        assert!(!valid_host(""), "empty is not a host");
        // The injection the barrier exists for: a newline splicing a directive.
        assert!(!valid_host("github.com\n    ProxyCommand evil"));
        assert!(!valid_host("has space"), "a Host line is space-separated");
        assert!(!valid_host("tab\there"));
    }

    #[test]
    fn routed_keys_drops_injected_host_tokens() {
        // A hand-edited ssh-keys.json carrying an injection token must not reach
        // the generated config: routed_keys filters it, keeping only clean hosts.
        let (mut cfg, _) = one_routed_op(vec![
            "github.com".into(),
            "evil\n    ProxyCommand pwn".into(),
        ]);
        // The op entry from one_routed_op is index 0.
        let routed = routed_keys(&cfg);
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].hosts, vec!["github.com"], "injection dropped");

        // A key whose ONLY host is an injection token is not routed at all.
        cfg.keys[0].hosts = vec!["bad\nToken".into()];
        assert!(routed_keys(&cfg).is_empty());
    }

    #[test]
    fn slug_sanitizes_and_never_empties() {
        assert_eq!(slug("GitHub"), "GitHub");
        assert_eq!(slug("id_ed25519"), "id_ed25519");
        assert_eq!(slug("prod/bastion*.rowm"), "prod-bastion-.rowm");
        assert_eq!(slug("///"), "key");
    }

    #[test]
    fn duplicate_labels_get_distinct_pub_filenames() {
        let routed = vec![
            Routed {
                label: "GitHub".into(),
                hosts: vec!["a".into()],
                pub_line: "x".into(),
            },
            Routed {
                label: "GitHub".into(),
                hosts: vec!["b".into()],
                pub_line: "y".into(),
            },
        ];
        let names = assign_pub_names(&routed);
        assert_eq!(names, vec!["GitHub.pub", "GitHub-2.pub"]);
    }

    #[test]
    fn rendered_config_pins_agent_and_offers_only_our_key() {
        let routed = vec![Routed {
            label: "GitHub".into(),
            hosts: vec!["github.com".into(), "gist.github.com".into()],
            pub_line: "ssh-ed25519 AAAA test".into(),
        }];
        let pub_paths = vec![PathBuf::from("/home/tom/.sigil/ssh/keys/GitHub.pub")];
        let text = render_config(&routed, Path::new("/run/sigil/ssh.sock"), &pub_paths);
        assert!(text.contains("Host github.com gist.github.com"));
        assert!(text.contains("IdentityAgent /run/sigil/ssh.sock"));
        assert!(text.contains("IdentityFile /home/tom/.sigil/ssh/keys/GitHub.pub"));
        assert!(text.contains("IdentitiesOnly yes"));
    }

    #[test]
    fn compose_puts_block_at_top_and_is_a_fixed_point() {
        let generated = Path::new("/home/tom/.sigil/ssh/config");
        let user = "Host example.com\n    User tom\n";
        let once = compose_with_block(user, generated);
        assert!(once.starts_with(BLOCK_START), "our block leads the file");
        assert!(once.contains("Include /home/tom/.sigil/ssh/config"));
        assert!(once.contains("Host example.com"), "user content preserved");
        // A second pass reproduces byte-for-byte (idempotent).
        assert_eq!(compose_with_block(&once, generated), once);
    }

    #[test]
    fn strip_block_removes_only_our_block_byte_identically() {
        let generated = Path::new("/g/config");
        let user = "Host example.com\n    User tom\n";
        let installed = compose_with_block(user, generated);
        let stripped = strip_block(&installed).expect("block present");
        assert_eq!(
            stripped.trim_start(),
            user,
            "removal restores the user content"
        );
        assert!(strip_block(user).is_none(), "no block, nothing to strip");
    }

    /// Point SIGIL_HOME and SIGIL_SSH_USER_CONFIG at a temp dir, run install +
    /// uninstall against a real (fake) `~/.ssh/config`, and check the file edits,
    /// the backup, and the generated artifacts.
    #[test]
    fn install_then_uninstall_round_trips_the_user_config() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sigil-sshcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let home = dir.join("sigilhome");
        let ssh_config = dir.join("dot-ssh-config");
        std::fs::write(&ssh_config, "Host example.com\n    User tom\n").unwrap();

        let prev_home = std::env::var_os("SIGIL_HOME");
        let prev_uc = std::env::var_os("SIGIL_SSH_USER_CONFIG");
        std::env::set_var("SIGIL_HOME", &home);
        std::env::set_var("SIGIL_SSH_USER_CONFIG", &ssh_config);

        let (cfg, _) = one_routed_op(vec!["github.com".into()]);
        let sock = PathBuf::from("/run/sigil/ssh-agent.sock");

        let report = install(&cfg, &sock).expect("install succeeds");
        assert_eq!(report.routed.len(), 1);
        assert!(report.ssh_config_changed);
        assert!(report.backup.is_some(), "a first install backs the file up");

        let after = std::fs::read_to_string(&ssh_config).unwrap();
        assert!(after.starts_with(BLOCK_START));
        assert!(after.contains("Host example.com"), "user content kept");
        // The generated config and the pub file exist.
        let gen = home.join("ssh").join("config");
        assert!(std::fs::read_to_string(&gen)
            .unwrap()
            .contains("Host github.com"));
        assert!(home.join("ssh").join("keys").join("GitHub.pub").exists());
        // The backup holds the pre-install contents verbatim.
        let backup = std::fs::read_to_string(report.backup.unwrap()).unwrap();
        assert_eq!(backup, "Host example.com\n    User tom\n");

        // A second install is a no-op on ~/.ssh/config.
        let again = install(&cfg, &sock).expect("re-install succeeds");
        assert!(!again.ssh_config_changed, "idempotent");

        // Uninstall removes our block and the generated dir, keeps user content.
        let changed = uninstall().expect("uninstall succeeds");
        assert!(changed);
        let restored = std::fs::read_to_string(&ssh_config).unwrap();
        assert_eq!(
            restored, "Host example.com\n    User tom\n",
            "removal is byte-clean: original restored, no leading blank line"
        );
        assert!(!home.join("ssh").exists(), "generated dir removed");

        match prev_home {
            Some(v) => std::env::set_var("SIGIL_HOME", v),
            None => std::env::remove_var("SIGIL_HOME"),
        }
        match prev_uc {
            Some(v) => std::env::set_var("SIGIL_SSH_USER_CONFIG", v),
            None => std::env::remove_var("SIGIL_SSH_USER_CONFIG"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_source_routes_from_the_sibling_pub() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sigil-sshcfg-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let keypath = dir.join("id_ed25519");
        std::fs::write(&keypath, key.to_openssh(ssh_key::LineEnding::LF).unwrap()).unwrap();
        std::fs::write(
            format!("{}.pub", keypath.display()),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();

        let cfg = SshKeyConfig {
            keys: Vec::new(),
            files: vec![SshFileEntry {
                path: keypath.display().to_string(),
                comment: String::new(),
                hosts: vec!["old.example.net".into()],
            }],
        };
        let routed = routed_keys(&cfg);
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].hosts, vec!["old.example.net"]);
        assert!(routed[0].pub_line.starts_with("ssh-ed25519 "));
        std::fs::remove_dir_all(&dir).ok();
    }
}
