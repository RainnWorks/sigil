//! The per-command configuration store: the map that makes `latch <cmd>` the
//! primary primitive.
//!
//! `latch <cmd> [args]` (or the transparent shim alias, or `latch run -- <cmd>`)
//! looks up the configuration for `<cmd>` here. A configured command is gated on
//! the phone and its provider injects the approved environment; an *unconfigured*
//! command is refused with a pointer to `latch config add <cmd>` and never run
//! ungated (a silent pass-through would be false security).
//!
//! Each entry binds a command to:
//! * a **provider** id (which [`SecretProvider`](crate::provider::SecretProvider)
//!   backs it — `1password`, `env-file`, …);
//! * a provider-specific **source** (e.g. the env-file path; unused by `op`);
//! * an optional **account** hint (which 1Password account, when a provider needs
//!   one and the argv carries no `--vault`);
//! * a **risk** policy that scales the approve friction on the phone.
//!
//! This is a config *mutation* surface, so — like the account and pairing stores
//! — it lives CLI-side (`latch config add|list|remove`). The daemon only *reads*
//! it, loaded at arm time (a compromised always-on daemon must not be able to
//! rewrite which commands are gated). Re-run `latch restart` to apply a change.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use latch_proto::RiskLevel;

/// One command's configuration. `command` is the argv[0] the primitive matches
/// (`op`, `gcloud`, …); the rest select and parameterise the provider.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandConfig {
    /// The command name this entry configures (argv[0]).
    pub command: String,
    /// The provider id that backs it (see [`crate::provider::ProviderRegistry`]).
    pub provider: String,
    /// Provider-specific source. For `env-file`, the path to the KEY=VALUE file
    /// whose values are injected after approval. Unused by `op`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional 1Password account label to route to, for providers that need a
    /// stored credential when the argv carries no `--vault` hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Risk policy: scales the approve control on the phone (deny is always one
    /// tap). Serializes lowercase (`routine` / `elevated` / `critical`).
    #[serde(default = "default_risk")]
    pub risk: RiskLevel,
}

fn default_risk() -> RiskLevel {
    RiskLevel::Routine
}

impl CommandConfig {
    /// The built-in default for `op`: the 1Password provider at routine risk.
    ///
    /// [`CommandStore::resolve`] returns this when no explicit `op` entry exists,
    /// so `latch op ...` (and the `op` shim alias the rowm launcher hits) works
    /// with zero configuration, gated exactly as before the generalization. Every
    /// *other* command must be added explicitly.
    pub fn default_op() -> Self {
        Self {
            command: "op".to_string(),
            provider: crate::provider::OpProvider::ID.to_string(),
            source: None,
            account: None,
            risk: RiskLevel::Routine,
        }
    }
}

/// Parse a risk level from a CLI string. `None` on an unknown value so the caller
/// can reject it rather than silently defaulting.
pub fn parse_risk(s: &str) -> Option<RiskLevel> {
    match s.to_ascii_lowercase().as_str() {
        "routine" => Some(RiskLevel::Routine),
        "elevated" => Some(RiskLevel::Elevated),
        "critical" => Some(RiskLevel::Critical),
        _ => None,
    }
}

/// The `snake`/lowercase label for a risk level, for display and JSON.
pub fn risk_str(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Routine => "routine",
        RiskLevel::Elevated => "elevated",
        RiskLevel::Critical => "critical",
    }
}

/// The command catalogue, persisted at `~/.latch/commands.json`. Plaintext by
/// design: it holds no secret, only the routing that must work while the daemon
/// is inert.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CommandStore {
    #[serde(default)]
    pub commands: Vec<CommandConfig>,
}

impl CommandStore {
    /// `~/.latch/commands.json`, or `$LATCH_HOME/commands.json` (tests).
    pub fn path() -> Option<PathBuf> {
        crate::paths::latch_home().map(|h| h.join("commands.json"))
    }

    /// Load the store, returning an empty one if the file is absent.
    pub fn load() -> io::Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist the store, parent dir 0700 and file 0600 (public data, but kept
    /// consistent with the rest of `~/.latch`).
    pub fn save(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = Self::path().ok_or_else(|| io::Error::other("no LATCH_HOME/HOME for config"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// The explicit entry for `cmd`, if one exists.
    pub fn get(&self, cmd: &str) -> Option<&CommandConfig> {
        self.commands.iter().find(|c| c.command == cmd)
    }

    /// Resolve the configuration the daemon should use for `cmd`: an explicit
    /// entry, else the built-in `op` default. `None` means "unconfigured" — the
    /// daemon refuses and points at `latch config add`.
    pub fn resolve(&self, cmd: &str) -> Option<CommandConfig> {
        if let Some(cfg) = self.get(cmd) {
            return Some(cfg.clone());
        }
        if cmd == "op" {
            return Some(CommandConfig::default_op());
        }
        None
    }

    /// Add an entry, rejecting a duplicate command.
    pub fn add(&mut self, cfg: CommandConfig) -> Result<(), String> {
        if self.commands.iter().any(|c| c.command == cfg.command) {
            return Err(format!(
                "{} is already configured (remove it first to replace)",
                cfg.command
            ));
        }
        self.commands.push(cfg);
        Ok(())
    }

    /// Remove the entry for `cmd`. Returns true if one was removed.
    pub fn remove(&mut self, cmd: &str) -> bool {
        let before = self.commands.len();
        self.commands.retain(|c| c.command != cmd);
        self.commands.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_resolves_by_default_without_an_entry() {
        // Zero-config `op` must still resolve to the 1Password provider so the
        // shim alias keeps working exactly as before.
        let store = CommandStore::default();
        let cfg = store.resolve("op").expect("op resolves by default");
        assert_eq!(cfg.provider, crate::provider::OpProvider::ID);
        assert_eq!(cfg.risk, RiskLevel::Routine);
    }

    #[test]
    fn an_unconfigured_command_does_not_resolve() {
        let store = CommandStore::default();
        assert!(
            store.resolve("gcloud").is_none(),
            "an unconfigured command must be refused, never run ungated"
        );
    }

    #[test]
    fn add_get_remove_round_trip_and_reject_duplicates() {
        let mut store = CommandStore::default();
        store
            .add(CommandConfig {
                command: "gcloud".into(),
                provider: "env-file".into(),
                source: Some("/home/tom/.gcloud.env".into()),
                account: None,
                risk: RiskLevel::Elevated,
            })
            .unwrap();
        let got = store.get("gcloud").expect("configured");
        assert_eq!(got.provider, "env-file");
        assert_eq!(got.source.as_deref(), Some("/home/tom/.gcloud.env"));
        assert_eq!(got.risk, RiskLevel::Elevated);

        // A duplicate command is rejected.
        assert!(store
            .add(CommandConfig {
                command: "gcloud".into(),
                provider: "1password".into(),
                source: None,
                account: None,
                risk: RiskLevel::Routine,
            })
            .is_err());

        // An explicit op entry overrides the built-in default.
        store
            .add(CommandConfig {
                command: "op".into(),
                provider: "1password".into(),
                source: None,
                account: Some("Rowm".into()),
                risk: RiskLevel::Critical,
            })
            .unwrap();
        assert_eq!(store.resolve("op").unwrap().risk, RiskLevel::Critical);

        assert!(store.remove("gcloud"));
        assert!(!store.remove("gcloud"));
        assert!(store.get("gcloud").is_none());
    }

    #[test]
    fn risk_parses_and_round_trips_to_a_label() {
        assert_eq!(parse_risk("elevated"), Some(RiskLevel::Elevated));
        assert_eq!(parse_risk("CRITICAL"), Some(RiskLevel::Critical));
        assert_eq!(parse_risk("bogus"), None);
        assert_eq!(risk_str(RiskLevel::Routine), "routine");
    }
}
