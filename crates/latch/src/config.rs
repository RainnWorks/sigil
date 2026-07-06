//! The generic if-this-then-that config store: rules and sources.
//!
//! Latch is "gated env-var injection + phone approval for ANY CLI", not an `op`
//! tool. This module is the core of that generality and holds **zero** concept
//! of 1Password. An invocation (argv) is matched against an ordered list of
//! [`Rule`]s; the first whose [`Match`] holds selects an [`Action`], which names
//! a [`Source`] (a pluggable provider configuration) to inject from and a risk
//! policy to gate under. `op` is one provider id among peers, named only inside a
//! user-authored source; the engine here never parses `op://`, reads `--vault`,
//! or special-cases any command.
//!
//! A configured invocation is gated on the phone and its source's provider
//! injects the approved environment; an *unmatched* invocation is refused with a
//! pointer to `latch-config` and never run ungated (a silent pass-through would
//! be false security).
//!
//! This is a config *mutation* surface, so — like the account and pairing stores
//! — it lives CLI-side (`latch-config …`). The daemon only *reads* it, loaded at
//! arm time (a compromised always-on daemon must not be able to rewrite which
//! commands are gated). Re-run `latch restart` to apply a change.
//!
//! See `docs/design/config-rule-engine.md` for the full design and migration.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use latch_proto::RiskLevel;

/// The current on-disk config schema version. Bumped only on a breaking layout
/// change; the loader tolerates a missing field via `serde(default)`.
pub const VERSION: u32 = 1;

/// A named provider configuration a rule injects from. `op`/1Password is one
/// `provider` value among peers (`env-file`, …); the engine never interprets the
/// provider-specific knobs, it hands the whole source to the provider.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Source {
    /// Unique id a rule's [`Action::source`] references.
    pub name: String,
    /// Provider id in the [`ProviderRegistry`](crate::provider::ProviderRegistry)
    /// (`1password`, `env-file`, …).
    pub provider: String,
    /// Provider-specific: the account label to route (the `op` provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Provider-specific: the KEY=VALUE file whose values are injected after
    /// approval (the `env-file` provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// One `{flag, value}` equality condition, e.g. `--project=prod`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlagEq {
    pub flag: String,
    pub value: String,
}

/// Composable conditions on an invoked command + argv. All present conditions
/// must hold (AND). A match with **no** conditions never matches — a
/// malformed/partial rule fails closed rather than gating every command.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Match {
    /// argv[0] equals this string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// argv[1] equals this string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommand: Option<String>,
    /// Every needle is a substring of some argv token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv_contains: Vec<String>,
    /// Every listed `--flag` is present (as `--flag` or `--flag=…`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_present: Vec<String>,
    /// Every `{flag,value}` is present (`--flag=value` or `--flag value`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_equals: Vec<FlagEq>,
    /// A regex over the space-joined args. DEFERRED: modeled and round-trips, but
    /// evaluation needs the `regex` crate (see the design doc); a rule that sets
    /// it is rejected at `rule add` time until the dependency is approved. When
    /// set, [`Match::matches`] treats it as never-matching (fails closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_regex: Option<String>,
}

impl Match {
    /// Whether every present condition holds for `argv`. Empty match => false.
    pub fn matches(&self, argv: &[String]) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(cmd) = &self.command {
            if argv.first() != Some(cmd) {
                return false;
            }
        }
        if let Some(sub) = &self.subcommand {
            if argv.get(1) != Some(sub) {
                return false;
            }
        }
        for needle in &self.argv_contains {
            if !argv.iter().any(|a| a.contains(needle.as_str())) {
                return false;
            }
        }
        for flag in &self.flag_present {
            if !flag_present(argv, flag) {
                return false;
            }
        }
        for fe in &self.flag_equals {
            if !flag_equals(argv, &fe.flag, &fe.value) {
                return false;
            }
        }
        // Deferred: an unevaluatable regex condition fails closed rather than
        // matching everything or silently ignoring the intent.
        if self.arg_regex.is_some() {
            return false;
        }
        true
    }

    /// Whether this match carries no conditions at all.
    pub fn is_empty(&self) -> bool {
        self.command.is_none()
            && self.subcommand.is_none()
            && self.argv_contains.is_empty()
            && self.flag_present.is_empty()
            && self.flag_equals.is_empty()
            && self.arg_regex.is_none()
    }
}

/// Whether `--flag` appears in `argv`, as a bare `--flag` or a `--flag=value`.
fn flag_present(argv: &[String], flag: &str) -> bool {
    let eq = format!("{flag}=");
    argv.iter().any(|a| a == flag || a.starts_with(&eq))
}

/// Whether `--flag value` appears, as `--flag=value` or `--flag` then `value`.
fn flag_equals(argv: &[String], flag: &str, value: &str) -> bool {
    let eq = format!("{flag}={value}");
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if a == &eq {
            return true;
        }
        if a == flag && it.clone().next().map(String::as_str) == Some(value) {
            return true;
        }
    }
    false
}

/// What to do on a match: gate under a risk policy, then inject the named
/// source's environment, then exec.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// The [`Source::name`] to inject from.
    pub source: String,
    /// Risk policy: scales the approve control on the phone (deny is always one
    /// tap). Serializes lowercase (`routine` / `elevated` / `critical`).
    #[serde(default = "default_risk")]
    pub risk: RiskLevel,
    /// Optional per-rule approval timeout in seconds; falls back to the global
    /// setting when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_sec: Option<u32>,
}

fn default_risk() -> RiskLevel {
    RiskLevel::Routine
}

/// One rule: a match paired with the action to take when it holds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Unique human label / id.
    pub name: String,
    #[serde(rename = "match")]
    pub match_: Match,
    pub action: Action,
}

/// The resolved gating decision for an invocation: the matched rule flattened
/// with its source into what [`fulfill`](crate::daemon) needs. Mirrors the fields
/// the old per-command config carried, plus the rule/source names for auditing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAction {
    /// The matched rule's name (for diagnostics/audit).
    pub rule: String,
    /// The provider id backing the source.
    pub provider: String,
    /// The provider-specific source path (`env-file`); empty for op.
    pub source_path: Option<String>,
    /// The account label to route (op); `None` for direct-injection providers.
    pub account: Option<String>,
    /// The approve-friction policy.
    pub risk: RiskLevel,
    /// Optional per-rule approval timeout in seconds.
    pub timeout_sec: Option<u32>,
}

/// The whole config: an ordered rule list plus the sources they reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_version() -> u32 {
    VERSION
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: VERSION,
            sources: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    /// `~/.latch/config.json`, or `$LATCH_HOME/config.json` (tests).
    pub fn path() -> Option<PathBuf> {
        crate::paths::latch_home().map(|h| h.join("config.json"))
    }

    /// The legacy per-command store path (`commands.json`), migrated on load.
    fn legacy_path() -> Option<PathBuf> {
        crate::paths::latch_home().map(|h| h.join("commands.json"))
    }

    /// Load the config. If `config.json` is absent but the legacy
    /// `commands.json` exists, migrate it (in memory; written on first save).
    /// An absent-everywhere config is the empty default.
    pub fn load() -> io::Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::load_legacy_or_default(),
            Err(e) => Err(e),
        }
    }

    /// Migrate the legacy `commands.json` into the rule/source model, or return
    /// the empty default when there is nothing to migrate.
    fn load_legacy_or_default() -> io::Result<Self> {
        let Some(legacy) = Self::legacy_path() else {
            return Ok(Self::default());
        };
        let bytes = match std::fs::read(&legacy) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };
        let legacy: LegacyStore = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self::from_legacy(legacy))
    }

    /// Build a config from the legacy per-command entries: each becomes a source
    /// named after its command plus a rule matching `command == <cmd>`. If no
    /// legacy entry named `op` exists, synthesize the historical implicit `op`
    /// default so a zero-config `op` keeps working after upgrade.
    fn from_legacy(legacy: LegacyStore) -> Self {
        let mut cfg = Self::default();
        let mut have_op = false;
        for c in legacy.commands {
            if c.command == "op" {
                have_op = true;
            }
            let source_name = c.command.clone();
            cfg.sources.push(Source {
                name: source_name.clone(),
                provider: c.provider,
                account: c.account,
                path: c.source,
            });
            cfg.rules.push(Rule {
                name: c.command.clone(),
                match_: Match {
                    command: Some(c.command),
                    ..Match::default()
                },
                action: Action {
                    source: source_name,
                    risk: c.risk,
                    timeout_sec: None,
                },
            });
        }
        if !have_op {
            cfg.add_op_default();
        }
        cfg
    }

    /// Append the historical implicit `op` rule + a default `1password` source
    /// (no account). Used by legacy migration to preserve zero-config `op`.
    fn add_op_default(&mut self) {
        const OP_SOURCE: &str = "op";
        self.sources.push(Source {
            name: OP_SOURCE.to_string(),
            provider: crate::provider::OpProvider::ID.to_string(),
            account: None,
            path: None,
        });
        self.rules.push(Rule {
            name: "op".to_string(),
            match_: Match {
                command: Some("op".to_string()),
                ..Match::default()
            },
            action: Action {
                source: OP_SOURCE.to_string(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        });
    }

    /// Persist the config, parent dir 0700 and file 0600 (public data, kept
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

    /// The source named `name`, if present.
    pub fn source(&self, name: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.name == name)
    }

    /// Whether any rule is keyed to the command name `cmd` (its match pins
    /// `command == cmd`). The coverage predicate the proxy/shim tooling asks
    /// before dropping an alias — "is `<cmd>` gated by a rule?" — kept here so it
    /// cannot drift from the match vocabulary. Note this is a *command-keyed*
    /// check, not full argv evaluation: a rule that matches only via
    /// subcommand/argv-contains without a `command` is deliberately not counted,
    /// because an alias is per-command and needs a command-anchored rule.
    pub fn gates_command(&self, cmd: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_.command.as_deref() == Some(cmd))
    }

    /// Resolve the first rule that matches `argv`, flattened with its source into
    /// a [`ResolvedAction`]. `None` means "unmatched" — the daemon refuses and
    /// points at `latch-config`. A rule whose action names an unknown source is
    /// skipped (fails closed rather than dispatching to a non-existent provider).
    pub fn resolve(&self, argv: &[String]) -> Option<ResolvedAction> {
        for rule in &self.rules {
            if !rule.match_.matches(argv) {
                continue;
            }
            let Some(src) = self.source(&rule.action.source) else {
                continue;
            };
            return Some(ResolvedAction {
                rule: rule.name.clone(),
                provider: src.provider.clone(),
                source_path: src.path.clone(),
                account: src.account.clone(),
                risk: rule.action.risk,
                timeout_sec: rule.action.timeout_sec,
            });
        }
        None
    }

    /// Add a source, rejecting a duplicate name.
    pub fn add_source(&mut self, src: Source) -> Result<(), String> {
        if self.sources.iter().any(|s| s.name == src.name) {
            return Err(format!(
                "source {} already exists (remove it first to replace)",
                src.name
            ));
        }
        self.sources.push(src);
        Ok(())
    }

    /// Remove the source named `name`. Returns true if one was removed. Refuses
    /// while a rule still references it (a dangling action would fail closed).
    pub fn remove_source(&mut self, name: &str) -> Result<bool, String> {
        if let Some(rule) = self.rules.iter().find(|r| r.action.source == name) {
            return Err(format!(
                "source {name} is still used by rule {}; remove the rule first",
                rule.name
            ));
        }
        let before = self.sources.len();
        self.sources.retain(|s| s.name != name);
        Ok(self.sources.len() != before)
    }

    /// Add a rule, rejecting a duplicate name, an empty match, or an action that
    /// references a source that does not exist.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), String> {
        if self.rules.iter().any(|r| r.name == rule.name) {
            return Err(format!(
                "rule {} already exists (remove it first to replace)",
                rule.name
            ));
        }
        if rule.match_.is_empty() {
            return Err("a rule needs at least one match condition".to_string());
        }
        if self.source(&rule.action.source).is_none() {
            return Err(format!(
                "rule {} references unknown source {}",
                rule.name, rule.action.source
            ));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Remove the rule named `name`. Returns true if one was removed.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() != before
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

/// The lowercase label for a risk level, for display and JSON.
pub fn risk_str(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Routine => "routine",
        RiskLevel::Elevated => "elevated",
        RiskLevel::Critical => "critical",
    }
}

/// The legacy `commands.json` shape, read once for migration only.
#[derive(Deserialize)]
struct LegacyStore {
    #[serde(default)]
    commands: Vec<LegacyCommand>,
}

#[derive(Deserialize)]
struct LegacyCommand {
    command: String,
    provider: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default = "default_risk")]
    risk: RiskLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_match_never_matches() {
        assert!(!Match::default().matches(&argv(&["op", "read"])));
    }

    #[test]
    fn command_and_argv_contains_and_together() {
        let m = Match {
            command: Some("op".into()),
            argv_contains: vec!["read".into()],
            ..Match::default()
        };
        assert!(m.matches(&argv(&["op", "read", "op://V/i/f"])));
        assert!(!m.matches(&argv(&["op", "item", "get"]))); // no "read"
        assert!(!m.matches(&argv(&["gcloud", "read"]))); // wrong command
    }

    #[test]
    fn subcommand_matches_argv1() {
        let m = Match {
            subcommand: Some("read".into()),
            ..Match::default()
        };
        assert!(m.matches(&argv(&["op", "read", "x"])));
        assert!(!m.matches(&argv(&["op", "item", "get"])));
    }

    #[test]
    fn flag_present_and_equals() {
        let m = Match {
            flag_present: vec!["--vault".into()],
            ..Match::default()
        };
        assert!(m.matches(&argv(&["op", "read", "--vault", "Eng"])));
        assert!(m.matches(&argv(&["op", "read", "--vault=Eng"])));
        assert!(!m.matches(&argv(&["op", "read"])));

        let eq = Match {
            flag_equals: vec![FlagEq {
                flag: "--project".into(),
                value: "prod".into(),
            }],
            ..Match::default()
        };
        assert!(eq.matches(&argv(&["gcloud", "--project=prod"])));
        assert!(eq.matches(&argv(&["gcloud", "--project", "prod"])));
        assert!(!eq.matches(&argv(&["gcloud", "--project", "dev"])));
    }

    #[test]
    fn regex_condition_is_deferred_and_fails_closed() {
        let m = Match {
            command: Some("op".into()),
            arg_regex: Some(".*".into()),
            ..Match::default()
        };
        assert!(
            !m.matches(&argv(&["op", "read"])),
            "a set regex must not match until it is implemented"
        );
    }

    #[test]
    fn resolve_first_match_wins_and_flattens_source() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "rowm-op".into(),
            provider: "1password".into(),
            account: Some("Rowm".into()),
            path: None,
        })
        .unwrap();
        cfg.add_source(Source {
            name: "gc".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x/.env".into()),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op-read".into(),
            match_: Match {
                command: Some("op".into()),
                argv_contains: vec!["read".into()],
                ..Match::default()
            },
            action: Action {
                source: "rowm-op".into(),
                risk: RiskLevel::Elevated,
                timeout_sec: Some(60),
            },
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "gcloud".into(),
            match_: Match {
                command: Some("gcloud".into()),
                ..Match::default()
            },
            action: Action {
                source: "gc".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();

        let r = cfg.resolve(&argv(&["op", "read", "op://V/i/f"])).unwrap();
        assert_eq!(r.rule, "op-read");
        assert_eq!(r.provider, "1password");
        assert_eq!(r.account.as_deref(), Some("Rowm"));
        assert_eq!(r.risk, RiskLevel::Elevated);
        assert_eq!(r.timeout_sec, Some(60));

        let g = cfg.resolve(&argv(&["gcloud", "auth"])).unwrap();
        assert_eq!(g.provider, "env-file");
        assert_eq!(g.source_path.as_deref(), Some("/x/.env"));

        assert!(cfg.resolve(&argv(&["kubectl", "get"])).is_none());
    }

    #[test]
    fn gates_command_is_command_keyed() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                source: "s".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        // A rule anchored only on a subcommand (no `command`) is not counted:
        // an alias is per-command and needs a command-anchored rule.
        cfg.add_rule(Rule {
            name: "sub-only".into(),
            match_: Match {
                subcommand: Some("read".into()),
                ..Match::default()
            },
            action: Action {
                source: "s".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        assert!(cfg.gates_command("op"));
        assert!(!cfg.gates_command("read"));
        assert!(!cfg.gates_command("gcloud"));
    }

    #[test]
    fn add_rule_rejects_unknown_source_and_empty_match() {
        let mut cfg = Config::default();
        assert!(cfg
            .add_rule(Rule {
                name: "x".into(),
                match_: Match {
                    command: Some("op".into()),
                    ..Match::default()
                },
                action: Action {
                    source: "nope".into(),
                    risk: RiskLevel::Routine,
                    timeout_sec: None,
                },
            })
            .is_err());
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
        })
        .unwrap();
        assert!(
            cfg.add_rule(Rule {
                name: "empty".into(),
                match_: Match::default(),
                action: Action {
                    source: "s".into(),
                    risk: RiskLevel::Routine,
                    timeout_sec: None,
                },
            })
            .is_err(),
            "an empty match must be rejected"
        );
    }

    #[test]
    fn remove_source_refuses_while_referenced() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "r".into(),
            match_: Match {
                command: Some("t".into()),
                ..Match::default()
            },
            action: Action {
                source: "s".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        assert!(cfg.remove_source("s").is_err(), "referenced source held");
        assert!(cfg.remove_rule("r"));
        assert!(cfg.remove_source("s").unwrap(), "now removable");
    }

    #[test]
    fn legacy_migration_builds_sources_and_rules_and_keeps_op_default() {
        // A legacy store with one non-op entry migrates to a source+rule, and
        // synthesizes the implicit op default so zero-config op keeps working.
        let legacy: LegacyStore = serde_json::from_str(
            r#"{"commands":[{"command":"gcloud","provider":"env-file","source":"/x/.env","risk":"elevated"}]}"#,
        )
        .unwrap();
        let cfg = Config::from_legacy(legacy);
        let g = cfg.resolve(&argv(&["gcloud", "auth"])).unwrap();
        assert_eq!(g.provider, "env-file");
        assert_eq!(g.source_path.as_deref(), Some("/x/.env"));
        assert_eq!(g.risk, RiskLevel::Elevated);
        // op still resolves by the synthesized default.
        let op = cfg.resolve(&argv(&["op", "read", "x"])).unwrap();
        assert_eq!(op.provider, "1password");
        assert_eq!(op.account, None);
    }

    #[test]
    fn legacy_explicit_op_is_not_double_added() {
        let legacy: LegacyStore = serde_json::from_str(
            r#"{"commands":[{"command":"op","provider":"1password","account":"Rowm","risk":"critical"}]}"#,
        )
        .unwrap();
        let cfg = Config::from_legacy(legacy);
        assert_eq!(cfg.rules.iter().filter(|r| r.name == "op").count(), 1);
        let op = cfg.resolve(&argv(&["op", "read"])).unwrap();
        assert_eq!(op.account.as_deref(), Some("Rowm"));
        assert_eq!(op.risk, RiskLevel::Critical);
    }

    #[test]
    fn round_trips_through_json() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "1password".into(),
            account: Some("Rowm".into()),
            path: None,
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                source: "s".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules, cfg.rules);
        assert_eq!(back.sources, cfg.sources);
        // The rename: the field serializes as "match".
        assert!(json.contains("\"match\""));
    }
}
