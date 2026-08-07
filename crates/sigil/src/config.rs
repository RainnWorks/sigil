//! The generic if-this-then-that config store: rules and sources.
//!
//! Sigil is "gated env-var injection + phone approval for ANY CLI", not an `op`
//! tool. This module is the core of that generality and holds **zero** concept
//! of 1Password. An invocation (argv) is matched against an ordered list of
//! [`Rule`]s; the first whose [`Match`] holds selects an [`Action`], which names
//! a [`Source`] (a pluggable provider configuration) to inject from and a lease
//! policy to gate under. `op` is one provider id among peers, named only inside a
//! user-authored source; the engine here never parses `op://`, reads `--vault`,
//! or special-cases any command.
//!
//! A configured invocation is gated on the phone and its source's provider
//! injects the approved environment; an *unmatched* invocation is refused with a
//! pointer to `sigil-config` and never run ungated (a silent pass-through would
//! be false security).
//!
//! This is a config *mutation* surface, so — like the account and pairing stores
//! — it lives CLI-side (`sigil-config …`). The daemon only *reads* it, loaded at
//! arm time (a compromised always-on daemon must not be able to rewrite which
//! commands are gated). Re-run `sigil restart` to apply a change.
//!
//! See `docs/design/config-rule-engine.md` for the full design and migration.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use sigil_proto::LeasePolicy;

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
    /// Provider-specific: for the inline `env` provider, the KEY **names** whose
    /// VALUES are injected after approval. The names are not secret and drive the
    /// zero-knowledge readout (the phone shows "will set FOO, BAR"); the VALUES
    /// are NEVER stored here. They are threshold-sealed in the threshold store
    /// (`threshold.db`), keyed by this source's `name`, opened per-approval with
    /// the phone's partial. A name listed here says only that a value was
    /// DECLARED; whether one is actually sealed is a runtime fact `export`
    /// overlays as a `sealed` flag (they diverge if a value was never set or a
    /// migration dropped it). Empty for every other provider. Kept sorted+unique
    /// by the CLI so `export`/`list` render deterministically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// NON-SECRET environment variables injected into the gated child verbatim,
    /// stored here in **cleartext** because they are explicitly not secrets:
    /// behavior switches for the gated tool (`OP_BIOMETRIC_UNLOCK_ENABLED=false`,
    /// `OP_CONFIG_DIR=…`, a scratch `HOME`). Sealed values ([`keys`](Self::keys))
    /// win on a key collision; see [`Config::resolve`].
    ///
    /// This hangs off the SOURCE rather than the rule because the source is
    /// already the "what environment does this inject" unit: the sealed key names
    /// live here, so collision resolution is a local read of one struct rather
    /// than a join, and several rules pointing at one source get one consistent
    /// environment instead of drifting per-rule copies. A rule stays what it has
    /// always been: a match plus which source to inject and how to lease it.
    ///
    /// A `BTreeMap` so the on-disk order is the sorted order (a stable
    /// `export`/diff) and a name can appear only once.
    ///
    /// The motivating case: a gated tool with its own ambient auth fallback that
    /// overrides the credential Sigil injects. `op` handed a valid
    /// `OP_SERVICE_ACCOUNT_TOKEN` still opened a caller channel to the 1Password
    /// desktop app and blocked in `open()` forever, because the daemon is not an
    /// authorized caller of that app. The fix is a plain var that turns the
    /// fallback off, and a plain var is the honest shape for it: sealing a value
    /// whose leak costs nothing would say Sigil is protecting something it is not.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plain: BTreeMap<String, String>,
}

impl Source {
    /// The plain vars as an ordered `(name, value)` list for injection. Sorted by
    /// name (the map's own order) so a spawn env is built deterministically.
    pub fn plain_pairs(&self) -> Vec<(String, String)> {
        self.plain
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Substrings that make an environment variable NAME look like a secret. Matched
/// case-insensitively anywhere in the name, so `GH_TOKEN`, `apikey_prod` and
/// `MY_PASSWORD_FILE` all trip it.
const SECRET_LOOKING: &[&str] = &["TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL", "APIKEY"];

/// Secret-looking ACRONYMS, matched as a whole `_`/punctuation-delimited segment
/// rather than a substring. `PAT` as a substring would condemn `PATH`, which is
/// both the most ordinary env var there is and one of the plain vars this feature
/// exists to set; as a segment it still catches `GH_PAT` and `PAT_GITHUB`.
const SECRET_LOOKING_SEGMENTS: &[&str] = &["PAT"];

/// The secret-looking token in `name`, if any.
///
/// A plain var is stored in cleartext in `config.json`, so writing a credential
/// into one is a silent downgrade from "Sigil is protecting this" to "Sigil is
/// publishing this" with no visible difference at the call site. Name-shape is a
/// blunt instrument and it will have false positives (`OP_CONFIG_KEYRING`,
/// `SSH_KEY_PATH`), which is why the CLI offers an explicit override rather than
/// a hard ban.
pub fn secret_looking_name(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    if let Some(t) = SECRET_LOOKING.iter().copied().find(|t| upper.contains(t)) {
        return Some(t);
    }
    SECRET_LOOKING_SEGMENTS.iter().copied().find(|t| {
        upper
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|seg| seg == *t)
    })
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

    /// Flag names in this match that can never match anything, i.e. those written
    /// without a leading dash.
    ///
    /// [`flag_present`] and [`flag_equals`] compare against whole argv tokens, so
    /// a flag stored as `account` would have to appear in argv as the bare word
    /// `account`, never as `--account` or `--account=x`. A rule authored that way
    /// renders correctly in `sigil-config list` and is dead on arrival, which is
    /// exactly the kind of quiet nothing this tool must not produce. `rule add`
    /// normalizes at authoring time; this reports the ones already on disk.
    pub fn dead_flags(&self) -> Vec<&str> {
        self.flag_present
            .iter()
            .map(String::as_str)
            .chain(self.flag_equals.iter().map(|fe| fe.flag.as_str()))
            .filter(|f| !f.starts_with('-'))
            .collect()
    }

    /// **The coverage label** for this match: a short, factual, display-only
    /// description of everything the rule matches, e.g. `op read`,
    /// `op with --account "rowmhq.1password.eu"`, or plain `op` when nothing
    /// beyond the command is constrained.
    ///
    /// This is what the daemon renders into
    /// [`LeasePolicy::Leasable::covers`](sigil_proto::LeasePolicy) so the phone's
    /// consent surface, the Mac, and `sigil lease list` describe one window with
    /// the same words instead of each guessing. Rendering rules:
    ///
    /// * It states the breadth honestly. A command-only rule renders the bare
    ///   command, never a narrower-sounding phrase, because the rule really does
    ///   cover every invocation of that command.
    /// * It is built ONLY from the user's own match conditions. No argv is ever
    ///   emitted (the invocation that happened to trip the rule is not the rule),
    ///   and no secret reference can appear (the match vocabulary has no secret
    ///   axis).
    /// * It is bounded. Beyond [`COVERS_MAX_ATOMS`] conditions, or past
    ///   [`sigil_proto::COVERS_MAX_CHARS`] characters, it degrades to an honest
    ///   count ("op with 5 match conditions") rather than a truncated list that
    ///   would read as if the omitted conditions did not exist. Individual
    ///   user-authored tokens are elided at [`COVERS_TOKEN_MAX`] so one long value
    ///   cannot eat the whole line.
    /// * It degrades the same way when a condition cannot be RENDERED, not just
    ///   when there are too many. A value with no printable ASCII in it (a vault
    ///   named in Japanese) reaches the consent surface as a bare marker, and
    ///   `op with --vault "<mark>"` would name a condition it cannot identify:
    ///   every such vault renders identically while the sentence still reads as
    ///   though it pinned one. `op with 1 match condition` is coarser and true,
    ///   which is the trade a consent surface takes. The cost is real and worth
    ///   stating: the count form drops the flag NAME too, so the reader loses
    ///   "there is a vault pin" along with the vault. See [`renders_anything`].
    /// * Every user-authored VALUE is quoted — `--vault "Shared Eng"`, like an
    ///   `argv_contains` needle — because the surfaces that render this label wrap
    ///   it in a colon-punctuated sentence ("Covers <label>: every command and
    ///   secret it matches"). Unquoted, an ordinary 1Password vault name with a
    ///   space dissolves into that prose, and a value carrying a colon
    ///   (`--host github.example.com:8443`) collides with the sentence's own
    ///   punctuation. Quoting also removes a real ambiguity in [`join_and`]:
    ///   `with --account "X" and --vault` now shows at a glance that the first
    ///   flag is pinned to a value and the second matches any value.
    ///
    ///   This is LEGIBILITY, not injection defence. The label is rendered
    ///   daemon-side from structured config fields, [`token`] bounds each atom,
    ///   [`LeasePolicy::with_covers`](sigil_proto::LeasePolicy) reduces the whole
    ///   label to an allowlist of printable ASCII (so nothing in it can reorder,
    ///   hide or stack on the caption it rides in), and [`Config::resolve`]
    ///   re-derives the label on every match
    ///   so a hand-edited `covers` on disk is ignored. Nothing remote reaches it.
    ///   The reason to quote is that Tom's own legitimate config produces bad
    ///   sentences without it.
    ///
    /// Never returns empty: every arm of `head` yields text, so a renderer's
    /// empty-label branch is a fallback for a daemon older than this field, not a
    /// state this code can produce.
    pub fn coverage(&self) -> String {
        let head = match (
            self.command.as_deref().map(token),
            self.subcommand.as_deref().map(token),
        ) {
            (Some(cmd), Some(sub)) => format!("{cmd} {sub}"),
            (Some(cmd), None) => cmd,
            (None, Some(sub)) => format!("any command with the subcommand {sub}"),
            (None, None) => "any command".to_string(),
        };

        let atoms = self.flag_equals.len()
            + self.flag_present.len()
            + self.argv_contains.len()
            + usize::from(self.arg_regex.is_some());
        if atoms == 0 {
            return head;
        }
        // Many conditions: an honest count beats a list the bound would truncate.
        if atoms > COVERS_MAX_ATOMS {
            return summarize(&head, atoms);
        }

        // A condition whose tokens carry nothing the label filter will render must
        // not be quoted into the sentence as though it named a value: two
        // different vaults would produce the identical `op with --vault "<mark>"`,
        // which looks precise and says nothing. Degrade to the count form the
        // "too many conditions" case already uses.
        let unrenderable = self
            .flag_equals
            .iter()
            .flat_map(|fe| [token(&fe.flag), token(&fe.value)])
            .chain(self.flag_present.iter().map(|f| token(f)))
            .chain(self.argv_contains.iter().map(|n| token(n)))
            .any(|t| !renders_anything(&t));
        if unrenderable {
            return summarize(&head, atoms);
        }

        let mut clauses: Vec<String> = Vec::new();
        let mut flags: Vec<String> = self
            .flag_equals
            .iter()
            .map(|fe| format!("{} \"{}\"", token(&fe.flag), token(&fe.value)))
            .collect();
        flags.extend(self.flag_present.iter().map(|f| token(f)));
        if !flags.is_empty() {
            clauses.push(format!("with {}", join_and(&flags)));
        }
        if !self.argv_contains.is_empty() {
            let needles: Vec<String> = self
                .argv_contains
                .iter()
                .map(|n| format!("\"{}\"", token(n)))
                .collect();
            clauses.push(format!("containing {}", join_and(&needles)));
        }
        if self.arg_regex.is_some() {
            clauses.push("matching a pattern".to_string());
        }

        let detailed = format!("{head} {}", clauses.join(", "));
        if detailed.chars().count() > sigil_proto::COVERS_MAX_CHARS {
            return summarize(&head, atoms);
        }
        detailed
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

/// Above this many match conditions, [`Match::coverage`] states a count instead
/// of listing them: three atoms is about what a phone caption line carries
/// before it stops being read.
pub const COVERS_MAX_ATOMS: usize = 3;

/// The longest a single user-authored token (a command, flag, value, or needle)
/// may run inside a coverage label before it is elided.
pub const COVERS_TOKEN_MAX: usize = 28;

/// One user-authored token, bounded for display. Whitespace and characters a
/// consent surface will not render are normalized by `LeasePolicy::with_covers`
/// on the way out; this only stops one long value from consuming the whole label.
fn token(raw: &str) -> String {
    elide(raw, COVERS_TOKEN_MAX)
}

/// Whether a display token would survive the label filter carrying anything a
/// reader could compare against their own rule.
///
/// The filter reduces a label to printable ASCII plus its own two marks (see
/// [`sigil_proto::sanitize_label`]), so a token written entirely in a non-Latin
/// script, or in whitespace, arrives at the consent surface as a bare marker or
/// as nothing. Quoting that into `--vault "<mark>"` would name a condition it
/// cannot identify: every such vault renders identically, and the reader learns
/// only that a pin exists. This is the predicate `Match::coverage` uses to fall
/// back to the honest count instead. The token is filtered here rather than
/// inspected directly so the two definitions of "renderable" cannot drift.
fn renders_anything(display_token: &str) -> bool {
    sigil_proto::sanitize_label(display_token, COVERS_TOKEN_MAX)
        .chars()
        .any(|c| c.is_ascii_graphic())
}

/// `raw` cut to at most `max` characters, the last of them the elision mark.
/// Counted in characters, like every other bound on this label, so a multi-byte
/// token is cut where a reader would cut it.
fn elide(raw: &str, max: usize) -> String {
    if raw.chars().count() <= max {
        return raw.to_string();
    }
    let mut s: String = raw
        .chars()
        .take(max.saturating_sub(1))
        .collect::<String>()
        .trim_end()
        .to_string();
    s.push('\u{2026}');
    s
}

/// `a`, `a and b`, `a, b and c` — the human list separator for a coverage label.
fn join_and(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The honest summary form: how wide, plus how many conditions narrow it.
///
/// The count clause is the whole reason this form exists, so it is what survives
/// the bound: the HEAD is elided to whatever
/// [`sigil_proto::COVERS_MAX_CHARS`] leaves after the clause, never the other way
/// round. Rendering the fallback and letting `with_covers` cut the tail off
/// produced `op … sss… with 4 match…`, which states neither the breadth nor the
/// count (R4-F5): a long `command` plus a long `subcommand` plus more than
/// [`COVERS_MAX_ATOMS`] conditions reaches 81 characters unaided.
fn summarize(head: &str, atoms: usize) -> String {
    let tail = if atoms == 1 {
        " with 1 match condition".to_string()
    } else {
        format!(" with {atoms} match conditions")
    };
    let budget = sigil_proto::COVERS_MAX_CHARS.saturating_sub(tail.chars().count());
    // A count so long it leaves the head no room at all is not reachable from a
    // config (atoms counts match conditions), but the clause still wins: a label
    // that says only how many conditions there are is degraded, not dishonest.
    if budget == 0 {
        return tail.trim_start().to_string();
    }
    format!("{}{tail}", elide(head, budget))
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

/// Whether a matched rule **gates** its command (phone approval + env injection,
/// under the lease policy) or **allows** it straight through (a passthrough: run
/// directly, no approval, no injection, no lease).
///
/// The default is [`Gate`](RuleMode::Gate): a missing or unknown mode must gate,
/// never allow, so a config authored before this field, or a hand-edit that drops
/// it, fails safe to gating rather than silently opening a passthrough. `allow`
/// is only ever the user's explicit, per-match choice.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// Require phone approval and inject the named source, honoring the lease policy.
    #[default]
    Gate,
    /// Passthrough: run the matched command directly, ungated and uninjected. An
    /// explicit allowlist entry, scoped strictly to the rule's match.
    Allow,
}

impl RuleMode {
    pub fn is_gate(&self) -> bool {
        matches!(self, RuleMode::Gate)
    }
    pub fn is_allow(&self) -> bool {
        matches!(self, RuleMode::Allow)
    }
}

/// What to do on a match. For a [`Gate`](RuleMode::Gate) rule: gate under the
/// lease policy, then inject the named source's environment, then exec. For an
/// [`Allow`](RuleMode::Allow) rule: nothing but run the command directly (no
/// `source`, no `lease`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// Gate (default) or allow (passthrough). See [`RuleMode`].
    #[serde(default)]
    pub mode: RuleMode,
    /// The [`Source::name`] to inject from. Required (non-empty) for a gate rule;
    /// **empty for an allow rule**, which injects nothing (the empty string is
    /// omitted on disk).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// Lease policy for a gate rule: whether an approval may also open an
    /// auto-approve window and its cap. Defaults to (and omits, on disk)
    /// [`LeasePolicy::RunOnce`], so a rule missing this field fails safe to
    /// run-once. Meaningless for an allow rule, where it stays run-once and is
    /// never consulted. Serializes only when leasable, e.g.
    /// `{"kind":"leasable","maxSecs":900}`. The policy's coverage label is NOT
    /// stored here: it is derived from the rule's [`Match`] at resolve time, so a
    /// hand-edited `covers` on disk is ignored and cannot be used to write
    /// arbitrary words onto the phone's consent surface.
    #[serde(default, skip_serializing_if = "LeasePolicy::is_run_once")]
    pub lease: LeasePolicy,
    /// Optional per-rule approval timeout in seconds; falls back to the global
    /// setting when absent. Unused by an allow rule (no approval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_sec: Option<u32>,
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

/// What [`Config::resolve`] decides for an invocation. `None` from resolve means
/// "refuse" (unmatched, or a matched-but-broken gate rule); this enum is the
/// matched outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// A passthrough: run the matched command directly, ungated and uninjected.
    /// Carries the matched rule name for the audit line only.
    Allow { rule: String },
    /// A gate: approve on the phone, then inject and exec per the [`ResolvedAction`].
    Gate(ResolvedAction),
}

/// The resolved GATE decision for an invocation: the matched gate rule flattened
/// with its source into what [`fulfill`](crate::daemon) needs. Mirrors the fields
/// the old per-command config carried, plus the rule/source names for auditing.
/// An allow rule resolves to [`Resolution::Allow`] instead, carrying none of this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAction {
    /// The matched rule's name (for diagnostics/audit).
    pub rule: String,
    /// The provider id backing the source.
    pub provider: String,
    /// The source's name, i.e. the key under which the inline `env` provider's
    /// sealed value blob is stored in the account store. The daemon uses it to
    /// fetch that blob; empty of meaning for other providers.
    pub source_name: String,
    /// The provider-specific source path (`env-file`); empty for op.
    pub source_path: Option<String>,
    /// The account label to route (op); `None` for direct-injection providers.
    pub account: Option<String>,
    /// The inline `env` provider's KEY names (for `describe`); empty otherwise.
    /// Names only, never values (values are sealed in the account store).
    pub env_keys: Vec<String>,
    /// The source's NON-SECRET `(name, value)` env vars, injected verbatim into
    /// the child alongside whatever the provider resolves. Cleartext by
    /// construction (see [`Source::plain`]), so unlike `env_keys` these carry
    /// their values. A sealed key of the same name wins; the daemon drops the
    /// shadowed entry here and says so once.
    pub plain_env: Vec<(String, String)>,
    /// The rule's lease policy: whether an approval may open an auto-approve
    /// window and its cap. The daemon consults this as the sole authority when
    /// deciding whether to grant (and how long to grant) a lease.
    ///
    /// When leasable, [`resolve`](Config::resolve) has already stamped it with the
    /// [`coverage`](Match::coverage) label rendered from THIS rule's match, so
    /// every downstream renderer (phone, Mac, CLI) says the same thing about the
    /// window's breadth. A run-once policy carries no label.
    pub lease: LeasePolicy,
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
    /// `~/.sigil/config.json`, or `$SIGIL_HOME/config.json` (tests).
    pub fn path() -> Option<PathBuf> {
        crate::paths::sigil_home().map(|h| h.join("config.json"))
    }

    /// The legacy per-command store path (`commands.json`), migrated on load.
    fn legacy_path() -> Option<PathBuf> {
        crate::paths::sigil_home().map(|h| h.join("commands.json"))
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
    /// default so a zero-config `op` keeps working after upgrade. The retired
    /// per-command risk tier is dropped: every migrated rule is run-once (the safe
    /// default), and a command becomes leasable only by re-authoring it.
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
                keys: Vec::new(),
                plain: Default::default(),
            });
            cfg.rules.push(Rule {
                name: c.command.clone(),
                match_: Match {
                    command: Some(c.command),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: source_name,
                    lease: LeasePolicy::RunOnce,
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
            keys: Vec::new(),
            plain: Default::default(),
        });
        self.rules.push(Rule {
            name: "op".to_string(),
            match_: Match {
                command: Some("op".to_string()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: OP_SOURCE.to_string(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        });
    }

    /// Persist the config, parent dir 0700 and file 0600 (public data, kept
    /// consistent with the rest of `~/.sigil`).
    pub fn save(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = Self::path().ok_or_else(|| io::Error::other("no SIGIL_HOME/HOME for config"))?;
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

    /// Resolve the first rule that matches `argv` into a [`Resolution`]. `None`
    /// means "refuse" — the daemon fails closed and points at `sigil-config`.
    /// First-match-in-config-order (the drag-to-order layering) is the ONLY
    /// precedence: stack a specific `Allow` rule above a general `Gate` rule and
    /// the specific match wins.
    ///
    /// An **allow** rule resolves to [`Resolution::Allow`]: a passthrough, no
    /// source lookup, no gate. A **gate** rule flattens with its source into a
    /// [`ResolvedAction`]. A gate rule whose action names an **unknown source**
    /// makes the whole resolution fail closed (`None`), it does NOT fall through
    /// to a later, broader rule. Falling through would be a fail-OPEN downgrade: a
    /// malformed or hand-edited high-priority rule could silently route the command
    /// to a broader rule the author did not intend for it. Invariant #5 wins over
    /// convenience; `sigil-config` and `import` validate referential integrity up
    /// front, so a dangling source only arises from a hand-edit, and the safe
    /// answer to a hand-edited-broken rule is to refuse. An **unmatched**
    /// invocation is likewise `None` (refuse) — never a silent passthrough.
    pub fn resolve(&self, argv: &[String]) -> Option<Resolution> {
        for rule in &self.rules {
            if !rule.match_.matches(argv) {
                continue;
            }
            if rule.action.mode.is_allow() {
                // Explicit, user-authored ungating, scoped strictly to this match.
                // No source, no injection, no gate.
                return Some(Resolution::Allow {
                    rule: rule.name.clone(),
                });
            }
            let Some(src) = self.source(&rule.action.source) else {
                // Matched gate rule, but its source is gone: refuse, never downgrade.
                return None;
            };
            return Some(Resolution::Gate(ResolvedAction {
                rule: rule.name.clone(),
                provider: src.provider.clone(),
                source_name: src.name.clone(),
                source_path: src.path.clone(),
                account: src.account.clone(),
                env_keys: src.keys.clone(),
                plain_env: src.plain_pairs(),
                // The coverage label is rendered HERE, by the daemon, from this
                // rule's own match conditions — never read from disk and never
                // supplied by a client, so no hand-edit or peer can put words on
                // the consent surface that the match does not back.
                lease: rule
                    .action
                    .lease
                    .clone()
                    .with_covers(rule.match_.coverage()),
                timeout_sec: rule.action.timeout_sec,
            }));
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

    /// Add a rule, rejecting a duplicate name or an empty match. A gate rule must
    /// name an existing source; an allow rule must carry no source and no lease
    /// (it is a pure passthrough). An empty match is rejected in BOTH modes, so an
    /// allow rule can never become an allow-everything (a match-less rule already
    /// never matches, but rejecting it up front makes the intent explicit).
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
        match rule.action.mode {
            RuleMode::Allow => {
                if !rule.action.source.is_empty() {
                    return Err(format!(
                        "allow rule {} must not name a source (it injects nothing)",
                        rule.name
                    ));
                }
                if rule.action.lease.is_leasable() {
                    return Err(format!(
                        "allow rule {} cannot be leasable (it never gates)",
                        rule.name
                    ));
                }
            }
            RuleMode::Gate => {
                if rule.action.source.is_empty() {
                    return Err(format!("gate rule {} needs a --source", rule.name));
                }
                if self.source(&rule.action.source).is_none() {
                    return Err(format!(
                        "rule {} references unknown source {}",
                        rule.name, rule.action.source
                    ));
                }
            }
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

/// A short human label for a lease policy, for `rule list` and `list` display.
/// Run-once renders `run-once`; leasable renders `leasable(<n>s)`.
pub fn lease_str(lease: &LeasePolicy) -> String {
    match lease {
        LeasePolicy::RunOnce => "run-once".to_string(),
        LeasePolicy::Leasable { max_secs, .. } => format!("leasable({max_secs}s)"),
    }
}

/// The legacy `commands.json` shape, read once for migration only. The old
/// per-command `risk` tier is intentionally not read: migrated rules are all
/// run-once (see [`Config::from_legacy`]).
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_flag_with_no_leading_dash_is_reported_as_dead() {
        // Rules authored before normalization can hold one. It cannot match any
        // real argv, so `rule list` has to say so rather than render it as
        // working config.
        let m = Match {
            command: Some("op".into()),
            flag_present: vec!["no-input".into(), "--quiet".into()],
            flag_equals: vec![
                FlagEq {
                    flag: "account".into(),
                    value: "rowmhq.1password.eu".into(),
                },
                FlagEq {
                    flag: "--vault".into(),
                    value: "Engineering".into(),
                },
            ],
            ..Match::default()
        };
        assert_eq!(m.dead_flags(), vec!["no-input", "account"]);
        assert!(
            !m.matches(&argv(&[
                "op",
                "--no-input",
                "--quiet",
                "--account=rowmhq.1password.eu",
                "--vault=Engineering"
            ])),
            "and it really does not match, which is the whole problem"
        );

        let fixed = Match {
            flag_present: vec!["--quiet".into()],
            flag_equals: vec![FlagEq {
                flag: "--vault".into(),
                value: "Engineering".into(),
            }],
            ..m
        };
        assert!(fixed.dead_flags().is_empty());
        assert!(fixed.matches(&argv(&["op", "--quiet", "--vault=Engineering"])));
    }

    /// Unwrap a resolution as a gate action, panicking on an allow (the common
    /// case for the gate-focused tests below).
    fn gate(r: Resolution) -> ResolvedAction {
        match r {
            Resolution::Gate(a) => a,
            Resolution::Allow { rule } => panic!("expected a gate resolution, got allow({rule})"),
        }
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

    // --- coverage label -----------------------------------------------------

    #[test]
    fn coverage_renders_each_match_shape() {
        // Command only: the honest breadth is the whole command, and the label
        // says exactly that rather than implying a narrower window.
        assert_eq!(
            Match {
                command: Some("op".into()),
                ..Match::default()
            }
            .coverage(),
            "op"
        );

        // Subcommand: the register the design brief asks for.
        assert_eq!(
            Match {
                command: Some("op".into()),
                subcommand: Some("read".into()),
                ..Match::default()
            }
            .coverage(),
            "op read"
        );

        // flag_equals names the flag and QUOTES the value it is pinned to, so the
        // value survives the colon-punctuated sentence the consent surfaces wrap
        // this label in, and so it is visibly distinct from a flag_present flag
        // that matches any value.
        assert_eq!(
            Match {
                command: Some("op".into()),
                flag_equals: vec![FlagEq {
                    flag: "--account".into(),
                    value: "rowmhq.1password.eu".into(),
                }],
                ..Match::default()
            }
            .coverage(),
            "op with --account \"rowmhq.1password.eu\""
        );

        // The values that made this necessary: a vault name with a space, and a
        // value carrying the caption's own punctuation.
        assert_eq!(
            Match {
                command: Some("op".into()),
                subcommand: Some("read".into()),
                flag_equals: vec![FlagEq {
                    flag: "--vault".into(),
                    value: "Shared Eng".into(),
                }],
                ..Match::default()
            }
            .coverage(),
            "op read with --vault \"Shared Eng\""
        );
        assert_eq!(
            Match {
                command: Some("curl".into()),
                flag_equals: vec![FlagEq {
                    flag: "--host".into(),
                    value: "github.example.com:8443".into(),
                }],
                ..Match::default()
            }
            .coverage(),
            "curl with --host \"github.example.com:8443\""
        );

        // flag_present names the flag alone (any value satisfies it).
        assert_eq!(
            Match {
                command: Some("op".into()),
                flag_present: vec!["--vault".into()],
                ..Match::default()
            }
            .coverage(),
            "op with --vault"
        );

        // argv_contains is a substring test, rendered as a quoted needle.
        assert_eq!(
            Match {
                command: Some("op".into()),
                argv_contains: vec!["Engineering".into()],
                ..Match::default()
            }
            .coverage(),
            "op containing \"Engineering\""
        );

        // Mixed conditions read as one sentence, flags first.
        assert_eq!(
            Match {
                command: Some("op".into()),
                subcommand: Some("read".into()),
                flag_present: vec!["--vault".into()],
                argv_contains: vec!["prod".into()],
                ..Match::default()
            }
            .coverage(),
            "op read with --vault, containing \"prod\""
        );

        // Two flags of the same kind list with "and", and the quoting is what
        // tells them apart: --project is pinned to one value, --quiet takes any.
        assert_eq!(
            Match {
                command: Some("gcloud".into()),
                flag_equals: vec![FlagEq {
                    flag: "--project".into(),
                    value: "prod".into(),
                }],
                flag_present: vec!["--quiet".into()],
                ..Match::default()
            }
            .coverage(),
            "gcloud with --project \"prod\" and --quiet"
        );

        // No command at all: the label must not pretend one was pinned.
        assert_eq!(
            Match {
                subcommand: Some("read".into()),
                ..Match::default()
            }
            .coverage(),
            "any command with the subcommand read"
        );
        assert_eq!(
            Match {
                argv_contains: vec!["prod".into()],
                ..Match::default()
            }
            .coverage(),
            "any command containing \"prod\""
        );

        // The deferred regex condition is named, never echoed.
        let re = Match {
            command: Some("op".into()),
            arg_regex: Some("^op://Engineering/.*$".into()),
            ..Match::default()
        }
        .coverage();
        assert_eq!(re, "op matching a pattern");
        assert!(!re.contains("op://"));
    }

    #[test]
    fn coverage_is_bounded_and_summarizes_a_busy_rule() {
        // Beyond COVERS_MAX_ATOMS conditions, an honest count beats a list that
        // the bound would have to truncate (a truncated list would read as if the
        // dropped conditions did not narrow the window).
        let busy = Match {
            command: Some("op".into()),
            subcommand: Some("read".into()),
            flag_present: vec!["--a".into(), "--b".into()],
            argv_contains: vec!["x".into(), "y".into(), "z".into()],
            ..Match::default()
        };
        assert_eq!(busy.coverage(), "op read with 5 match conditions");
        assert!(busy.coverage().chars().count() <= sigil_proto::COVERS_MAX_CHARS);

        // A few conditions that are individually long also summarize rather than
        // overflow the caption line.
        let long_values = Match {
            command: Some("op".into()),
            flag_equals: vec![
                FlagEq {
                    flag: "--account".into(),
                    value: "a".repeat(40),
                },
                FlagEq {
                    flag: "--vault".into(),
                    value: "b".repeat(40),
                },
            ],
            ..Match::default()
        };
        assert_eq!(long_values.coverage(), "op with 2 match conditions");

        // One long token is elided, not allowed to consume the whole label.
        let one_long = Match {
            command: Some("op".into()),
            flag_equals: vec![FlagEq {
                flag: "--account".into(),
                value: "c".repeat(200),
            }],
            ..Match::default()
        };
        assert!(one_long.coverage().chars().count() <= sigil_proto::COVERS_MAX_CHARS);
        assert!(one_long.coverage().contains('\u{2026}'));

        // Even a pathological command name cannot overflow the wire bound once
        // the policy stamps it (the proto is the last line of defense).
        let huge = Match {
            command: Some("d".repeat(500)),
            ..Match::default()
        };
        let stamped = LeasePolicy::leasable(60).with_covers(huge.coverage());
        assert!(stamped.covers().chars().count() <= sigil_proto::COVERS_MAX_CHARS);

        // Singular reads as singular when a single long condition summarizes.
        let single = Match {
            command: Some("e".repeat(60)),
            flag_equals: vec![FlagEq {
                flag: "f".repeat(40),
                value: "g".repeat(40),
            }],
            ..Match::default()
        };
        assert!(
            single.coverage().ends_with("with 1 match condition"),
            "got {}",
            single.coverage()
        );

        // R4-F5, the shape the three above never reached: a long command AND a
        // long subcommand AND more than COVERS_MAX_ATOMS conditions. The head is
        // then two elided tokens plus a space (57 characters) and the count
        // clause adds 24, so the summary used to hand `with_covers` 81 characters
        // and get the count clause itself cut ("... with 4 match…"). The count is
        // the whole point of this form, so the head yields to it instead.
        let both_long = Match {
            command: Some("c".repeat(60)),
            subcommand: Some("s".repeat(60)),
            flag_present: vec!["--a".into(), "--b".into()],
            argv_contains: vec!["x".into(), "y".into()],
            ..Match::default()
        };
        let summary = both_long.coverage();
        assert!(
            summary.ends_with("with 4 match conditions"),
            "the count clause must survive the bound intact: {summary}"
        );
        assert!(
            summary.chars().count() <= sigil_proto::COVERS_MAX_CHARS,
            "{} chars: {summary}",
            summary.chars().count()
        );
        // And it is still true after the choke point, which is what the phone,
        // the Mac and `sigil lease list` actually render.
        let stamped_both = LeasePolicy::leasable(60).with_covers(&summary);
        assert_eq!(stamped_both.covers(), summary);
        assert!(stamped_both.covers().ends_with("with 4 match conditions"));
        // The breadth is still stated first: the head is elided, never dropped.
        assert!(stamped_both.covers().starts_with("cccc"));
    }

    /// A condition the consent surface cannot render must not be quoted into the
    /// sentence as though it named a value: after the label filter, every such
    /// value looks identical, so the sentence would read as precise while
    /// identifying nothing.
    #[test]
    fn coverage_degrades_a_condition_it_cannot_render_to_the_count() {
        let vault = |v: &str| Match {
            command: Some("op".into()),
            subcommand: Some("read".into()),
            flag_equals: vec![FlagEq {
                flag: "--vault".into(),
                value: v.into(),
            }],
            ..Match::default()
        };

        // Two different vaults, neither with any printable ASCII in it. Quoted,
        // both would render `op read with --vault "<mark>"`.
        for v in ["\u{65e5}\u{672c}", "\u{4e2d}\u{56fd}", "   ", "\u{202e}"] {
            assert_eq!(
                vault(v).coverage(),
                "op read with 1 match condition",
                "unrenderable value {v:?} was quoted as though it named a vault"
            );
        }

        // Partly renderable is still rendered: the marker sits where the gap is,
        // and the rest of the value is there to compare against the rule.
        let accented = vault("Ing\u{e9}nierie");
        assert_eq!(accented.coverage(), "op read with --vault \"Ingénierie\"");
        assert_eq!(
            LeasePolicy::leasable(60)
                .with_covers(accented.coverage())
                .covers(),
            "op read with --vault \"Ing\u{fffd}nierie\""
        );

        // The same holds for the other token positions.
        let needle = Match {
            command: Some("op".into()),
            argv_contains: vec!["\u{30a8}\u{30f3}".into()],
            ..Match::default()
        };
        assert_eq!(needle.coverage(), "op with 1 match condition");
        let flag = Match {
            command: Some("op".into()),
            flag_present: vec!["\u{30d5}\u{30e9}\u{30b0}".into()],
            ..Match::default()
        };
        assert_eq!(flag.coverage(), "op with 1 match condition");

        // A count reached this way is still a count: it must not claim a breadth
        // narrower than the rule's, and it must survive the choke point whole.
        let mixed = Match {
            command: Some("op".into()),
            flag_equals: vec![
                FlagEq {
                    flag: "--account".into(),
                    value: "rowmhq.1password.eu".into(),
                },
                FlagEq {
                    flag: "--vault".into(),
                    value: "\u{65e5}\u{672c}".into(),
                },
            ],
            ..Match::default()
        };
        assert_eq!(mixed.coverage(), "op with 2 match conditions");
        assert_eq!(
            LeasePolicy::leasable(60)
                .with_covers(mixed.coverage())
                .covers(),
            "op with 2 match conditions"
        );
    }

    #[test]
    fn resolve_stamps_the_coverage_label_only_on_a_leasable_rule() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "op".into(),
            provider: "1password".into(),
            account: None,
            path: None,
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op-read".into(),
            match_: Match {
                command: Some("op".into()),
                subcommand: Some("read".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "op".into(),
                lease: LeasePolicy::leasable(900),
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op-item".into(),
            match_: Match {
                command: Some("op".into()),
                subcommand: Some("item".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "op".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();

        let leasable = gate(cfg.resolve(&argv(&["op", "read", "op://V/i/f"])).unwrap());
        assert_eq!(leasable.rule, "op-read");
        assert_eq!(leasable.lease.covers(), "op read");

        // A run-once rule opens no window, so it must describe none.
        let once = gate(cfg.resolve(&argv(&["op", "item", "get", "x"])).unwrap());
        assert_eq!(once.lease, LeasePolicy::RunOnce);
        assert_eq!(once.lease.covers(), "");
    }

    #[test]
    fn a_hand_edited_covers_on_disk_is_ignored_by_resolve() {
        // `covers` is daemon-rendered from the match, never read from config: a
        // hand-edit cannot put arbitrary words on the phone's consent surface.
        let json = r#"{
          "version": 1,
          "sources": [{"name":"op","provider":"1password"}],
          "rules": [{
            "name":"op-read",
            "match":{"command":"op","subcommand":"read"},
            "action":{"mode":"gate","source":"op",
                      "lease":{"kind":"leasable","maxSecs":900,
                               "covers":"only this one harmless secret"}}
          }]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let a = gate(cfg.resolve(&argv(&["op", "read", "op://V/i/f"])).unwrap());
        assert_eq!(a.lease.covers(), "op read");
    }

    #[test]
    fn resolving_never_writes_the_label_back_into_the_config() {
        // The label is derived per resolution, so the in-memory (and therefore
        // saved) config keeps none: it can never drift from the match it claims to
        // describe, and `sigil-config export` stays byte-stable.
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "op".into(),
            provider: "1password".into(),
            account: None,
            path: None,
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op-read".into(),
            match_: Match {
                command: Some("op".into()),
                subcommand: Some("read".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "op".into(),
                lease: LeasePolicy::leasable(900),
                timeout_sec: None,
            },
        })
        .unwrap();

        let r = gate(cfg.resolve(&argv(&["op", "read", "op://V/i/f"])).unwrap());
        assert_eq!(r.lease.covers(), "op read");
        assert_eq!(cfg.rules[0].action.lease.covers(), "");
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"maxSecs\":900"));
        assert!(
            !json.contains("covers"),
            "the saved config must not carry a coverage label: {json}"
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
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_source(Source {
            name: "gc".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x/.env".into()),
            keys: Vec::new(),
            plain: Default::default(),
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
                mode: RuleMode::Gate,
                source: "rowm-op".into(),
                lease: LeasePolicy::leasable(900),
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
                mode: RuleMode::Gate,
                source: "gc".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();

        let r = gate(cfg.resolve(&argv(&["op", "read", "op://V/i/f"])).unwrap());
        assert_eq!(r.rule, "op-read");
        assert_eq!(r.provider, "1password");
        assert_eq!(r.account.as_deref(), Some("Rowm"));
        // Resolution stamps the coverage label rendered from this rule's match.
        assert_eq!(
            r.lease,
            LeasePolicy::leasable(900).with_covers("op containing \"read\"")
        );
        assert_eq!(r.timeout_sec, Some(60));

        let g = gate(cfg.resolve(&argv(&["gcloud", "auth"])).unwrap());
        assert_eq!(g.provider, "env-file");
        assert_eq!(g.source_path.as_deref(), Some("/x/.env"));

        assert!(cfg.resolve(&argv(&["kubectl", "get"])).is_none());
    }

    #[test]
    fn resolve_flattens_inline_env_keys_and_source_name() {
        // An inline env source carries KEY names (never values) and its name is
        // the blob key the daemon fetches; resolve() must surface both.
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "deploy-env".into(),
            provider: crate::provider::EnvProvider::ID.into(),
            account: None,
            path: None,
            keys: vec!["TOKEN".into(), "REGION".into()],
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "deploy".into(),
            match_: Match {
                command: Some("deploy".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "deploy-env".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        let r = gate(cfg.resolve(&argv(&["deploy", "--now"])).unwrap());
        assert_eq!(r.provider, "env");
        assert_eq!(r.source_name, "deploy-env");
        assert_eq!(r.env_keys, vec!["TOKEN".to_string(), "REGION".to_string()]);
        assert_eq!(r.source_path, None);
        assert_eq!(r.account, None);

        // The KEY names round-trip through JSON; values were never here to leak.
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"keys\""));
        assert!(json.contains("TOKEN"));
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sources, cfg.sources);
    }

    /// A source plus a rule matching `command == <name>`, for the plain-var tests.
    fn one_source_cfg(provider: &str, keys: &[&str], plain: &[(&str, &str)]) -> Config {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: provider.into(),
            account: None,
            path: None,
            keys: keys.iter().map(|k| k.to_string()).collect(),
            plain: plain
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "r".into(),
            match_: Match {
                command: Some("tool".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "s".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    #[test]
    fn resolve_carries_the_sources_plain_vars_sorted() {
        let cfg = one_source_cfg(
            crate::provider::EnvProvider::ID,
            &["OP_SERVICE_ACCOUNT_TOKEN"],
            &[
                ("OP_CONFIG_DIR", "/tmp/scratch"),
                ("OP_BIOMETRIC_UNLOCK_ENABLED", "false"),
            ],
        );
        let r = gate(cfg.resolve(&argv(&["tool", "run"])).unwrap());
        assert_eq!(
            r.plain_env,
            vec![
                (
                    "OP_BIOMETRIC_UNLOCK_ENABLED".to_string(),
                    "false".to_string()
                ),
                ("OP_CONFIG_DIR".to_string(), "/tmp/scratch".to_string()),
            ],
            "sorted by name, so a spawn env is built the same way every time"
        );
        // Sealed and plain are different kinds of thing and stay separable at the
        // resolution boundary: names only on one side, values on the other.
        assert_eq!(r.env_keys, vec!["OP_SERVICE_ACCOUNT_TOKEN".to_string()]);
    }

    #[test]
    fn a_source_with_only_plain_vars_resolves_as_a_live_gate() {
        // Gate plus plain env injection, no sealed value anywhere: a legitimate
        // configuration, not the dead config an unsealed declared key would be.
        let cfg = one_source_cfg(
            crate::provider::EnvProvider::ID,
            &[],
            &[("OP_BIOMETRIC_UNLOCK_ENABLED", "false")],
        );
        let r = gate(cfg.resolve(&argv(&["tool", "run"])).unwrap());
        assert!(r.env_keys.is_empty());
        assert_eq!(r.plain_env.len(), 1);
    }

    #[test]
    fn plain_vars_round_trip_through_config_json_in_cleartext() {
        // Cleartext is the point: they are not secrets, and a reader of
        // config.json must be able to see exactly which values Sigil is NOT
        // protecting.
        let cfg = one_source_cfg(
            "1password",
            &[],
            &[("OP_BIOMETRIC_UNLOCK_ENABLED", "false")],
        );
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        assert!(json.contains("\"plain\""), "{json}");
        assert!(json.contains("\"false\""), "the value is stored: {json}");
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sources, cfg.sources);

        // And a source with none omits the field entirely, so an existing
        // config.json is byte-identical after a round trip.
        let bare = one_source_cfg("1password", &[], &[]);
        assert!(!serde_json::to_string(&bare).unwrap().contains("plain"));
        // A config written before this field loads with an empty map.
        let old: Config =
            serde_json::from_str(r#"{"version":1,"sources":[{"name":"s","provider":"env"}]}"#)
                .unwrap();
        assert!(old.sources[0].plain.is_empty());
    }

    #[test]
    fn secret_looking_names_are_flagged_and_ordinary_ones_are_not() {
        for name in [
            "GITHUB_TOKEN",
            "aws_secret_access_key",
            "MY_PASSWORD_FILE",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "SSH_KEY_PATH",
            "GCP_CREDENTIALS",
            "apikey_prod",
            "GH_PAT",
            "PAT_GITHUB",
        ] {
            assert!(
                secret_looking_name(name).is_some(),
                "{name} should trip the guardrail"
            );
        }
        for name in [
            "OP_BIOMETRIC_UNLOCK_ENABLED",
            "OP_CONFIG_DIR",
            "HOME",
            "PATH",
            "NO_COLOR",
            "AWS_REGION",
            "COMPATIBILITY_MODE",
        ] {
            assert_eq!(
                secret_looking_name(name),
                None,
                "{name} is an ordinary behavior switch and must not be refused"
            );
        }
    }

    #[test]
    fn gates_command_is_command_keyed() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "s".into(),
                lease: LeasePolicy::RunOnce,
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
                mode: RuleMode::Gate,
                source: "s".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        assert!(cfg.gates_command("op"));
        assert!(!cfg.gates_command("read"));
        assert!(!cfg.gates_command("gcloud"));
    }

    #[test]
    fn matched_rule_with_unknown_source_fails_closed_not_downgrade() {
        // sec-review Note B: a matched rule whose source is gone (hand-edited
        // config) must REFUSE, never fall through to a later broader rule. Build a
        // config by hand (bypassing add_rule's referential check, as a bad edit
        // would) where the first matching rule points at a missing source and a
        // later catch-all-ish rule would otherwise capture the same command.
        let cfg = Config {
            version: VERSION,
            sources: vec![Source {
                name: "real".into(),
                provider: "env-file".into(),
                account: None,
                path: Some("/x/.env".into()),
                keys: Vec::new(),
                plain: Default::default(),
            }],
            rules: vec![
                Rule {
                    name: "specific".into(),
                    match_: Match {
                        command: Some("op".into()),
                        argv_contains: vec!["read".into()],
                        ..Match::default()
                    },
                    action: Action {
                        mode: RuleMode::Gate,
                        source: "GONE".into(), // dangling on purpose
                        lease: LeasePolicy::RunOnce,
                        timeout_sec: None,
                    },
                },
                Rule {
                    name: "broad".into(),
                    match_: Match {
                        command: Some("op".into()),
                        ..Match::default()
                    },
                    action: Action {
                        mode: RuleMode::Gate,
                        source: "real".into(),
                        lease: LeasePolicy::RunOnce,
                        timeout_sec: None,
                    },
                },
            ],
        };
        // `op read …` matches the specific (broken) rule first -> refuse, do NOT
        // downgrade to the broad rule.
        assert!(
            cfg.resolve(&argv(&["op", "read", "x"])).is_none(),
            "a matched rule with a dangling source must fail closed, not downgrade"
        );
        // A command the broken rule does NOT match still resolves via the broad
        // rule (the fail-closed is scoped to the matched-but-broken rule).
        assert_eq!(
            gate(cfg.resolve(&argv(&["op", "item", "get"])).unwrap()).rule,
            "broad"
        );
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
                    mode: RuleMode::Gate,
                    source: "nope".into(),
                    lease: LeasePolicy::RunOnce,
                    timeout_sec: None,
                },
            })
            .is_err());
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        assert!(
            cfg.add_rule(Rule {
                name: "empty".into(),
                match_: Match::default(),
                action: Action {
                    mode: RuleMode::Gate,
                    source: "s".into(),
                    lease: LeasePolicy::RunOnce,
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
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "r".into(),
            match_: Match {
                command: Some("t".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "s".into(),
                lease: LeasePolicy::RunOnce,
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
        let g = gate(cfg.resolve(&argv(&["gcloud", "auth"])).unwrap());
        assert_eq!(g.provider, "env-file");
        assert_eq!(g.source_path.as_deref(), Some("/x/.env"));
        // The retired risk tier is dropped on migration: every rule is run-once.
        assert_eq!(g.lease, LeasePolicy::RunOnce);
        // op still resolves by the synthesized default.
        let op = gate(cfg.resolve(&argv(&["op", "read", "x"])).unwrap());
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
        let op = gate(cfg.resolve(&argv(&["op", "read"])).unwrap());
        assert_eq!(op.account.as_deref(), Some("Rowm"));
        assert_eq!(op.lease, LeasePolicy::RunOnce);
    }

    #[test]
    fn round_trips_through_json() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "1password".into(),
            account: Some("Rowm".into()),
            path: None,
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "s".into(),
                lease: LeasePolicy::RunOnce,
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

    #[test]
    fn action_defaults_to_run_once_when_lease_field_absent() {
        // A rule authored before the lease field (or hand-edited to drop it) must
        // deserialize to run-once, the safe default: never silently leasable.
        let cfg: Config = serde_json::from_str(
            r#"{"version":1,
                "sources":[{"name":"s","provider":"env-file","path":"/x/.env"}],
                "rules":[{"name":"r","match":{"command":"gcloud"},"action":{"source":"s"}}]}"#,
        )
        .unwrap();
        let r = gate(cfg.resolve(&argv(&["gcloud", "auth"])).unwrap());
        assert_eq!(r.lease, LeasePolicy::RunOnce);
    }

    #[test]
    fn leasable_policy_round_trips_through_config_json() {
        // A leasable rule with a cap survives export -> import byte-for-byte, and
        // resolve() surfaces the cap the daemon clamps against.
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "gc".into(),
            provider: "1password".into(),
            account: Some("Rowm".into()),
            path: None,
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "gcloud".into(),
            match_: Match {
                command: Some("gcloud".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "gc".into(),
                lease: LeasePolicy::leasable(900),
                timeout_sec: None,
            },
        })
        .unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"kind\":\"leasable\""));
        assert!(json.contains("\"maxSecs\":900"));
        // The stored policy carries the cap only; the coverage label is derived at
        // resolve time and never persisted.
        assert!(!json.contains("covers"));
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules, cfg.rules);
        let r = gate(back.resolve(&argv(&["gcloud", "auth"])).unwrap());
        assert_eq!(r.lease, LeasePolicy::leasable(900).with_covers("gcloud"));
    }

    #[test]
    fn allow_rule_resolves_to_passthrough_and_layers_above_a_gate() {
        // The `op account list` use case: a specific ALLOW rule stacked ABOVE the
        // general GATE rule. First-match-in-order is the only precedence.
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "op".into(),
            provider: "1password".into(),
            account: None,
            path: None,
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op-account-list".into(),
            match_: Match {
                command: Some("op".into()),
                subcommand: Some("account".into()),
                argv_contains: vec!["list".into()],
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Allow,
                source: String::new(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Gate,
                source: "op".into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();

        // The specific allow rule wins for `op account list`.
        assert_eq!(
            cfg.resolve(&argv(&["op", "account", "list"])),
            Some(Resolution::Allow {
                rule: "op-account-list".into()
            })
        );
        // Any other `op` falls through to the gate rule.
        let g = gate(cfg.resolve(&argv(&["op", "read", "x"])).unwrap());
        assert_eq!(g.rule, "op");
        assert_eq!(g.provider, "1password");
        // An unmatched command still refuses (never a silent passthrough).
        assert!(cfg.resolve(&argv(&["kubectl", "get"])).is_none());

        // The allow rule round-trips and carries no source/lease on disk.
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"mode\":\"allow\""));
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules, cfg.rules);
    }

    #[test]
    fn add_rule_rejects_an_allow_with_a_source_or_lease_and_a_gate_without() {
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "s".into(),
            provider: "env-file".into(),
            account: None,
            path: Some("/x".into()),
            keys: Vec::new(),
            plain: Default::default(),
        })
        .unwrap();
        // An allow rule that names a source is rejected (it injects nothing).
        assert!(cfg
            .add_rule(Rule {
                name: "bad-allow".into(),
                match_: Match {
                    command: Some("op".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Allow,
                    source: "s".into(),
                    lease: LeasePolicy::RunOnce,
                    timeout_sec: None,
                },
            })
            .is_err());
        // An allow rule that is leasable is rejected (it never gates).
        assert!(cfg
            .add_rule(Rule {
                name: "leasable-allow".into(),
                match_: Match {
                    command: Some("op".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Allow,
                    source: String::new(),
                    lease: LeasePolicy::leasable(60),
                    timeout_sec: None,
                },
            })
            .is_err());
        // A gate rule with no source is rejected.
        assert!(cfg
            .add_rule(Rule {
                name: "sourceless-gate".into(),
                match_: Match {
                    command: Some("op".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: String::new(),
                    lease: LeasePolicy::RunOnce,
                    timeout_sec: None,
                },
            })
            .is_err());
        // A valid allow rule (no source, run-once) is accepted.
        assert!(cfg
            .add_rule(Rule {
                name: "good-allow".into(),
                match_: Match {
                    command: Some("op".into()),
                    subcommand: Some("account".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Allow,
                    source: String::new(),
                    lease: LeasePolicy::RunOnce,
                    timeout_sec: None,
                },
            })
            .is_ok());
    }
}
