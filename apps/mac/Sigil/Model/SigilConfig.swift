//  SigilConfig.swift
//  The if-this-then-that config the daemon reads at arm time: an ordered rule
//  list plus the sources they inject from. This mirrors the CLI's own shapes
//  (crates/sigil/src/config.rs Config/Source/Rule/Match/Action) field-for-field,
//  because the app loads the whole config via `sigil-config export` and writes it
//  back via the `rule`/`source` verbs (or `import`). The engine is provider-blind:
//  `1password` is one provider id among peers, named only inside a source, never
//  special-cased here.
//
//  Only `MatchConfig` needs hand-written Codable: its list conditions serialize
//  with serde `skip_serializing_if = Vec::is_empty`, so they are simply absent
//  from the JSON when empty and must decode back to []. The other structs' fields
//  are always present (or plain optionals), so their synthesized Codable matches
//  the wire shape as-is.

import Foundation

/// The inline `env` provider id. Every rule the app authors owns one of these
/// sources, named after the rule and never shown: it holds the rule's write-once
/// KEY=VALUE environment, sealed under the DEK in the account store, and exposes
/// only its KEY names here. Mirrors `crate::provider::EnvProvider::ID`.
let envProviderID = "env"

/// A named provider configuration a rule injects from. Mirrors `Source`
/// (crates/sigil/src/config.rs). In this app every source is the inline `env`
/// provider: `keys` lists the KEY names whose VALUES were sealed under the DEK
/// (the values are never here, never on the wire the app sees). `account`/`path`
/// are kept only so an older config authored by the CLI still round-trips.
///
/// Hand-written Codable because `keys` serializes with serde
/// `skip_serializing_if = Vec::is_empty` on the Rust side, so it is simply absent
/// when empty and must decode back to []; synthesized Decodable would reject the
/// missing key.
struct SourceConfig: Codable, Sendable, Equatable, Identifiable {
    var name: String
    var provider: String
    var account: String?
    var path: String?
    /// The inline `env` provider's KEY names (never values). Empty for other
    /// providers, and for an env source with nothing sealed yet. An env source
    /// with no sealed record in the threshold store is inert: `export` drops its
    /// keys, so it presents here as a plain gate (empty), never as "set".
    var keys: [String] = []
    /// NON-SECRET env vars the source injects, in cleartext (core's
    /// `Source.plain`). Not editable here yet, but carried through decode and
    /// encode so a save from this app cannot silently delete config the CLI
    /// authored with `sigil-config source env set-plain`.
    var plain: [String: String] = [:]

    var id: String { name }

    enum CodingKeys: String, CodingKey { case name, provider, account, path, keys, plain }

    init(name: String, provider: String, account: String? = nil,
         path: String? = nil, keys: [String] = [], plain: [String: String] = [:]) {
        self.name = name
        self.provider = provider
        self.account = account
        self.path = path
        self.keys = keys
        self.plain = plain
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        provider = try c.decode(String.self, forKey: .provider)
        account = try c.decodeIfPresent(String.self, forKey: .account)
        path = try c.decodeIfPresent(String.self, forKey: .path)
        keys = try c.decodeIfPresent([String].self, forKey: .keys) ?? []
        plain = try c.decodeIfPresent([String: String].self, forKey: .plain) ?? [:]
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(provider, forKey: .provider)
        try c.encodeIfPresent(account, forKey: .account)
        try c.encodeIfPresent(path, forKey: .path)
        if !keys.isEmpty { try c.encode(keys, forKey: .keys) }
        if !plain.isEmpty { try c.encode(plain, forKey: .plain) }
    }
}

/// One `{flag, value}` equality condition, e.g. `--project=prod`. Mirrors `FlagEq`.
struct FlagEqConfig: Codable, Sendable, Equatable, Identifiable {
    var flag: String
    var value: String
    var id: String { "\(flag)=\(value)" }
}

/// Composable match conditions on an invoked command + argv. Every present
/// condition must hold (AND); a match with no conditions never matches (the
/// engine fails closed on an empty rule). Mirrors `Match`.
struct MatchConfig: Codable, Sendable, Equatable {
    /// argv[0] equals this.
    var command: String?
    /// argv[1] equals this.
    var subcommand: String?
    /// Every needle is a substring of some argv token.
    var argvContains: [String] = []
    /// Every listed `--flag` is present.
    var flagPresent: [String] = []
    /// Every `{flag,value}` is present.
    var flagEquals: [FlagEqConfig] = []

    // arg_regex is deferred in core (rejected at `rule add`), so the app never
    // authors it and does not model it here.

    enum CodingKeys: String, CodingKey {
        case command, subcommand
        case argvContains = "argv_contains"
        case flagPresent = "flag_present"
        case flagEquals = "flag_equals"
    }

    init(command: String? = nil, subcommand: String? = nil,
         argvContains: [String] = [], flagPresent: [String] = [],
         flagEquals: [FlagEqConfig] = []) {
        self.command = command
        self.subcommand = subcommand
        self.argvContains = argvContains
        self.flagPresent = flagPresent
        self.flagEquals = flagEquals
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        command = try c.decodeIfPresent(String.self, forKey: .command)
        subcommand = try c.decodeIfPresent(String.self, forKey: .subcommand)
        argvContains = try c.decodeIfPresent([String].self, forKey: .argvContains) ?? []
        flagPresent = try c.decodeIfPresent([String].self, forKey: .flagPresent) ?? []
        flagEquals = try c.decodeIfPresent([FlagEqConfig].self, forKey: .flagEquals) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(command, forKey: .command)
        try c.encodeIfPresent(subcommand, forKey: .subcommand)
        if !argvContains.isEmpty { try c.encode(argvContains, forKey: .argvContains) }
        if !flagPresent.isEmpty { try c.encode(flagPresent, forKey: .flagPresent) }
        if !flagEquals.isEmpty { try c.encode(flagEquals, forKey: .flagEquals) }
    }

    /// Whether this match carries no conditions at all. The engine refuses to
    /// store such a rule (it would fail closed on every command), so the editor
    /// gates Save on the same predicate.
    var isEmpty: Bool {
        command == nil && subcommand == nil
            && argvContains.isEmpty && flagPresent.isEmpty && flagEquals.isEmpty
    }

    /// A short, human summary of the conditions, most-significant first.
    var summary: String {
        var parts: [String] = []
        if let command { parts.append(command) }
        if let subcommand { parts.append(subcommand) }
        parts.append(contentsOf: argvContains)
        parts.append(contentsOf: flagPresent)
        parts.append(contentsOf: flagEquals.map { "\($0.flag)=\($0.value)" })
        return parts.joined(separator: " ")
    }
}

/// Whether a matched command is gated (held for phone approval, then injected)
/// or allowed straight through (a passthrough: run directly, no approval, no
/// injection). Mirrors `RuleMode` (crates/sigil/src/config.rs); serde spells the
/// tags lowercase. The default is `gate`: a missing or unknown mode must gate,
/// never silently pass a command through unapproved.
enum RuleMode: String, Codable, Sendable, Equatable {
    case gate
    case allow
}

/// A gate rule's lease policy: whether one approval may also open a session
/// window, and its cap. Mirrors `LeasePolicy` (crates/sigil-proto), an
/// internally tagged enum: `{"kind":"runOnce"}` (the default, omitted on disk) or
/// `{"kind":"leasable","maxSecs":900}`. Run-once is the safe default: every run
/// needs a fresh approval.
enum LeasePolicyConfig: Codable, Sendable, Equatable {
    case runOnce
    case leasable(maxSecs: Int)

    enum CodingKeys: String, CodingKey { case kind, maxSecs }

    var isRunOnce: Bool { if case .runOnce = self { return true } else { return false } }
    var maxSecs: Int? { if case .leasable(let m) = self { return m } else { return nil } }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "leasable": self = .leasable(maxSecs: try c.decode(Int.self, forKey: .maxSecs))
        default: self = .runOnce
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .runOnce:
            try c.encode("runOnce", forKey: .kind)
        case .leasable(let maxSecs):
            try c.encode("leasable", forKey: .kind)
            try c.encode(maxSecs, forKey: .maxSecs)
        }
    }
}

/// What to do on a match. For a gate rule: hold for phone approval under the
/// lease policy, then inject the named source's environment. For an allow rule:
/// run the command directly, naming no source and carrying no lease. Mirrors
/// `Action`. Hand-written Codable to match core's serde exactly: `mode` is always
/// written; `source` is omitted when empty (an allow rule); `lease` is omitted
/// when run-once (the default); `timeout_sec` is absent when it falls back to the
/// global setting.
struct ActionConfig: Codable, Sendable, Equatable {
    var mode: RuleMode = .gate
    var source: String = ""
    var lease: LeasePolicyConfig = .runOnce
    var timeoutSec: Int?

    enum CodingKeys: String, CodingKey {
        case mode, source, lease
        case timeoutSec = "timeout_sec"
    }

    init(mode: RuleMode = .gate, source: String = "",
         lease: LeasePolicyConfig = .runOnce, timeoutSec: Int? = nil) {
        self.mode = mode
        self.source = source
        self.lease = lease
        self.timeoutSec = timeoutSec
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeIfPresent(RuleMode.self, forKey: .mode) ?? .gate
        source = try c.decodeIfPresent(String.self, forKey: .source) ?? ""
        lease = try c.decodeIfPresent(LeasePolicyConfig.self, forKey: .lease) ?? .runOnce
        timeoutSec = try c.decodeIfPresent(Int.self, forKey: .timeoutSec)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(mode, forKey: .mode)
        if !source.isEmpty { try c.encode(source, forKey: .source) }
        if !lease.isRunOnce { try c.encode(lease, forKey: .lease) }
        try c.encodeIfPresent(timeoutSec, forKey: .timeoutSec)
    }
}

/// One rule: a match paired with the action to take when it holds. Mirrors `Rule`
/// (the `match` field is renamed from `match_` on the wire).
struct RuleConfig: Codable, Sendable, Equatable, Identifiable {
    var name: String
    var match: MatchConfig
    var action: ActionConfig
    var id: String { name }
}

/// The whole config: an ordered rule list plus the sources they reference.
/// Mirrors `Config`. Loaded via `sigil-config export`, replaced via `import`.
struct SigilConfig: Codable, Sendable, Equatable {
    var version: Int = 1
    var sources: [SourceConfig] = []
    var rules: [RuleConfig] = []

    /// The source a rule injects from, resolved by name.
    func source(named name: String) -> SourceConfig? {
        sources.first { $0.name == name }
    }
}

// MARK: - Quick starts

/// A one-tap starting point that pre-fills the command match and suggests the
/// environment KEY names a common tool wants, so the first rule is not a blank
/// form. It creates nothing on its own and names no provider or source: tapping
/// one just opens the editor seeded with a command and some empty VALUE rows the
/// user fills in. Adding one is a new entry in `catalog`, not a new screen.
struct QuickStart: Identifiable, Sendable {
    let id: String
    let title: String
    let subtitle: String
    let symbol: String
    /// argv[0] to match. Empty opens the editor fully blank (the "Any command"
    /// tile) for authoring from scratch.
    let command: String
    /// The environment KEY names to pre-lay as empty (write-only) VALUE rows.
    let suggestedKeys: [String]

    init(id: String, title: String, subtitle: String, symbol: String,
         command: String = "", suggestedKeys: [String] = []) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.symbol = symbol
        self.command = command
        self.suggestedKeys = suggestedKeys
    }

    /// The draft this quick start seeds the editor with.
    func draft() -> RuleDraft {
        var draft = RuleDraft()
        draft.command = command
        draft.env = suggestedKeys.map { EnvRow(key: $0) }
        return draft
    }

    /// The shipped quick starts. `op` leads, presented as one command among peers
    /// (you unlock it *with* Sigil), never as the app's identity.
    static let catalog: [QuickStart] = [
        QuickStart(id: "op",
                   title: "1Password CLI",
                   subtitle: "Gate op on your phone, then hand it its service-account token.",
                   symbol: "key.horizontal",
                   command: "op", suggestedKeys: ["OP_SERVICE_ACCOUNT_TOKEN"]),
        QuickStart(id: "gcloud",
                   title: "gcloud",
                   subtitle: "Gate gcloud and inject its Google Cloud credentials.",
                   symbol: "cloud",
                   command: "gcloud", suggestedKeys: ["GOOGLE_APPLICATION_CREDENTIALS"]),
        QuickStart(id: "aws",
                   title: "AWS CLI",
                   subtitle: "Gate aws and inject its access key.",
                   symbol: "cloud",
                   command: "aws", suggestedKeys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
        QuickStart(id: "custom",
                   title: "Any command",
                   subtitle: "Gate any command and inject the environment you name.",
                   symbol: "wand.and.stars"),
    ]
}

// MARK: - Environment rows

/// One row of a rule's inline environment editor. The KEY is always visible; the
/// VALUE is write-only. A row loaded from an existing rule (`existing == true`)
/// shows a masked placeholder instead of the value the app can never read back;
/// the user may type a replacement (`value` becomes non-empty) or drop the row.
/// A fresh row is a KEY the user is adding now, VALUE and all.
struct EnvRow: Identifiable {
    let id = UUID()
    var key: String
    /// The VALUE the user typed. Empty on an `existing` row means "unchanged".
    var value: String = ""
    /// Whether this KEY is already sealed on the rule's source (loaded from
    /// config), so its stored value is unknown to the app.
    var existing: Bool = false

    init(key: String = "", value: String = "", existing: Bool = false) {
        self.key = key
        self.value = value
        self.existing = existing
    }
}

/// A KEY=VALUE pair on its way to being sealed. The value lives here only for the
/// moment between the editor and the `source env set` call that encrypts it under
/// the DEK, then it is gone.
struct EnvSecret: Sendable, Equatable {
    var key: String
    var value: String
}

// MARK: - Rule draft

/// The editable state behind the rule editor: a command to match and the inline,
/// write-once environment to inject. A rule IS its match; it has no user-facing
/// name. Its config identity (RuleConfig.name) is a unique id the model mints on
/// save so two rules can share a base command, and the backing `env` source is
/// hidden plumbing the model manages, never named here.
struct RuleDraft {
    var command = ""
    var subcommand = ""
    var argvContains: [String] = []
    var flagPresent: [String] = []
    var flagEquals: [FlagEqConfig] = []
    /// The inline environment rows (KEY always shown, VALUE write-only). Only a
    /// gate rule carries an environment; an allow rule injects nothing.
    var env: [EnvRow] = []
    /// Gate (hold for phone approval) or allow (passthrough, no approval). A
    /// brand-new rule defaults to gate, the safe default.
    var mode: RuleMode = .gate
    /// Whether a gate rule may open a session lease. Off (run-once) by default.
    var leasable: Bool = false
    /// The lease cap in seconds when `leasable`. Preserved while toggling run-once
    /// off and on. Defaults to 15 minutes, matching core's DEFAULT_LEASE_MAX_SECS.
    var leaseMaxSecs: Int = 900
    /// Preserved across an edit but not surfaced. nil means "use the global timeout".
    var timeoutSec: Int?

    /// The lease policy this draft would author (meaningful only for a gate rule).
    var leasePolicy: LeasePolicyConfig {
        leasable ? .leasable(maxSecs: leaseMaxSecs) : .runOnce
    }
    /// The config identity of an existing rule, carried across an edit so it stays
    /// stable (never renamed). nil for a brand-new rule (the model mints one).
    var ruleName: String?
    /// The hidden `env` source backing an existing rule, carried across an edit so
    /// its sealed values survive. nil for a brand-new rule (the model allocates one).
    var sourceName: String?

    /// The match this draft would author.
    var match: MatchConfig {
        MatchConfig(
            command: command.trimmed.nilIfEmpty,
            subcommand: subcommand.trimmed.nilIfEmpty,
            argvContains: argvContains.compactMap { $0.trimmed.nilIfEmpty },
            flagPresent: flagPresent.compactMap { $0.trimmed.nilIfEmpty },
            flagEquals: flagEquals.filter { !$0.flag.trimmed.isEmpty }
        )
    }

    init() {}

    /// Seed a draft from an existing rule, for editing in place. The rule's env
    /// source resolves to KEY-only rows (values stay sealed, unknown to the app).
    init(editing rule: RuleConfig, in config: SigilConfig) {
        ruleName = rule.name
        command = rule.match.command ?? ""
        subcommand = rule.match.subcommand ?? ""
        argvContains = rule.match.argvContains
        flagPresent = rule.match.flagPresent
        flagEquals = rule.match.flagEquals
        mode = rule.action.mode
        if let cap = rule.action.lease.maxSecs {
            leasable = true
            leaseMaxSecs = cap
        }
        timeoutSec = rule.action.timeoutSec
        sourceName = rule.action.source.nilIfEmpty
        if let src = config.source(named: rule.action.source) {
            env = src.keys.map { EnvRow(key: $0, existing: true) }
        }
    }
}

// MARK: - Lease duration formatting

/// Human labels and preset caps for a lease window, shared by the rule editor
/// (the cap picker) and the menubar (the "up to Nm" hint on a leasable request).
enum LeaseDuration {
    /// The cap presets offered in the editor, in seconds: 5m, 15m, 30m, 1h, 2h, 4h.
    static let presets: [Int] = [300, 900, 1800, 3600, 7200, 14400]

    /// A terse spelled-out label, e.g. "15 min", "1 hour", "2 hours".
    static func label(_ secs: Int) -> String {
        if secs >= 3600, secs % 3600 == 0 {
            let h = secs / 3600
            return "\(h) \(h == 1 ? "hour" : "hours")"
        }
        let m = max(1, secs / 60)
        return "\(m) min"
    }

    /// A compact label for tight spots, e.g. "15m", "1h".
    static func short(_ secs: Int) -> String {
        if secs >= 3600, secs % 3600 == 0 { return "\(secs / 3600)h" }
        return "\(max(1, secs / 60))m"
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    var nilIfEmpty: String? { isEmpty ? nil : self }
    /// A config-source-name-safe slug, e.g. "Rowm work" -> "rowm-work".
    var sourceSlug: String {
        let lowered = lowercased()
        var out = ""
        var lastDash = false
        for ch in lowered {
            if ch.isLetter || ch.isNumber {
                out.append(ch); lastDash = false
            } else if !lastDash {
                out.append("-"); lastDash = true
            }
        }
        let trimmed = out.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "source" : trimmed
    }
}
