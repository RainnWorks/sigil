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

/// A named provider configuration a rule injects from. Mirrors `Source`: one
/// struct, provider-specific fields present or absent by `provider`. `account`
/// routes a 1Password credential (by its label); `path` names an env-file.
struct SourceConfig: Codable, Sendable, Equatable, Identifiable {
    var name: String
    var provider: String
    var account: String?
    var path: String?

    var id: String { name }

    /// The provider as the app's enum, when it is one the app knows how to show.
    var knownProvider: SourceProvider? { SourceProvider(rawValue: provider) }

    /// A one-line human description of where this source's secrets come from.
    var origin: String {
        if let path { return path }
        if let account { return account }
        return provider
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

/// What to do on a match: gate under a risk policy, then inject the named
/// source's environment. Mirrors `Action`. `risk` is always serialized by core;
/// `timeout_sec` is absent when it falls back to the global setting.
struct ActionConfig: Codable, Sendable, Equatable {
    var source: String
    var risk: String = RiskLevel.routine.rawValue
    var timeoutSec: Int?

    enum CodingKeys: String, CodingKey {
        case source, risk
        case timeoutSec = "timeout_sec"
    }

    var riskLevel: RiskLevel { RiskLevel(rawValue: risk) ?? .routine }
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

// MARK: - Recipes

/// A one-click starting point that lays down a sane source + rule for a common
/// tool, so the first rule is never hand-authored from a blank form. Data-driven
/// on purpose: adding a recipe is a new entry in `catalog`, not a new screen.
/// Clicking a recipe opens the rule editor pre-filled with these defaults, where
/// the user confirms or tweaks which source, risk, and match before saving.
struct Recipe: Identifiable, Sendable {
    let id: String
    let title: String
    let subtitle: String
    let symbol: String
    /// The kind of source this recipe injects from. The editor pins the source
    /// picker to this provider (or, for `.custom`, offers the full picker).
    let provider: SourceProvider
    /// Default argv[0] to match. Empty means "you name the command" (the editor
    /// leaves the field blank and required).
    let command: String
    let subcommand: String?
    let argvContains: [String]
    let risk: RiskLevel
    /// When true the recipe imposes no provider or command, opening the editor
    /// fully blank for authoring any tool from scratch.
    let custom: Bool

    init(id: String, title: String, subtitle: String, symbol: String,
         provider: SourceProvider = .envFile, command: String = "",
         subcommand: String? = nil, argvContains: [String] = [],
         risk: RiskLevel = .routine, custom: Bool = false) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.symbol = symbol
        self.provider = provider
        self.command = command
        self.subcommand = subcommand
        self.argvContains = argvContains
        self.risk = risk
        self.custom = custom
    }

    /// The starting draft this recipe seeds the editor with.
    func draft() -> RuleDraft {
        var draft = RuleDraft()
        draft.name = command.isEmpty ? id : command
        draft.command = command
        draft.subcommand = subcommand ?? ""
        draft.argvContains = argvContains
        draft.risk = risk
        draft.provider = provider
        draft.custom = custom
        return draft
    }

    /// The shipped recipes. 1Password is the first entry, presented as one tool
    /// among peers, never as the app's identity.
    static let catalog: [Recipe] = [
        Recipe(id: "1Password CLI",
               title: "1Password CLI",
               subtitle: "Gate op on your phone before any secret is read.",
               symbol: "key.horizontal",
               provider: .onePassword, command: "op", risk: .routine),
        Recipe(id: "gcloud",
               title: "gcloud",
               subtitle: "Inject Google Cloud credentials from an env file when gcloud runs.",
               symbol: "cloud",
               provider: .envFile, command: "gcloud", risk: .elevated),
        Recipe(id: "AWS CLI",
               title: "AWS CLI",
               subtitle: "Inject AWS credentials from an env file when aws runs.",
               symbol: "cloud",
               provider: .envFile, command: "aws", risk: .elevated),
        // No SSH recipe yet: SSH signing is a separate first-class flow (the
        // phone-gated ssh-agent, RequestKind.sshSignature), not an env-file
        // injection, so there is no honest source a recipe could name here until
        // an ssh-agent source provider exists.
        Recipe(id: "Env file",
               title: "Env file",
               subtitle: "Inject a KEY=VALUE file into any command you name.",
               symbol: "doc.text",
               provider: .envFile, command: "", risk: .routine),
        Recipe(id: "Any command",
               title: "Any command",
               subtitle: "Author a rule from scratch for any tool, any provider.",
               symbol: "wand.and.stars",
               provider: .envFile, command: "", risk: .routine, custom: true),
    ]
}

/// The editable state behind the rule editor. Kept provider-blind: it names a
/// command to match and a source to inject from, never anything 1Password-shaped.
struct RuleDraft {
    var name = ""
    var command = ""
    var subcommand = ""
    var argvContains: [String] = []
    var flagPresent: [String] = []
    var flagEquals: [FlagEqConfig] = []
    var risk: RiskLevel = .routine
    /// nil means "use the global timeout".
    var timeoutSec: Int?
    /// The source picker's selection: the id of the chosen ingredient (a config
    /// source name, or a 1Password credential label). Empty until chosen.
    var sourceKey = ""
    /// The provider this draft's source must be. Recipes pin it; the custom
    /// path lets the picker span providers.
    var provider: SourceProvider = .envFile
    /// Whether the provider may be chosen freely (the "Any command" recipe).
    var custom = false

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

    /// Seed a draft from an existing rule, for editing in place.
    init() {}

    init(editing rule: RuleConfig, in config: SigilConfig, ingredients: [Account]) {
        name = rule.name
        command = rule.match.command ?? ""
        subcommand = rule.match.subcommand ?? ""
        argvContains = rule.match.argvContains
        flagPresent = rule.match.flagPresent
        flagEquals = rule.match.flagEquals
        risk = rule.action.riskLevel
        timeoutSec = rule.action.timeoutSec
        // Resolve the rule's config source back to a picker key: an env-file
        // source keys on its own name; a 1Password source keys on the credential
        // label it routes, so the picker lands on the same ingredient. Editing
        // pins the provider to the rule's own (custom = false) so the source
        // picker stays within it; silently repointing an op gate at an env file is
        // not something a rule edit should allow. A cross-provider change is a
        // deliberate remove-and-recreate.
        if let src = config.source(named: rule.action.source) {
            provider = src.knownProvider ?? .envFile
            custom = false
            switch src.knownProvider {
            case .onePassword: sourceKey = src.account ?? src.name
            default: sourceKey = src.name
            }
        }
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
