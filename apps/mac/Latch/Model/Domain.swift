//  Domain.swift
//  App-facing domain types. These mirror the phone app's src/domain/types.ts and
//  the daemon's local protocol (crates/latch/src/local.rs, daemon.rs, lease.rs)
//  so both surfaces speak one vocabulary. The Mac stores names and metadata,
//  never secret values.

import Foundation

// MARK: - Status / doctor

/// The single approving factor the daemon would gate with. Resolution order,
/// from cli.rs cmd_status/cmd_doctor: paired phone > biometric > fail closed.
enum Factor: Equatable, Sendable {
    case pairedPhone(relay: String)
    case biometric
    case failClosed

    var tone: StateTone {
        switch self {
        case .pairedPhone, .biometric: return .armed
        case .failClosed: return .warn
        }
    }
    var label: String {
        switch self {
        case .pairedPhone: return "paired phone"
        case .biometric: return "biometric"
        case .failClosed: return "fail closed"
        }
    }
    var detail: String {
        switch self {
        case .pairedPhone(let relay): return "via \(relay)"
        case .biometric: return "hardware Touch ID (Secure Enclave)"
        case .failClosed: return "no factor; run: sigil pair"
        }
    }
}

/// The shim's health on PATH, including drift (installed but not winning, or
/// pointing at a stale binary). Mirrors paths::ShimStatus.
struct ShimState: Equatable, Sendable {
    enum Kind: Equatable, Sendable { case healthy, drift, notInstalled, unknown }
    var kind: Kind
    /// Where the shim is (or would be), e.g. ~/.sigil/bin/op.
    var path: String?
    /// A single drift line when not healthy, e.g. "another op wins on PATH".
    var issue: String?

    var tone: StateTone { kind == .healthy ? .armed : .warn }
    var word: String {
        switch kind {
        case .healthy: return "on PATH"
        case .drift: return "drift"
        case .notInstalled: return "not installed"
        case .unknown: return "unknown"
        }
    }
}

/// A single row of the status panel (daemon, shim, op, accounts, factor, relay).
struct StatusReport: Equatable, Sendable {
    var daemonUp: Bool
    var socketPath: String
    var shim: ShimState
    var opFound: Bool
    var opPath: String?
    var accountCount: Int
    var factor: Factor
    /// Present only when a pairing names a relay; nil means "not applicable".
    var relayReachable: Bool?
    var relayURL: String?

    /// The coarse arm state that drives the menubar and the header word.
    var armState: ArmState {
        if lockedDown { return .lockedDown }
        if !daemonUp { return .idle }
        switch factor {
        case .failClosed: return .idle
        default: return .armed
        }
    }
    var lockedDown: Bool = false
}

enum ArmState: Equatable, Sendable {
    case idle, armed, lockedDown

    var menubar: MenubarState {
        switch self {
        case .idle: return .idle
        case .armed: return .armed
        case .lockedDown: return .locked
        }
    }
}

// MARK: - Accounts

enum TokenHealth: String, Sendable { case healthy, rotate, expiring }

/// A configured secret source's provider. The daemon's provider registry
/// (crates/latch/src/provider.rs) is built to take more without changing this
/// shape; 1Password is provider #1, not the product, so this list is not
/// exhaustive on principle. Two ship today.
enum SourceProvider: String, Sendable, Equatable, CaseIterable, Identifiable {
    case onePassword = "1password"
    case envFile = "env-file"

    var id: String { rawValue }
    var displayName: String {
        switch self {
        case .onePassword: return "1Password"
        case .envFile: return "Env file"
        }
    }
}

/// One configured secret source. Mirrors the CLI's own `Source` shape
/// (crates/latch/src/config.rs): one struct, provider-specific fields present
/// or absent depending on `provider`, rather than a separate type per
/// provider. 1Password sources carry a stored credential (vaults, health,
/// rotation); env-file sources carry a file path and none of that, since there
/// is no credential to rotate or vault to probe.
struct Account: Identifiable, Equatable, Sendable {
    let id: String
    var label: String
    var provider: SourceProvider = .onePassword
    /// 1Password only: vaults the token can route to (probed live at add
    /// time). Empty is a warning state: service accounts cannot see built-in
    /// Personal/Shared. Always empty for env-file.
    var vaults: [String] = []
    var health: TokenHealth = .healthy
    var detail: String?
    var lastUsedAt: Date?
    /// env-file only: the KEY=VALUE file this source injects from.
    var path: String?
}

/// What the add sheet collected, already shaped for its provider: 1Password
/// stores a credential (`sigil-config account add`), env-file just names a
/// source (`sigil-config source add --provider env-file`). Keeping this a
/// draft-per-provider enum (rather than one struct with optional fields)
/// means a new provider's add flow cannot forget to handle its own fields.
enum AccountDraft: Sendable {
    case onePassword(label: String, token: String)
    case envFile(name: String, path: String)
}

// MARK: - Leases

/// An active session lease. Mirrors lease::LeaseInfo (grant_hex, account, scope,
/// remaining, age). The Mac renders a live countdown to `expiresAt`.
struct Lease: Identifiable, Equatable, Sendable {
    var id: String { grantHex }
    let grantHex: String
    var caller: String
    var account: String
    var scope: String
    var grantedAt: Date
    var expiresAt: Date

    func remaining(now: Date) -> TimeInterval { max(0, expiresAt.timeIntervalSince(now)) }
}

// MARK: - History (audit)

enum Decision: String, Sendable, Equatable { case approved, denied, expired }

enum RequestKind: String, Sendable, Equatable {
    case secretRead = "secret_read"
    case sshSignature = "ssh_signature"
    case resume
    case lockdownClear = "lockdown_clear"
}

struct HistoryEntry: Identifiable, Equatable, Sendable {
    let id: String
    var kind: RequestKind
    /// "Engineering/.env > graphql-api" or "github-deploy -> git@github.com".
    var label: String
    var account: String
    var process: String
    var cwd: String
    var decision: Decision
    /// Empty for approvals; the reason line for denials.
    var note: String?
    var at: Date
    /// How it was decided: "phone", "biometric", "lease", "rule".
    var via: String
}

// MARK: - Pending requests (the approval sheet / menubar)

enum RiskLevel: String, Sendable, Equatable { case routine, elevated, critical }

struct SecretRef: Equatable, Sendable {
    var provider: String
    /// Display-only path segments, most-general first.
    var segments: [String]
    var label: String
}

struct SshChallenge: Equatable, Sendable {
    var keyLabel: String
    var host: String
    var fingerprint: String
}

struct Provenance: Equatable, Sendable {
    /// Root-first, e.g. ["zsh", "claude", "op"].
    var processChain: [String]
    var cwd: String
    var machine: String
    var requestedAt: Date
}

/// A request waiting on a decision. Mirrors protocol ApprovalRequest; the Mac
/// only ever renders it, never reads a secret value.
struct PendingRequest: Identifiable, Equatable, Sendable {
    let id: String
    var kind: RequestKind
    var command: [String]
    var secrets: [SecretRef]
    var ssh: SshChallenge?
    var provenance: Provenance
    var risk: RiskLevel
    var reason: String?
    var expiresAt: Date
    var timeoutSec: TimeInterval
    /// How many identical requests coalesced behind this one.
    var coalesced: Int = 0

    func remaining(now: Date) -> TimeInterval { max(0, expiresAt.timeIntervalSince(now)) }
    func fraction(now: Date) -> Double {
        guard timeoutSec > 0 else { return 0 }
        return min(1, max(0, remaining(now: now) / timeoutSec))
    }
    /// The brightest display label: item name, or SSH host.
    var title: String {
        if let ssh { return ssh.host }
        return secrets.first?.label ?? command.joined(separator: " ")
    }
}

// MARK: - Pairing

/// Whether local Mac approvals are possible. Hardened mode never mints the Mac
/// Secure Enclave envelope, making the phone strictly required.
enum MacApprovalsMode: Equatable, Sendable {
    case enabled            // a Mac SE envelope exists; Touch ID can approve
    case hardenedPhoneOnly  // no Mac envelope; every approval degrades to phone
}

struct PairedDevice: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    /// The six SAS words agreed at pairing.
    var sasWords: [String]
    var relayURL: String
    var pairedAt: Date
}

/// Live state of the pairing ceremony as the Mac drives it.
enum PairingCeremony: Equatable, Sendable {
    case idle
    /// QR rendered (payload base64), waiting for the phone's response.
    case awaitingPhone(payloadBase64: String)
    /// Phone responded; SAS words to compare on both screens.
    case confirmSAS(words: [String])
    /// Confirmed, DEK delivered, persisted.
    case paired(PairedDevice)
    case failed(reason: String)
}

// MARK: - Settings

struct AppSettings: Equatable, Sendable {
    var approvalTimeoutSec: Int = 120
    var notificationsEnabled: Bool = true
    var historyRetentionDays: Int = 30
    /// "owned endpoint", relay URL, or shared relay.
    var relayURL: String = ""
    var reduceMotion: Bool = false
}
