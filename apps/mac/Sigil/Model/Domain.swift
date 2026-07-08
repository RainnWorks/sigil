//  Domain.swift
//  App-facing domain types. These mirror the phone app's src/domain/types.ts and
//  the daemon's local protocol (crates/sigil/src/local.rs, daemon.rs, lease.rs)
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

/// A single row of the status panel (daemon, shim, op, factor, relay).
struct StatusReport: Equatable, Sendable {
    var daemonUp: Bool
    var socketPath: String
    var shim: ShimState
    var opFound: Bool
    var opPath: String?
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
    /// Whether this request's matched rule permits a session lease. When false
    /// (run-once), a local approver must not offer "approve for N minutes"; the
    /// daemon refuses a lease even if one is asked for.
    var leasable: Bool = false
    /// The per-rule lease cap in seconds when `leasable`; nil for run-once.
    var maxLeaseSecs: Int?
    var reason: String?
    var expiresAt: Date
    var timeoutSec: TimeInterval
    /// How many identical requests coalesced behind this one.
    var coalesced: Int = 0
    /// The phone acknowledged receipt (Sent vs Delivered). Display only: a
    /// missing receipt reads as "couldn't confirm" and never gates the decision.
    var delivered: Bool = false
    var deliveredAt: Date?

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
