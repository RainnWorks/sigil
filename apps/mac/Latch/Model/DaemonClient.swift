//  DaemonClient.swift
//  The seam between the app and the daemon. Everything the GUI does must also be
//  possible headless via the `latch` CLI, so this protocol is deliberately a
//  thin mirror of the CLI verbs (crates/latch/src/cli.rs) and the local control
//  protocol (crates/latch/src/local.rs Frame/Reply).
//
//  Two implementations exist, mirroring how the phone app shipped a mock
//  transport alongside the real one:
//    - MockDaemonClient  — realistic fixtures, every screen and state renders
//                          with no daemon running.
//    - CLIDaemonClient   — shells out to the real `latch` binary.

import Foundation

/// A decision the app can take on a pending request or the daemon as a whole.
enum ControlResult: Sendable {
    case ok(lines: [String])
    case failed(lines: [String])
}

enum DaemonError: LocalizedError {
    case unreachable(String)
    case cli(String)
    case notImplemented(String)

    var errorDescription: String? {
        switch self {
        case .unreachable(let s): return "daemon unreachable: \(s)"
        case .cli(let s): return s
        case .notImplemented(let s): return s
        }
    }
}

/// The full surface the configurator and menubar drive. All async; a real
/// implementation shells out or opens the unix socket, a mock returns fixtures.
protocol DaemonClient: Sendable {
    // Status / diagnostics
    func status() async throws -> StatusReport
    /// The doctor's ordered checks, each a (label, ok, hint) triple.
    func doctor() async throws -> [DoctorCheck]

    // Accounts
    func accounts() async throws -> [Account]
    /// Add a service-account token. `probeVaults` returns the vaults the token
    /// can route (empty is the warn case). The token never leaves this call.
    func addAccount(label: String, token: String) async throws -> Account
    func rotateAccount(id: String, token: String) async throws -> Account
    func removeAccount(id: String) async throws

    // Leases
    func leases() async throws -> [Lease]
    func revokeLease(grantPrefix: String) async throws -> ControlResult

    // History
    func history() async throws -> [HistoryEntry]

    // Pending requests + decisions (menubar)
    func pending() async throws -> [PendingRequest]
    func approve(id: String, lease: Bool) async throws -> ControlResult
    func deny(id: String) async throws -> ControlResult

    // Daemon-wide controls
    func lockdown(clear: Bool) async throws -> ControlResult

    // Pairing
    func pairedDevice() async throws -> PairedDevice?
    /// Begin the ceremony; the returned stream yields ceremony states as the
    /// phone responds. The app renders the QR and SAS words from these.
    func beginPairing(relayURL: String) -> AsyncStream<PairingCeremony>
    func unpair() async throws -> ControlResult
    /// Toggle whether the Mac Secure Enclave envelope exists (Enable Mac
    /// approvals) vs hardened phone-only.
    func setMacApprovals(_ mode: MacApprovalsMode) async throws

    // Shim
    func installShim() async throws -> ControlResult

    // Settings
    func settings() async throws -> AppSettings
    func saveSettings(_ settings: AppSettings) async throws
    func wipe() async throws -> ControlResult
}

/// One doctor row. Mirrors cli.rs `check(label, ok, hint)`.
struct DoctorCheck: Identifiable, Equatable, Sendable {
    var id: String { label }
    var label: String
    var ok: Bool
    var hint: String
}
