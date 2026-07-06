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

    // Accounts (really: configured secret sources — see `Account`, `AccountDraft`)
    func accounts() async throws -> [Account]
    /// Add a source for whichever provider the draft names. 1Password probes
    /// the token's vaults live (empty is the warn case) and returns them on
    /// the result; env-file has no equivalent probe (no credential to test),
    /// so its result just echoes what was configured. The token, for the
    /// 1Password case, never leaves this call.
    func addAccount(_ draft: AccountDraft) async throws -> Account
    /// 1Password only: replace the stored token. Env-file sources have no
    /// token to rotate; the UI does not offer this for them.
    func rotateAccount(id: String, token: String) async throws -> Account
    /// Forget the source. Dispatches to the right backing store for
    /// `account.provider` (the 1Password credential store vs. a named
    /// config source), which is why this takes the whole `Account`.
    func removeAccount(_ account: Account) async throws

    // Leases
    func leases() async throws -> [Lease]
    func revokeLease(grantPrefix: String) async throws -> ControlResult

    // History
    func history() async throws -> [HistoryEntry]

    // Pending requests + decisions (menubar)
    func pending() async throws -> [PendingRequest]
    /// A live feed of the pending set: the current set now, and a fresh snapshot
    /// on every change, until the consumer stops iterating. The socket client
    /// backs this with the daemon's `subscribe_pending` event stream; the default
    /// below polls `pending()` for clients that have no push channel (mock, CLI).
    func subscribePending() -> AsyncStream<[PendingRequest]>
    func approve(id: String, lease: Bool) async throws -> ControlResult
    func deny(id: String) async throws -> ControlResult

    // Daemon-wide controls
    func lockdown(clear: Bool) async throws -> ControlResult

    // Pairing
    func pairedDevice() async throws -> PairedDevice?
    /// Begin the ceremony; the returned stream yields ceremony states as the
    /// phone responds. The app renders the QR and SAS words from these.
    func beginPairing(relayURL: String) -> AsyncStream<PairingCeremony>
    /// The human's decision once the ceremony reaches `.confirmSAS`: this is
    /// the actual MITM backstop, so it must only fire from a real tap after the
    /// six words were compared on both screens. The DEK is not sealed or sent
    /// until `match: true` reaches the ceremony; `false` (or never calling this)
    /// fails it closed. A no-op outside an active `.confirmSAS` state.
    func confirmPairing(match: Bool)
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

extension DaemonClient {
    /// Fallback pending feed for clients without a push channel: poll `pending()`
    /// on a short interval. SocketDaemonClient overrides this with the daemon's
    /// live event stream. Iterating stops the poll (via onTermination).
    func subscribePending() -> AsyncStream<[PendingRequest]> {
        AsyncStream { continuation in
            let task = Task {
                while !Task.isCancelled {
                    if let snapshot = try? await pending() { continuation.yield(snapshot) }
                    try? await Task.sleep(for: .seconds(2))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

/// One doctor row. Mirrors cli.rs `check(label, ok, hint)`.
struct DoctorCheck: Identifiable, Equatable, Sendable {
    var id: String { label }
    var label: String
    var ok: Bool
    var hint: String
}
