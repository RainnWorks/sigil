//  DaemonClient.swift
//  The seam between the app and the daemon. Everything the GUI does must also be
//  possible headless via the `sigil` CLI, so this protocol is deliberately a
//  thin mirror of the CLI verbs (crates/sigil/src/cli.rs) and the local control
//  protocol (crates/sigil/src/local.rs Frame/Reply).
//
//  Two implementations exist, mirroring how the phone app shipped a mock
//  transport alongside the real one:
//    - MockDaemonClient  — realistic fixtures, every screen and state renders
//                          with no daemon running.
//    - CLIDaemonClient   — shells out to the real `sigil` binary.

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

    // Config (the if-this-then-that rules + the hidden `env` sources they inject
    // from). Loaded whole via `sigil-config export`; authored via the
    // `rule`/`source` verbs; an in-place edit round-trips through `import`
    // (export, mutate the one rule, replace). The daemon only reads this store,
    // so all of it is sigil-config-side, never the always-on daemon.
    func config() async throws -> SigilConfig
    /// `sigil-config source add <name> --provider env`. The app creates one
    /// hidden `env` source per rule to hold its write-once environment.
    func addSource(_ source: SourceConfig) async throws
    /// `sigil-config source remove <name>`. Also purges the source's sealed env
    /// blob. Refuses while a rule references it.
    func removeSource(name: String) async throws
    /// `sigil-config rule add <name> --source … [match flags…] [--risk …] [--timeout …]`.
    func addRule(_ rule: RuleConfig) async throws
    /// `sigil-config rule remove <name>`.
    func removeRule(name: String) async throws
    /// `sigil-config import` (whole config on stdin). Validates referential
    /// integrity before persisting; used for an in-place rule edit.
    func importConfig(_ config: SigilConfig) async throws

    // Inline env values (write-once, never read back). Each pair's VALUE is
    // sealed under the DEK the moment it is set; only its KEY name survives in
    // `config()`. Setting a value unwraps the DEK, so it presents Touch ID.
    /// `sigil-config source env set <name> --stdin` with the KEY=VALUE pairs on
    /// stdin (never argv), sealing every value in one DEK unwrap. An existing KEY
    /// is replaced in place; a new KEY is appended.
    func sealEnv(source: String, secrets: [EnvSecret]) async throws
    /// `sigil-config source env unset <name> --key <KEY>`: drop one sealed KEY.
    func unsealEnv(source: String, key: String) async throws

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
