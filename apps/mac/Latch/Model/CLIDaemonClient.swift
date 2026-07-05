//  CLIDaemonClient.swift
//  Drives the `latch` binary the same way a human would from a shell. Its live
//  role is the shell-out half of SocketDaemonClient: the CLI-only keystore/config
//  mutations that the least-privilege split (PROTOCOL.md) keeps out of the daemon
//  — account add/rotate/remove + list, settings, wipe, mac-approvals, shim
//  install, unpair, and the pairing NDJSON ceremony. Those `--json` shapes are
//  specified in crates/latch/JSON.md.
//
//  It still conforms to the full DaemonClient (its status/doctor/leases/history/
//  pending/control verbs shell out too) so it remains a usable headless client on
//  its own, but the shipping app reaches the daemon's report/control verbs over
//  the socket via SocketDaemonClient — the read DTOs below (StatusDTO, CheckDTO,
//  LeaseDTO, HistoryDTO, PendingDTO) are shared by both so the wire shape is
//  decoded in exactly one place.
//
//  `latch <cmd> --json` outputs (stdout, one JSON value, no ANSI):
//
//    latch status --json
//      { "daemon_up": bool, "socket": str, "shim": {"kind": "healthy|drift|not_installed|unknown",
//        "path": str?, "issue": str?}, "op": {"found": bool, "path": str?},
//        "accounts": int, "factor": {"kind":"phone|biometric|fail_closed","relay":str?},
//        "relay_reachable": bool?, "relay_url": str?, "locked_down": bool }
//    latch doctor --json   -> [ {"label": str, "ok": bool, "hint": str}, ... ]
//    latch account list --json -> [ {"id":str,"label":str,"vaults":[str],
//        "health":"healthy|rotate|expiring","detail":str?,"last_used_ms":int?}, ... ]
//    latch account add --token-stdin --label <l> --json
//        -> {"id":str,"label":str,"vaults":[str],"health":str,"detail":str?}
//    latch account rotate --id <id> --token-stdin --json -> (same account shape)
//    latch account remove --id <id> --json -> {"ok":bool,"lines":[str]}
//    latch lease list --json -> [ {"grant_hex":str,"caller":str,"account":str,
//        "scope":str,"granted_ms":int,"expires_ms":int}, ... ]
//    latch lease revoke <prefix> --json -> {"ok":bool,"lines":[str]}
//    latch history --json -> [ {"id":str,"kind":str,"label":str,"account":str,
//        "process":str,"cwd":str,"decision":"approved|denied|expired","note":str?,
//        "at_ms":int,"via":str}, ... ]     (NEW verb; the CLI has no `history` yet)
//    latch pending --json -> [ ApprovalRequest-shaped, with expires_ms/timeout_ms ]
//        (NEW verb; menubar needs to enumerate what the daemon is holding)
//    latch approve --local --id <id> [--lease] --json -> {"ok":bool,"lines":[str]}
//    latch deny --local --id <id> --json -> {"ok":bool,"lines":[str]}
//    latch lockdown [--clear] --json -> {"ok":bool,"lines":[str]}
//    latch pair list --json -> {"paired": {"name":str,"sas_words":[str],
//        "relay_url":str,"paired_ms":int} | null }
//    latch pair --relay <url> --json  (streams NDJSON ceremony events on stdout:
//        {"event":"qr","payload_b64":str}
//        {"event":"sas","words":[str]}
//        {"event":"paired","name":str,"sas_words":[str],"relay_url":str,"paired_ms":int}
//        {"event":"failed","reason":str} )   (NEW: the CLI is interactive today)
//    latch unpair --json -> {"ok":bool,"lines":[str]}
//    latch mac-approvals --enable|--phone-only --json -> {"ok":bool}  (NEW verb;
//        mints or drops the Mac Secure Enclave envelope. Pairs with the SE seam.)
//    latch shim install --json -> {"ok":bool,"lines":[str]}
//    latch settings get --json / latch settings set --json <patch>  (NEW verbs)
//    latch wipe --json -> {"ok":bool,"lines":[str]}

import Foundation

/// Drives the `latch` binary. `binaryURL` defaults to a PATH lookup; the app can
/// override it (Settings) if the user installed it somewhere non-standard.
struct CLIDaemonClient: DaemonClient {
    var binaryURL: URL

    init(binaryURL: URL? = nil) {
        self.binaryURL = binaryURL ?? CLIDaemonClient.resolveLatch()
    }

    // MARK: run

    /// Run `latch <args>`, optionally feeding `stdin`, returning stdout data.
    /// Throws DaemonError on non-zero exit or spawn failure.
    private func run(_ args: [String], stdin: Data? = nil) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            let proc = Process()
            proc.executableURL = binaryURL
            proc.arguments = args
            // Ensure the shim-first PATH so `latch` finds the real `op` and its
            // own socket the same way an interactive shell would.
            var env = ProcessInfo.processInfo.environment
            env["NO_COLOR"] = "1"
            proc.environment = env

            let outPipe = Pipe(), errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe
            if let stdin {
                let inPipe = Pipe()
                proc.standardInput = inPipe
                inPipe.fileHandleForWriting.write(stdin)
                try? inPipe.fileHandleForWriting.close()
            }
            proc.terminationHandler = { p in
                let out = outPipe.fileHandleForReading.readDataToEndOfFile()
                let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                if p.terminationStatus == 0 {
                    cont.resume(returning: out)
                } else {
                    cont.resume(throwing: DaemonError.cli(err.isEmpty ? "latch exited \(p.terminationStatus)" : err.trimmingCharacters(in: .whitespacesAndNewlines)))
                }
            }
            do { try proc.run() }
            catch { cont.resume(throwing: DaemonError.unreachable(String(describing: error))) }
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw DaemonError.cli("could not parse `latch ... --json` output: \(error)") }
    }

    static func resolveLatch() -> URL {
        for candidate in ["\(NSHomeDirectory())/.latch/bin/latch",
                          "/usr/local/bin/latch", "/opt/homebrew/bin/latch"] {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate)
            }
        }
        return URL(fileURLWithPath: "/usr/local/bin/latch")
    }

    // MARK: DaemonClient

    func status() async throws -> StatusReport {
        let dto = try decode(StatusDTO.self, await run(["status", "--json"]))
        return dto.model()
    }

    func doctor() async throws -> [DoctorCheck] {
        let dto = try decode([CheckDTO].self, await run(["doctor", "--json"]))
        return dto.map { DoctorCheck(label: $0.label, ok: $0.ok, hint: $0.hint) }
    }

    func accounts() async throws -> [Account] {
        try decode([AccountDTO].self, await run(["account", "list", "--json"])).map { $0.model() }
    }

    func addAccount(label: String, token: String) async throws -> Account {
        let data = try await run(["account", "add", "--token-stdin", "--label", label, "--json"],
                                 stdin: Data(token.utf8))
        return try decode(AccountDTO.self, data).model()
    }

    func rotateAccount(id: String, token: String) async throws -> Account {
        let data = try await run(["account", "rotate", "--id", id, "--token-stdin", "--json"],
                                 stdin: Data(token.utf8))
        return try decode(AccountDTO.self, data).model()
    }

    func removeAccount(id: String) async throws {
        _ = try await run(["account", "remove", "--id", id, "--json"])
    }

    func leases() async throws -> [Lease] {
        try decode([LeaseDTO].self, await run(["lease", "list", "--json"])).map { $0.model() }
    }

    func revokeLease(grantPrefix: String) async throws -> ControlResult {
        try controlResult(await run(["lease", "revoke", grantPrefix, "--json"]))
    }

    func history() async throws -> [HistoryEntry] {
        try decode([HistoryDTO].self, await run(["history", "--json"])).map { $0.model() }
    }

    func pending() async throws -> [PendingRequest] {
        try decode([PendingDTO].self, await run(["pending", "--json"])).map { $0.model() }
    }

    func approve(id: String, lease: Bool) async throws -> ControlResult {
        var args = ["approve", "--local", "--id", id]
        if lease { args.append("--lease") }
        args.append("--json")
        return try controlResult(await run(args))
    }

    func deny(id: String) async throws -> ControlResult {
        try controlResult(await run(["deny", "--local", "--id", id, "--json"]))
    }

    func lockdown(clear: Bool) async throws -> ControlResult {
        var args = ["lockdown"]
        if clear { args.append("--clear") }
        args.append("--json")
        return try controlResult(await run(args))
    }

    func pairedDevice() async throws -> PairedDevice? {
        let dto = try decode(PairListDTO.self, await run(["pair", "list", "--json"]))
        return dto.paired?.model()
    }

    func beginPairing(relayURL: String) -> AsyncStream<PairingCeremony> {
        AsyncStream { continuation in
            let proc = Process()
            proc.executableURL = binaryURL
            proc.arguments = ["pair", "--relay", relayURL, "--json"]
            var env = ProcessInfo.processInfo.environment
            env["NO_COLOR"] = "1"
            proc.environment = env
            let outPipe = Pipe()
            proc.standardOutput = outPipe
            // Parse the NDJSON ceremony stream line by line.
            let handle = outPipe.fileHandleForReading
            handle.readabilityHandler = { fh in
                let data = fh.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
                for line in text.split(separator: "\n") {
                    guard let event = try? JSONDecoder().decode(CeremonyEventDTO.self, from: Data(line.utf8)) else { continue }
                    if let state = event.state(relayURL: relayURL) { continuation.yield(state) }
                }
            }
            proc.terminationHandler = { _ in
                handle.readabilityHandler = nil
                continuation.finish()
            }
            do { try proc.run() }
            catch {
                continuation.yield(.failed(reason: String(describing: error)))
                continuation.finish()
            }
        }
    }

    func unpair() async throws -> ControlResult { try controlResult(await run(["unpair", "--json"])) }

    func setMacApprovals(_ mode: MacApprovalsMode) async throws {
        let flag = mode == .enabled ? "--enable" : "--phone-only"
        _ = try await run(["mac-approvals", flag, "--json"])
    }

    func installShim() async throws -> ControlResult {
        try controlResult(await run(["shim", "install", "--json"]))
    }

    func settings() async throws -> AppSettings {
        try decode(SettingsDTO.self, await run(["settings", "get", "--json"])).model()
    }

    func saveSettings(_ settings: AppSettings) async throws {
        let patch = try JSONEncoder().encode(SettingsDTO(settings))
        _ = try await run(["settings", "set", "--json"], stdin: patch)
    }

    func wipe() async throws -> ControlResult { try controlResult(await run(["wipe", "--json"])) }

    // MARK: helpers

    private func controlResult(_ data: Data) throws -> ControlResult {
        let dto = try decode(ControlDTO.self, data)
        return dto.ok ? .ok(lines: dto.lines) : .failed(lines: dto.lines)
    }
}

// MARK: - DTOs (the `--json` contract shapes)

private struct ControlDTO: Decodable { let ok: Bool; let lines: [String] }

// Shared with SocketDaemonClient: the socket's Reply.json bodies are these exact
// shapes (crates/latch/src/json.rs), so they are decoded in one place only.
struct StatusDTO: Decodable {
    struct Shim: Decodable { let kind: String; let path: String?; let issue: String? }
    struct Op: Decodable { let found: Bool; let path: String? }
    struct FactorDTO: Decodable { let kind: String; let relay: String? }
    let daemon_up: Bool
    let socket: String
    let shim: Shim
    let op: Op
    let accounts: Int
    let factor: FactorDTO
    let relay_reachable: Bool?
    let relay_url: String?
    let locked_down: Bool

    func model() -> StatusReport {
        let shimKind: ShimState.Kind = switch shim.kind {
        case "healthy": .healthy; case "drift": .drift
        case "not_installed": .notInstalled; default: .unknown
        }
        let f: Factor = switch factor.kind {
        case "phone": .pairedPhone(relay: factor.relay ?? relay_url ?? "relay")
        case "biometric": .biometric
        default: .failClosed
        }
        return StatusReport(daemonUp: daemon_up, socketPath: socket,
                            shim: ShimState(kind: shimKind, path: shim.path, issue: shim.issue),
                            opFound: op.found, opPath: op.path, accountCount: accounts,
                            factor: f, relayReachable: relay_reachable, relayURL: relay_url,
                            lockedDown: locked_down)
    }
}

struct CheckDTO: Decodable { let label: String; let ok: Bool; let hint: String }

private struct AccountDTO: Decodable {
    let id: String; let label: String; let vaults: [String]
    let health: String; let detail: String?; let last_used_ms: Int?
    func model() -> Account {
        Account(id: id, label: label, vaults: vaults,
                health: TokenHealth(rawValue: health) ?? .healthy, detail: detail,
                lastUsedAt: last_used_ms.map { Date(timeIntervalSince1970: Double($0) / 1000) })
    }
}

struct LeaseDTO: Decodable {
    let grant_hex: String; let caller: String; let account: String; let scope: String
    let granted_ms: Int; let expires_ms: Int
    func model() -> Lease {
        Lease(grantHex: grant_hex, caller: caller, account: account, scope: scope,
              grantedAt: Date(timeIntervalSince1970: Double(granted_ms) / 1000),
              expiresAt: Date(timeIntervalSince1970: Double(expires_ms) / 1000))
    }
}

struct HistoryDTO: Decodable {
    let id: String; let kind: String; let label: String; let account: String
    let process: String; let cwd: String; let decision: String; let note: String?
    let at_ms: Int; let via: String
    func model() -> HistoryEntry {
        HistoryEntry(id: id, kind: RequestKind(rawValue: kind) ?? .secretRead, label: label,
                     account: account, process: process, cwd: cwd,
                     decision: Decision(rawValue: decision) ?? .expired, note: note,
                     at: Date(timeIntervalSince1970: Double(at_ms) / 1000), via: via)
    }
}

struct PendingDTO: Decodable {
    struct SecretDTO: Decodable { let provider: String; let segments: [String]; let label: String }
    struct SshDTO: Decodable { let key_label: String; let host: String; let fingerprint: String }
    struct ProvDTO: Decodable { let process_chain: [String]; let cwd: String; let machine: String; let requested_ms: Int }
    let id: String; let kind: String; let command: [String]
    let secrets: [SecretDTO]; let ssh: SshDTO?; let provenance: ProvDTO
    let risk: String; let reason: String?; let expires_ms: Int; let timeout_ms: Int; let coalesced: Int?
    func model() -> PendingRequest {
        PendingRequest(id: id, kind: RequestKind(rawValue: kind) ?? .secretRead, command: command,
                       secrets: secrets.map { SecretRef(provider: $0.provider, segments: $0.segments, label: $0.label) },
                       ssh: ssh.map { SshChallenge(keyLabel: $0.key_label, host: $0.host, fingerprint: $0.fingerprint) },
                       provenance: Provenance(processChain: provenance.process_chain, cwd: provenance.cwd,
                                              machine: provenance.machine,
                                              requestedAt: Date(timeIntervalSince1970: Double(provenance.requested_ms) / 1000)),
                       risk: RiskLevel(rawValue: risk) ?? .routine, reason: reason,
                       expiresAt: Date(timeIntervalSince1970: Double(expires_ms) / 1000),
                       timeoutSec: Double(timeout_ms) / 1000, coalesced: coalesced ?? 0)
    }
}

private struct PairListDTO: Decodable {
    struct Paired: Decodable {
        let name: String; let sas_words: [String]; let relay_url: String; let paired_ms: Int
        func model() -> PairedDevice {
            PairedDevice(id: "phone", name: name, sasWords: sas_words, relayURL: relay_url,
                         pairedAt: Date(timeIntervalSince1970: Double(paired_ms) / 1000))
        }
    }
    let paired: Paired?
}

private struct CeremonyEventDTO: Decodable {
    let event: String
    let payload_b64: String?
    let words: [String]?
    let name: String?
    let sas_words: [String]?
    let relay_url: String?
    let paired_ms: Int?
    let reason: String?
    func state(relayURL: String) -> PairingCeremony? {
        switch event {
        case "qr": return payload_b64.map { .awaitingPhone(payloadBase64: $0) }
        case "sas": return words.map { .confirmSAS(words: $0) }
        case "paired":
            return .paired(PairedDevice(id: "phone", name: name ?? "iPhone",
                                        sasWords: sas_words ?? [], relayURL: relay_url ?? relayURL,
                                        pairedAt: paired_ms.map { Date(timeIntervalSince1970: Double($0) / 1000) } ?? Date()))
        case "failed": return .failed(reason: reason ?? "pairing failed")
        default: return nil
        }
    }
}

private struct SettingsDTO: Codable {
    let approval_timeout_sec: Int; let notifications: Bool; let retention_days: Int
    let relay_url: String; let reduce_motion: Bool
    init(_ s: AppSettings) {
        approval_timeout_sec = s.approvalTimeoutSec; notifications = s.notificationsEnabled
        retention_days = s.historyRetentionDays; relay_url = s.relayURL; reduce_motion = s.reduceMotion
    }
    func model() -> AppSettings {
        AppSettings(approvalTimeoutSec: approval_timeout_sec, notificationsEnabled: notifications,
                    historyRetentionDays: retention_days, relayURL: relay_url, reduceMotion: reduce_motion)
    }
}
