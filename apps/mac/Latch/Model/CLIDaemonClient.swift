//  CLIDaemonClient.swift
//  Drives the `sigil` binary the same way a human would from a shell. Its live
//  role is the shell-out half of SocketDaemonClient: the CLI-only keystore/config
//  mutations that the least-privilege split (PROTOCOL.md) keeps out of the daemon
//  — account add/rotate/remove + list, settings, wipe, mac-approvals, shim
//  install, unpair, and the pairing NDJSON ceremony. Those `--json` shapes are
//  specified in crates/sigil/JSON.md.
//
//  It still conforms to the full DaemonClient (its status/doctor/leases/history/
//  pending/control verbs shell out too) so it remains a usable headless client on
//  its own, but the shipping app reaches the daemon's report/control verbs over
//  the socket via SocketDaemonClient — the read DTOs below (StatusDTO, CheckDTO,
//  LeaseDTO, HistoryDTO, PendingDTO) are shared by both so the wire shape is
//  decoded in exactly one place.
//
//  `sigil <cmd> --json` outputs (stdout, one JSON value, no ANSI). The v4
//  rework split configuration mutation into a second binary, `sigil-config`
//  (task #42): account/settings/mac-approvals/wipe live there now, so the
//  runtime/pairing verbs below run against `binaryURL` (`run`) and the config
//  verbs run against `configBinaryURL` (`runConfig`) — see `resolveSigilConfig`.
//
//    sigil status --json
//      { "daemon_up": bool, "socket": str, "shim": {"kind": "healthy|drift|not_installed|unknown",
//        "path": str?, "issue": str?}, "op": {"found": bool, "path": str?},
//        "accounts": int, "factor": {"kind":"phone|biometric|fail_closed","relay":str?},
//        "relay_reachable": bool?, "relay_url": str?, "locked_down": bool }
//    sigil doctor --json   -> [ {"label": str, "ok": bool, "hint": str}, ... ]
//    sigil-config export -> {version, sources:[{name,provider,account?,path?,
//        keys?:[str]}], rules:[...]}   (the whole config; env sources carry KEY
//        names only, never values)
//    sigil-config source add <name> --provider env --json -> {"ok":bool,"lines":[str]}
//    sigil-config source remove <name> --json -> {"ok":bool,"lines":[str]}
//    sigil-config source env set <name> --stdin --json   (KEY=VALUE lines on
//        stdin, sealed under the DEK) -> {"ok":bool,"lines":[str]}
//    sigil-config source env unset <name> --key <KEY> --json -> {"ok":bool,"lines":[str]}
//    sigil lease list --json -> [ {"grant_hex":str,"caller":str,"account":str,
//        "scope":str,"granted_ms":int,"expires_ms":int}, ... ]
//    sigil lease revoke <prefix> --json -> {"ok":bool,"lines":[str]}
//    sigil history --json -> [ {"id":str,"kind":str,"label":str,"account":str,
//        "process":str,"cwd":str,"decision":"approved|denied|expired","note":str?,
//        "at_ms":int,"via":str}, ... ]     (NEW verb; the CLI has no `history` yet)
//    sigil pending --json -> [ ApprovalRequest-shaped, with expires_ms/timeout_ms ]
//        (NEW verb; menubar needs to enumerate what the daemon is holding)
//    sigil approve --local --id <id> [--lease] --json -> {"ok":bool,"lines":[str]}
//    sigil deny --local --id <id> --json -> {"ok":bool,"lines":[str]}
//    sigil lockdown [--clear] --json -> {"ok":bool,"lines":[str]}
//    sigil pair list --json -> {"paired": {"name":str,"sas_words":[str],
//        "relay_url":str,"paired_ms":int} | null }
//    sigil pair --relay <url> --json  (streams NDJSON ceremony events on stdout:
//        {"event":"qr","payload_b64":str}
//        {"event":"sas","words":[str]}
//        {"event":"paired","name":str,"sas_words":[str],"relay_url":str,"paired_ms":int}
//        {"event":"failed","reason":str} )   after "sas", the ceremony blocks on
//        one line of our stdin and proceeds only if it reads "confirm" — see
//        `confirmPairing(match:)`.
//    sigil unpair --json -> {"ok":bool,"lines":[str]}
//    sigil-config mac-approvals --enable|--phone-only --json -> {"ok":bool}
//        (mints or drops the Mac Secure Enclave envelope. Pairs with the SE seam.)
//    sigil shim install --json -> {"ok":bool,"lines":[str]}
//    sigil-config settings get --json / sigil-config settings set --json <patch>
//    sigil-config wipe --force --json -> {"ok":bool,"lines":[str]}

import Foundation

/// Drives the `sigil` binary. `binaryURL` defaults to a PATH lookup; the app can
/// override it (Settings) if the user installed it somewhere non-standard.
struct CLIDaemonClient: DaemonClient {
    var binaryURL: URL
    /// `sigil-config`, the sibling binary the v4 rework split config mutation
    /// into (task #42): account/settings/mac-approvals/wipe. Resolved next to
    /// `binaryURL` since the two ship together.
    var configBinaryURL: URL
    /// The stdin pipe of the currently running `pair --json` ceremony (if any),
    /// so `confirmPairing` can reach it. A class because `CLIDaemonClient` is a
    /// value type but `beginPairing` and `confirmPairing` are called on the same
    /// instance (held once by AppModel) and must share this across the calls.
    private let pairingStdin = PairingStdin()

    init(binaryURL: URL? = nil) {
        let sigil = binaryURL ?? CLIDaemonClient.resolveSigil()
        self.binaryURL = sigil
        self.configBinaryURL = CLIDaemonClient.resolveSigilConfig(besideSigil: sigil)
    }

    /// Environment for every `sigil` invocation. `SIGIL_DEV_KEYSTORE=file` is
    /// temporary: until the Secure Enclave DEK wrap is wired into the daemon
    /// (task #24), the real keystore dies with "secure enclave path not yet
    /// verified on hardware", so pairing and account mutations need the
    /// dev file-backed keystore to run at all. `OP_SERVICE_ACCOUNT_TOKEN`, if
    /// present in the app's own environment, already passes through via
    /// ProcessInfo — nothing extra to do for it.
    private static func env() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["NO_COLOR"] = "1"
        env["SIGIL_DEV_KEYSTORE"] = "file"
        return env
    }

    // MARK: run

    /// Spawn `binary <args>`, optionally feeding `stdin`, returning stdout data.
    /// Throws DaemonError on non-zero exit or spawn failure. Shared by `run`
    /// (the `sigil` binary) and `runConfig` (`sigil-config`).
    private func execute(_ binary: URL, _ args: [String], stdin: Data? = nil) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            let proc = Process()
            proc.executableURL = binary
            proc.arguments = args
            // Ensure the shim-first PATH so `sigil` finds the real `op` and its
            // own socket the same way an interactive shell would.
            proc.environment = Self.env()

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
                    // Some refusals (`wipe` without --force, `source remove` on
                    // a name a rule still references) print a normal control
                    // body - {"ok":false,"lines":[...]} - to STDOUT rather than
                    // stderr, with the non-zero exit standing in for "did not
                    // happen." Prefer that real reason over the generic
                    // fallback whenever stdout actually decodes as one; this is
                    // the one seam every CLI-driven error surface goes through,
                    // so fixing it here (rather than per call site) covers
                    // every refusal shaped like this at once.
                    if let dto = try? JSONDecoder().decode(ControlDTO.self, from: out), !dto.ok {
                        cont.resume(throwing: DaemonError.cli(dto.lines.joined(separator: "; ")))
                    } else {
                        cont.resume(throwing: DaemonError.cli(err.isEmpty ? "\(binary.lastPathComponent) exited \(p.terminationStatus)" : err.trimmingCharacters(in: .whitespacesAndNewlines)))
                    }
                }
            }
            do { try proc.run() }
            catch { cont.resume(throwing: DaemonError.unreachable("could not launch \(binary.lastPathComponent)")) }
        }
    }

    /// Run `sigil <args>` (runtime/pairing verbs).
    private func run(_ args: [String], stdin: Data? = nil) async throws -> Data {
        try await execute(binaryURL, args, stdin: stdin)
    }

    /// Run `sigil-config <args>` (account/settings/mac-approvals/wipe — the
    /// config-mutation verbs the v4 rework split into their own binary).
    private func runConfig(_ args: [String], stdin: Data? = nil) async throws -> Data {
        try await execute(configBinaryURL, args, stdin: stdin)
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw DaemonError.cli("could not parse `sigil ... --json` output: \(error)") }
    }

    static func resolveSigil() -> URL {
        for candidate in ["\(NSHomeDirectory())/.sigil/bin/sigil",
                          "/usr/local/bin/sigil", "/opt/homebrew/bin/sigil"] {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate)
            }
        }
        return URL(fileURLWithPath: "/usr/local/bin/sigil")
    }

    /// `sigil-config` ships next to `sigil`, so try that sibling first; fall
    /// back to the same candidate locations `resolveSigil` checks, in case the
    /// two were installed separately.
    static func resolveSigilConfig(besideSigil sigil: URL) -> URL {
        let sibling = sigil.deletingLastPathComponent().appendingPathComponent("sigil-config")
        if FileManager.default.isExecutableFile(atPath: sibling.path) { return sibling }
        for candidate in ["\(NSHomeDirectory())/.sigil/bin/sigil-config",
                          "/usr/local/bin/sigil-config", "/opt/homebrew/bin/sigil-config"] {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate)
            }
        }
        return sibling
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

    // MARK: config (rules + their hidden env sources)

    /// The whole config as `sigil-config export` emits it (the same JSON `list
    /// --json` prints): `{version, sources:[…], rules:[…]}`.
    func config() async throws -> SigilConfig {
        try decode(SigilConfig.self, await runConfig(["export"]))
    }

    func addSource(_ source: SourceConfig) async throws {
        var args = ["source", "add", source.name, "--provider", source.provider]
        if let account = source.account { args += ["--account", account] }
        if let path = source.path { args += ["--path", path] }
        args.append("--json")
        _ = try await runConfig(args)
    }

    func removeSource(name: String) async throws {
        _ = try await runConfig(["source", "remove", name, "--json"])
    }

    func addRule(_ rule: RuleConfig) async throws {
        var args = ["rule", "add", rule.name, "--source", rule.action.source]
        let m = rule.match
        if let command = m.command { args += ["--command", command] }
        if let subcommand = m.subcommand { args += ["--subcommand", subcommand] }
        for needle in m.argvContains { args += ["--argv-contains", needle] }
        for flag in m.flagPresent { args += ["--flag", flag] }
        for fe in m.flagEquals { args += ["--flag-eq", "\(fe.flag)=\(fe.value)"] }
        args += ["--risk", rule.action.risk]
        if let timeout = rule.action.timeoutSec { args += ["--timeout", String(timeout)] }
        args.append("--json")
        _ = try await runConfig(args)
    }

    func removeRule(name: String) async throws {
        _ = try await runConfig(["rule", "remove", name, "--json"])
    }

    func importConfig(_ config: SigilConfig) async throws {
        let body = try JSONEncoder().encode(config)
        _ = try await runConfig(["import", "--json"], stdin: body)
    }

    /// Seal every pair in one `source env set --stdin` call: the VALUES ride on
    /// stdin as KEY=VALUE lines (never argv, which `ps` would leak), so one DEK
    /// unwrap covers the whole batch. Core takes the VALUE verbatim after the
    /// first `=`, so a value may itself contain `=`.
    func sealEnv(source: String, secrets: [EnvSecret]) async throws {
        let body = secrets.map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
        _ = try await runConfig(["source", "env", "set", source, "--stdin", "--json"],
                                stdin: Data(body.utf8))
    }

    func unsealEnv(source: String, key: String) async throws {
        _ = try await runConfig(["source", "env", "unset", source, "--key", key, "--json"])
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
            proc.environment = Self.env()
            let outPipe = Pipe()
            let inPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardInput = inPipe
            // `confirmPairing` writes into this once the human taps match; cli.rs
            // blocks on it after the "sas" event before it ever seals the DEK.
            pairingStdin.set(inPipe)
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
                pairingStdin.set(nil)
                continuation.finish()
            }
            do { try proc.run() }
            catch {
                pairingStdin.set(nil)
                continuation.yield(.failed(reason: "could not launch \(binaryURL.lastPathComponent)"))
                continuation.finish()
            }
        }
    }

    /// Write the human's SAS decision to the ceremony's stdin. `confirm` is the
    /// only line cli.rs treats as a match; anything else fails the ceremony
    /// closed, so `match: false` is spelled out explicitly rather than sent as
    /// silence (closing the pipe would also work, but a stray zombie process
    /// blocked on stdin should not read as "confirmed").
    func confirmPairing(match: Bool) {
        pairingStdin.send(match ? "confirm" : "reject")
    }

    func unpair() async throws -> ControlResult { try controlResult(await run(["unpair", "--json"])) }

    func setMacApprovals(_ mode: MacApprovalsMode) async throws {
        let flag = mode == .enabled ? "--enable" : "--phone-only"
        _ = try await runConfig(["mac-approvals", flag, "--json"])
    }

    func installShim() async throws -> ControlResult {
        try controlResult(await run(["shim", "install", "--json"]))
    }

    func settings() async throws -> AppSettings {
        try decode(SettingsDTO.self, await runConfig(["settings", "get", "--json"])).model()
    }

    func saveSettings(_ settings: AppSettings) async throws {
        let patch = try JSONEncoder().encode(SettingsDTO(settings))
        _ = try await runConfig(["settings", "set", "--json"], stdin: patch)
    }

    // `--force` here is not a missing confirmation step: SettingsView's own
    // confirmationDialog is the human gate, so by the time this call happens
    // the human already said yes. Without it sigil-config just refuses (exit
    // 1, "refusing to wipe without --force") and this would surface as a
    // thrown error instead of the wipe actually happening.
    func wipe() async throws -> ControlResult { try controlResult(await runConfig(["wipe", "--force", "--json"])) }

    // MARK: helpers

    private func controlResult(_ data: Data) throws -> ControlResult {
        let dto = try decode(ControlDTO.self, data)
        return dto.ok ? .ok(lines: dto.lines) : .failed(lines: dto.lines)
    }
}

/// The stdin pipe of an in-flight `pair --json` ceremony. A class (not a
/// struct field alone) because `CLIDaemonClient` is a value type but the same
/// instance's `beginPairing` and `confirmPairing` calls must share state; the
/// lock is only ever held for a pointer read/write, never around IO.
private final class PairingStdin: @unchecked Sendable {
    private let lock = NSLock()
    private var pipe: Pipe?
    func set(_ p: Pipe?) { lock.lock(); pipe = p; lock.unlock() }
    func send(_ line: String) {
        lock.lock(); let p = pipe; lock.unlock()
        guard let p, let data = "\(line)\n".data(using: .utf8) else { return }
        p.fileHandleForWriting.write(data)
    }
}

// MARK: - DTOs (the `--json` contract shapes)

private struct ControlDTO: Decodable { let ok: Bool; let lines: [String] }

// Shared with SocketDaemonClient: the socket's Reply.json bodies are these exact
// shapes (crates/sigil/src/json.rs), so they are decoded in one place only.
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
                            opFound: op.found, opPath: op.path,
                            factor: f, relayReachable: relay_reachable, relayURL: relay_url,
                            lockedDown: locked_down)
    }
}

struct CheckDTO: Decodable { let label: String; let ok: Bool; let hint: String }

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
