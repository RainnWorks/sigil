//  SocketDaemonClient.swift
//  The real DaemonClient. It speaks the daemon's unix control socket directly for
//  everything the daemon may report or control at runtime (PROTOCOL.md), and
//  shells out to the `sigil` binary only for the keystore/config mutations the
//  least-privilege split keeps out of the daemon (JSON.md).
//
//  There is one interface, two renderers: this client is the second socket client
//  alongside the human `sigil` CLI. The wire is the Frame/Reply protocol in
//  crates/sigil/src/local.rs; the json bodies are the DTOs in crates/sigil/src/
//  json.rs, decoded here by the same structs CLIDaemonClient uses (StatusDTO,
//  CheckDTO, LeaseDTO, HistoryDTO, PendingDTO — shared, not duplicated).
//
//  Split, so the two paths never blur:
//    - Over the socket: status, doctor, lease_list, pending, history (Reply.json);
//      lockdown, lease_revoke, approve, deny (Reply.control); and a long-lived
//      subscribe_pending event stream (Reply.event) that drives the menubar live.
//    - Shelled out to `sigil … --json` via the composed CLIDaemonClient: account
//      add/rotate/remove, account list, settings get/set, wipe, mac-approvals,
//      shim install, unpair, and the pairing NDJSON ceremony. These write the
//      keystore / ~/.sigil and are deliberately not daemon capabilities.
//
//  When the socket is unreachable the read verbs degrade to a calm "daemon not
//  running" state rather than throwing, so the window and menubar render an
//  honest daemon-down status instead of an error wall.

import Foundation

struct SocketDaemonClient: DaemonClient {
    /// The daemon control socket, $SIGIL_SOCK or $TMPDIR/sigil/daemon.sock.
    let socketPath: String
    /// The shell-out half, for the CLI-only keystore/config mutations.
    private let cli: CLIDaemonClient

    /// Off-main queue for the blocking connect/write/read of each round trip.
    /// Concurrent: independent request/reply verbs need not serialise (each opens
    /// its own short-lived connection, as the protocol's one-reply-then-close
    /// verbs expect).
    private static let ioQueue = DispatchQueue(
        label: "works.rainn.sigil.mac.socket", qos: .userInitiated, attributes: .concurrent)

    init(socketPath: String? = nil, cli: CLIDaemonClient = CLIDaemonClient()) {
        self.socketPath = socketPath ?? SocketDaemonClient.defaultSocketPath()
        self.cli = cli
    }

    static func defaultSocketPath() -> String {
        let env = ProcessInfo.processInfo.environment
        if let sock = env["SIGIL_SOCK"], !sock.isEmpty { return sock }
        let tmp = env["TMPDIR"] ?? NSTemporaryDirectory()
        return (tmp as NSString).appendingPathComponent("sigil/daemon.sock")
    }

    // MARK: - Read / report (Reply.json) — degrade to daemon-down, never throw

    func status() async throws -> StatusReport {
        guard let body = try? await jsonRoundTrip(.status),
              let dto = try? Self.decode(StatusDTO.self, body) else {
            return daemonDownStatus()
        }
        return dto.model()
    }

    func doctor() async throws -> [DoctorCheck] {
        guard let body = try? await jsonRoundTrip(.doctor),
              let dtos = try? Self.decode([CheckDTO].self, body) else { return [] }
        return dtos.map { DoctorCheck(label: $0.label, ok: $0.ok, hint: $0.hint) }
    }

    func leases() async throws -> [Lease] {
        guard let body = try? await jsonRoundTrip(.leaseList),
              let dtos = try? Self.decode([LeaseDTO].self, body) else { return [] }
        return dtos.map { $0.model() }
    }

    func history() async throws -> [HistoryEntry] {
        guard let body = try? await jsonRoundTrip(.history),
              let dtos = try? Self.decode([HistoryDTO].self, body) else { return [] }
        return dtos.map { $0.model() }
    }

    func pending() async throws -> [PendingRequest] {
        guard let body = try? await jsonRoundTrip(.pending),
              let dtos = try? Self.decode([PendingDTO].self, body) else { return [] }
        return dtos.map { $0.model() }
    }

    // MARK: - Runtime control (Reply.control)

    func revokeLease(grantPrefix: String) async throws -> ControlResult {
        await control(.leaseRevoke(prefix: grantPrefix))
    }

    func approve(id: String, lease: Bool) async throws -> ControlResult {
        await control(.approve(id: id, lease: lease))
    }

    func deny(id: String) async throws -> ControlResult {
        await control(.deny(id: id))
    }

    func lockdown(clear: Bool) async throws -> ControlResult {
        await control(.lockdown(clear: clear))
    }

    // MARK: - Live pending subscription (Reply.event stream)

    /// One long-lived `subscribe_pending` connection: the daemon writes the
    /// current set immediately and again on every change (plus a keepalive), until
    /// we hang up. Self-healing: if the connection drops or the daemon is down we
    /// surface an empty set and reconnect after a short backoff, so the menubar
    /// stays live across daemon restarts. The stream ends only when its consumer
    /// (AppModel) cancels it.
    func subscribePending() -> AsyncStream<[PendingRequest]> {
        let path = socketPath
        return AsyncStream { continuation in
            let cancel = CancelBox()
            continuation.onTermination = { _ in cancel.cancel() }
            Thread.detachNewThread {
                while !cancel.isCancelled {
                    do {
                        let conn = try UnixSocketConnection(path: path)
                        try conn.writeLine(Self.encodeFrame(.subscribePending))
                        while !cancel.isCancelled, let line = try conn.readLine() {
                            if let snapshot = Self.decodeEventSnapshot(line) {
                                continuation.yield(snapshot)
                            }
                        }
                    } catch {
                        // Daemon down or connection dropped: clear the menubar,
                        // then back off and resubscribe.
                        continuation.yield([])
                    }
                    guard !cancel.isCancelled else { break }
                    Thread.sleep(forTimeInterval: 2)
                }
                continuation.finish()
            }
        }
    }

    // MARK: - Shelled out to `sigil … --json` (keystore / config mutations)

    func config() async throws -> SigilConfig { try await cli.config() }
    func addSource(_ source: SourceConfig) async throws { try await cli.addSource(source) }
    func removeSource(name: String) async throws { try await cli.removeSource(name: name) }
    func addRule(_ rule: RuleConfig) async throws { try await cli.addRule(rule) }
    func removeRule(name: String) async throws { try await cli.removeRule(name: name) }
    func importConfig(_ config: SigilConfig) async throws { try await cli.importConfig(config) }
    func sealEnv(source: String, secrets: [EnvSecret]) async throws {
        try await cli.sealEnv(source: source, secrets: secrets)
    }
    func unsealEnv(source: String, key: String) async throws {
        try await cli.unsealEnv(source: source, key: key)
    }

    func settings() async throws -> AppSettings { try await cli.settings() }
    func saveSettings(_ settings: AppSettings) async throws { try await cli.saveSettings(settings) }
    func wipe() async throws -> ControlResult { try await cli.wipe() }

    func setMacApprovals(_ mode: MacApprovalsMode) async throws { try await cli.setMacApprovals(mode) }
    func installShim() async throws -> ControlResult { try await cli.installShim() }

    // MARK: - Daemon lifecycle
    //
    // `daemonRunning` we answer directly with a connect-probe of our own socket
    // (no round trip, no frame); the start/stop/restart/install verbs and the
    // version/path readouts are keystore-adjacent shell-outs, so they delegate to
    // the CLI half like the other mutations.

    func daemonRunning() async -> Bool { daemonSocketReachable(path: socketPath) }
    func daemonVersion() async -> String? { await cli.daemonVersion() }
    func daemonBinaryPath() -> String? { cli.daemonBinaryPath() }
    func startDaemon() async throws { try await cli.startDaemon() }
    func stopDaemon() async throws { try await cli.stopDaemon() }
    func restartDaemon() async throws { try await cli.restartDaemon() }
    func installDaemon() async throws { try await cli.installDaemon() }

    // SSH agent config: served keys and the managed ~/.ssh/config routing are a
    // keystore-adjacent concern the daemon does not own, so they delegate to the
    // shell-out half like the other config mutations.
    func sshKeys() async throws -> SshKeyStore { try await cli.sshKeys() }
    func addSshOnePasswordKey(vault: String, item: String, field: String,
                              comment: String, hosts: [String], publicKey: String) async throws {
        try await cli.addSshOnePasswordKey(vault: vault, item: item, field: field,
                                           comment: comment, hosts: hosts, publicKey: publicKey)
    }
    func addSshFileKey(path: String, comment: String, hosts: [String]) async throws {
        try await cli.addSshFileKey(path: path, comment: comment, hosts: hosts)
    }
    func removeSshKey(item: String) async throws { try await cli.removeSshKey(item: item) }
    func installSshRouting() async throws { try await cli.installSshRouting() }
    func uninstallSshRouting() async throws { try await cli.uninstallSshRouting() }
    func sshRoutingInstalled() async -> Bool { await cli.sshRoutingInstalled() }
    func generatedSshConfig() async -> String? { await cli.generatedSshConfig() }

    func pairedDevice() async throws -> PairedDevice? { try await cli.pairedDevice() }
    func beginPairing(relayURL: String) -> AsyncStream<PairingCeremony> {
        cli.beginPairing(relayURL: relayURL)
    }
    func confirmPairing(match: Bool) { cli.confirmPairing(match: match) }
    func unpair() async throws -> ControlResult { try await cli.unpair() }

    // MARK: - Socket round trips

    /// Send one Frame, read the single reply line, and unwrap its `json` body.
    /// Throws on connect/io failure so the read callers can degrade.
    private func jsonRoundTrip(_ frame: Frame) async throws -> Data {
        let line = try await roundTrip(frame)
        return try Self.jsonBody(line)
    }

    /// Send one control Frame and map the `{ok,lines}` reply. Connect/io failures
    /// become a `.failed` result naming the daemon-down cause rather than a throw,
    /// so the caller can show the reason lines.
    private func control(_ frame: Frame) async -> ControlResult {
        do {
            let line = try await roundTrip(frame)
            let reply = try Self.decode(ReplyEnvelope.self, line)
            guard reply.kind == "control" else {
                return .failed(lines: ["unexpected reply: \(reply.kind)"])
            }
            return (reply.ok ?? false)
                ? .ok(lines: reply.lines ?? [])
                : .failed(lines: reply.lines ?? ["refused"])
        } catch let error as SocketError {
            return .failed(lines: ["daemon not running", error.detail])
        } catch {
            return .failed(lines: [String(describing: error)])
        }
    }

    /// One blocking connect → write frame → read one reply line, off the main
    /// thread. Each verb gets its own connection (the daemon closes after a single
    /// request/reply reply).
    private func roundTrip(_ frame: Frame) async throws -> Data {
        let payload = Self.encodeFrame(frame)
        let path = socketPath
        return try await withCheckedThrowingContinuation { cont in
            Self.ioQueue.async {
                do {
                    let conn = try UnixSocketConnection(path: path)
                    try conn.writeLine(payload)
                    guard let line = try conn.readLine() else {
                        throw SocketError.io("daemon closed the connection without a reply")
                    }
                    cont.resume(returning: line)
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Frame encoding / reply decoding

    /// A request frame. Tagged by `kind` on the wire (crates/sigil/src/local.rs).
    private enum Frame {
        case status, doctor, leaseList, pending, history, subscribePending
        case lockdown(clear: Bool)
        case leaseRevoke(prefix: String)
        case approve(id: String, lease: Bool)
        case deny(id: String)
    }

    private static func encodeFrame(_ frame: Frame) -> Data {
        let object: [String: Any]
        switch frame {
        case .status: object = ["kind": "status"]
        case .doctor: object = ["kind": "doctor"]
        case .leaseList: object = ["kind": "lease_list"]
        case .pending: object = ["kind": "pending"]
        case .history: object = ["kind": "history"]
        case .subscribePending: object = ["kind": "subscribe_pending"]
        case .lockdown(let clear): object = ["kind": "lockdown", "clear": clear]
        case .leaseRevoke(let prefix): object = ["kind": "lease_revoke", "prefix": prefix]
        case .approve(let id, let lease): object = ["kind": "approve", "id": id, "lease": lease]
        case .deny(let id): object = ["kind": "deny", "id": id]
        }
        // The keys are fixed and JSON-safe; serialization cannot realistically fail.
        return (try? JSONSerialization.data(withJSONObject: object)) ?? Data("{}".utf8)
    }

    /// The reply envelope, tagged by `kind`: json | control | event | exit.
    private struct ReplyEnvelope: Decodable {
        let kind: String
        let body: String?          // json, event: a JSON text to parse further
        let ok: Bool?              // control
        let lines: [String]?       // control
        let code: Int?             // exit (shim path; unused here)
    }

    /// Unwrap a `{"kind":"json","body":"…"}` reply to the body's JSON bytes.
    private static func jsonBody(_ line: Data) throws -> Data {
        let reply = try decode(ReplyEnvelope.self, line)
        guard reply.kind == "json", let body = reply.body else {
            throw SocketError.io("expected a json reply, got \(reply.kind)")
        }
        return Data(body.utf8)
    }

    /// Parse one `{"kind":"event","body":"[PendingJson]"}` snapshot. Non-event
    /// lines (or malformed bodies) are ignored so a stray frame never crashes the
    /// subscription.
    private static func decodeEventSnapshot(_ line: Data) -> [PendingRequest]? {
        guard let reply = try? decode(ReplyEnvelope.self, line),
              reply.kind == "event", let body = reply.body,
              let dtos = try? decode([PendingDTO].self, Data(body.utf8)) else { return nil }
        return dtos.map { $0.model() }
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        try JSONDecoder().decode(T.self, from: data)
    }

    /// The honest daemon-down status: we cannot ask the daemon for host facts when
    /// the socket is not listening, so we report only what we know (daemon down),
    /// which the window renders as "socket not listening" with a Start affordance.
    private func daemonDownStatus() -> StatusReport {
        StatusReport(
            daemonUp: false,
            socketPath: socketPath,
            shim: ShimState(kind: .unknown, path: nil, issue: "daemon not running"),
            opFound: false, opPath: nil,
            factor: .failClosed, relayReachable: nil, relayURL: nil, lockedDown: false)
    }
}

// MARK: - Unix domain socket

private enum SocketError: Error {
    case connect(String)
    case io(String)

    var detail: String {
        switch self {
        case .connect(let s): return s
        case .io(let s): return s
        }
    }
}

/// A lightweight daemon liveness probe shared by both clients' `daemonRunning`:
/// can we connect to the control socket at `path`? A successful connect means the
/// daemon is listening; a refused or absent socket means it is down. No frame is
/// sent and the connection is dropped at once (deinit closes the fd), so it never
/// perturbs the daemon. Synchronous: a unix-socket connect resolves immediately,
/// it never blocks waiting for a listener that is not there.
func daemonSocketReachable(path: String) -> Bool {
    (try? UnixSocketConnection(path: path)) != nil
}

/// A single blocking connection to the daemon control socket. Created, used, and
/// dropped inside one off-main closure (request/reply) or one detached thread
/// (subscription); it never crosses concurrency domains, so it needs no
/// Sendable guarantees.
private final class UnixSocketConnection {
    private let fd: Int32
    /// Bytes read past the last newline, kept for the next readLine().
    private var carry: [UInt8] = []

    init(path: String) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw SocketError.connect("socket(): \(String(cString: strerror(errno)))")
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        let placed = path.withCString { src -> Bool in
            withUnsafeMutablePointer(to: &addr.sun_path) { raw in
                raw.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                    guard strlen(src) < capacity else { return false }
                    strcpy(dst, src)
                    return true
                }
            }
        }
        guard placed else {
            close(fd)
            throw SocketError.connect("socket path too long (\(path.utf8.count) > \(capacity))")
        }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let reason = String(cString: strerror(errno))
            close(fd)
            throw SocketError.connect(reason)
        }
        self.fd = fd
    }

    deinit { close(fd) }

    /// Write the frame followed by the newline the daemon frames on.
    func writeLine(_ data: Data) throws {
        var payload = data
        payload.append(0x0A)
        try payload.withUnsafeBytes { raw in
            guard var cursor = raw.baseAddress else { return }
            var remaining = raw.count
            while remaining > 0 {
                let n = Darwin.write(fd, cursor, remaining)
                if n > 0 {
                    cursor = cursor.advanced(by: n)
                    remaining -= n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    throw SocketError.io("write(): \(String(cString: strerror(errno)))")
                }
            }
        }
    }

    /// Read one newline-delimited reply line (newline stripped). Returns nil at
    /// end of stream. Blocks until a line, EOF, or error.
    func readLine() throws -> Data? {
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            if let newline = carry.firstIndex(of: 0x0A) {
                let line = Array(carry[..<newline])
                carry.removeSubrange(...newline)
                return Data(line)
            }
            let n = chunk.withUnsafeMutableBytes { buf in
                Darwin.read(fd, buf.baseAddress, buf.count)
            }
            if n > 0 {
                carry.append(contentsOf: chunk[0..<n])
            } else if n == 0 {
                guard !carry.isEmpty else { return nil }
                let line = Data(carry)
                carry.removeAll()
                return line
            } else if errno == EINTR {
                continue
            } else {
                throw SocketError.io("read(): \(String(cString: strerror(errno)))")
            }
        }
    }
}

/// A tiny thread-safe cancellation flag shared between the subscription's
/// detached read thread and the AsyncStream's onTermination handler.
private final class CancelBox: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        cancelled = true
    }
}
