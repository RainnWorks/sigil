//  MockDaemonClient.swift
//  Realistic fixtures so every screen and every state in the brief renders with
//  no daemon running. This mirrors the phone app's mock transport: the app is
//  fully exercisable in a dev build and in SwiftUI previews.
//
//  The mock keeps mutable in-memory state so approve/deny/lockdown/pair actually
//  change what the screens show, making the whole flow demoable end to end.

import Foundation

/// A tunable scenario so previews and the running app can select a state (armed,
/// pending, hardened, locked down, fail-closed).
enum MockScenario: Sendable {
    case armedIdle          // paired, armed, nothing pending
    case pendingRequests    // two requests waiting
    case hardenedPhoneOnly  // paired but Mac approvals off
    case biometricOnly      // no phone; biometric factor
    case failClosed         // no factor at all
    case lockedDown
}

actor MockDaemonClient: DaemonClient {
    private var scenario: MockScenario
    private var accountsStore: [Account]
    private var leasesStore: [Lease]
    private var historyStore: [HistoryEntry]
    private var pendingStore: [PendingRequest]
    private var paired: PairedDevice?
    private var macMode: MacApprovalsMode
    private var locked: Bool
    private var appSettings: AppSettings

    init(scenario: MockScenario = .armedIdle) {
        self.scenario = scenario
        self.accountsStore = Fixtures.accounts
        self.leasesStore = Fixtures.leases
        self.historyStore = Fixtures.history
        self.pendingStore = (scenario == .pendingRequests) ? Fixtures.pending : []
        self.paired = (scenario == .biometricOnly || scenario == .failClosed) ? nil : Fixtures.paired
        self.macMode = (scenario == .hardenedPhoneOnly) ? .hardenedPhoneOnly : .enabled
        self.locked = (scenario == .lockedDown)
        self.appSettings = Fixtures.settings
    }

    private var factor: Factor {
        if let paired { return .pairedPhone(relay: paired.relayURL) }
        switch scenario {
        case .biometricOnly: return .biometric
        default: return .failClosed
        }
    }

    func status() -> StatusReport {
        StatusReport(
            daemonUp: scenario != .failClosed || locked,
            socketPath: "/var/folders/xy/latch/daemon.sock",
            shim: scenario == .failClosed
                ? ShimState(kind: .drift, path: "~/.latch/bin/op", issue: "another op wins on PATH (/opt/homebrew/bin/op)")
                : ShimState(kind: .healthy, path: "~/.latch/bin/op", issue: nil),
            opFound: true,
            opPath: "/opt/homebrew/bin/op",
            accountCount: accountsStore.count,
            factor: factor,
            relayReachable: paired != nil ? true : nil,
            relayURL: paired?.relayURL,
            lockedDown: locked
        )
    }

    func doctor() -> [DoctorCheck] {
        let s = status()
        var checks: [DoctorCheck] = [
            .init(label: "shim wins on PATH and is current", ok: s.shim.kind == .healthy,
                  hint: s.shim.issue ?? ""),
            .init(label: "daemon socket reachable", ok: s.daemonUp,
                  hint: s.daemonUp ? "" : "daemon not running (latch start)"),
            .init(label: "socket path length ok", ok: true, hint: ""),
            .init(label: "approving factor resolved", ok: {
                if case .failClosed = s.factor { return false } else { return true }
            }(), hint: s.factor.detail),
        ]
        if let reachable = s.relayReachable {
            checks.append(.init(label: "relay reachable", ok: reachable,
                                hint: reachable ? "" : "cannot reach the paired relay (approvals will time out)"))
        }
        checks.append(.init(label: "real op found", ok: s.opFound, hint: s.opFound ? "" : "no `op` on PATH"))
        return checks
    }

    func accounts() -> [Account] { accountsStore }

    func addAccount(label: String, token: String) -> Account {
        // Probe is faked: a token with "empty" in it sees no vaults (the warn case).
        let vaults = token.lowercased().contains("empty") ? [] : ["Engineering", "Rowm work"]
        let a = Account(id: UUID().uuidString, label: label, vaults: vaults,
                        health: vaults.isEmpty ? .rotate : .healthy,
                        detail: vaults.isEmpty ? "no usable vault visible" : nil,
                        lastUsedAt: nil)
        accountsStore.append(a)
        return a
    }

    func rotateAccount(id: String, token: String) throws -> Account {
        guard let i = accountsStore.firstIndex(where: { $0.id == id }) else {
            throw DaemonError.cli("no such account")
        }
        accountsStore[i].health = .healthy
        accountsStore[i].detail = nil
        return accountsStore[i]
    }

    func removeAccount(id: String) { accountsStore.removeAll { $0.id == id } }

    func leases() -> [Lease] { locked ? [] : leasesStore }

    func revokeLease(grantPrefix: String) -> ControlResult {
        let before = leasesStore.count
        leasesStore.removeAll { $0.grantHex.hasPrefix(grantPrefix) }
        let n = before - leasesStore.count
        return n > 0 ? .ok(lines: ["revoked \(n) lease(s)"]) : .failed(lines: ["no lease matched \(grantPrefix)"])
    }

    func history() -> [HistoryEntry] { historyStore }

    func pending() -> [PendingRequest] { locked ? [] : pendingStore }

    func approve(id: String, lease: Bool) -> ControlResult {
        guard let req = pendingStore.first(where: { $0.id == id }) else {
            return .failed(lines: ["no pending request with that id"])
        }
        pendingStore.removeAll { $0.id == id }
        historyStore.insert(.init(id: id, kind: req.kind, label: req.title,
                                  account: "Rowm work", process: req.provenance.processChain.joined(separator: " > "),
                                  cwd: req.provenance.cwd, decision: .approved, note: nil,
                                  at: Date(), via: "biometric"), at: 0)
        if lease {
            leasesStore.insert(.init(grantHex: String(UUID().uuidString.prefix(12)).lowercased(),
                                     caller: req.provenance.processChain.last ?? "op",
                                     account: "Rowm work", scope: req.title,
                                     grantedAt: Date(), expiresAt: Date().addingTimeInterval(900)), at: 0)
        }
        return .ok(lines: ["approved\(lease ? " (session lease)" : "")"])
    }

    func deny(id: String) -> ControlResult {
        guard let req = pendingStore.first(where: { $0.id == id }) else {
            return .failed(lines: ["no pending request with that id"])
        }
        pendingStore.removeAll { $0.id == id }
        historyStore.insert(.init(id: id, kind: req.kind, label: req.title, account: "Rowm work",
                                  process: req.provenance.processChain.joined(separator: " > "),
                                  cwd: req.provenance.cwd, decision: .denied, note: "denied at the Mac",
                                  at: Date(), via: "biometric"), at: 0)
        return .ok(lines: ["denied"])
    }

    func lockdown(clear: Bool) -> ControlResult {
        locked = !clear
        return .ok(lines: [clear ? "unsealed" : "sealed: denied everything pending, refusing new"])
    }

    func pairedDevice() -> PairedDevice? { paired }

    nonisolated func beginPairing(relayURL: String) -> AsyncStream<PairingCeremony> {
        AsyncStream { continuation in
            Task {
                let payload = Fixtures.qrPayloadBase64
                continuation.yield(.awaitingPhone(payloadBase64: payload))
                try? await Task.sleep(for: .seconds(2.2))
                let words = ["tide", "brass", "anchor", "harbor", "dusk", "iron"]
                continuation.yield(.confirmSAS(words: words))
                try? await Task.sleep(for: .seconds(2.2))
                let device = PairedDevice(id: UUID().uuidString, name: "iPhone",
                                          sasWords: words, relayURL: relayURL, pairedAt: Date())
                await self.setPaired(device)
                continuation.yield(.paired(device))
                continuation.finish()
            }
        }
    }

    private func setPaired(_ device: PairedDevice) { self.paired = device }

    func unpair() -> ControlResult {
        paired = nil
        return .ok(lines: ["phone unpaired; the daemon will fail closed until you pair again"])
    }

    func setMacApprovals(_ mode: MacApprovalsMode) { macMode = mode }

    func installShim() -> ControlResult {
        .ok(lines: ["shim installed", "~/.latch/bin/op -> /usr/local/bin/latch"])
    }

    func settings() -> AppSettings { appSettings }
    func saveSettings(_ settings: AppSettings) { appSettings = settings }
    func wipe() -> ControlResult { .ok(lines: ["wiped: tokens, pairing, leases, history"]) }
}

// MARK: - Fixtures

enum Fixtures {
    static let accounts: [Account] = [
        Account(id: "acc-rowm", label: "Rowm work", vaults: ["Engineering", "Rowm work", "Shared"],
                health: .healthy, detail: nil, lastUsedAt: Date().addingTimeInterval(-420)),
        Account(id: "acc-perso", label: "personal", vaults: ["Private"],
                health: .expiring, detail: "expires in 6d", lastUsedAt: Date().addingTimeInterval(-86_400 * 2)),
    ]

    static let leases: [Lease] = [
        Lease(grantHex: "9f3c1a77be20", caller: "claude", account: "Rowm work",
              scope: "Engineering/.env", grantedAt: Date().addingTimeInterval(-300),
              expiresAt: Date().addingTimeInterval(600)),
        Lease(grantHex: "2b8ee410c9d1", caller: "rowm launcher", account: "Rowm work",
              scope: "op read op://Engineering/graphql-api/credential",
              grantedAt: Date().addingTimeInterval(-90), expiresAt: Date().addingTimeInterval(90)),
    ]

    static let history: [HistoryEntry] = [
        HistoryEntry(id: "h1", kind: .secretRead, label: "Engineering/.env > graphql-api",
                     account: "Rowm work", process: "zsh > claude > op", cwd: "~/Projects/rowm",
                     decision: .approved, note: nil, at: Date().addingTimeInterval(-120), via: "phone"),
        HistoryEntry(id: "h2", kind: .sshSignature, label: "github-deploy -> git@github.com",
                     account: "personal", process: "zsh > git > ssh", cwd: "~/Projects/op-remote",
                     decision: .approved, note: nil, at: Date().addingTimeInterval(-900), via: "biometric"),
        HistoryEntry(id: "h3", kind: .secretRead, label: "Production/db > password",
                     account: "Rowm work", process: "zsh > node > op", cwd: "~/Projects/rowm",
                     decision: .denied, note: "Production vault; denied at the phone.",
                     at: Date().addingTimeInterval(-3600), via: "phone"),
        HistoryEntry(id: "h4", kind: .secretRead, label: "Engineering/ci > token",
                     account: "Rowm work", process: "zsh > make > op", cwd: "~/Projects/rowm",
                     decision: .expired, note: "no decision in 120s", at: Date().addingTimeInterval(-7200), via: "phone"),
    ]

    static let pending: [PendingRequest] = [
        PendingRequest(
            id: "req-1", kind: .secretRead, command: ["op", "read", "op://Engineering/graphql-api/credential"],
            secrets: [SecretRef(provider: "1password", segments: ["Engineering", "graphql-api"], label: "graphql-api")],
            ssh: nil,
            provenance: Provenance(processChain: ["zsh", "claude", "op"], cwd: "~/Projects/rowm",
                                   machine: "studio.local", requestedAt: Date().addingTimeInterval(-6)),
            risk: .routine, reason: nil, expiresAt: Date().addingTimeInterval(96), timeoutSec: 120, coalesced: 3),
        PendingRequest(
            id: "req-2", kind: .sshSignature, command: ["ssh", "git@github.com"],
            secrets: [],
            ssh: SshChallenge(keyLabel: "github-deploy", host: "git@github.com",
                              fingerprint: "SHA256:9m8x1c0Vd2pKtqE7bQ4wZ+f3nR6uJ0aLyH5sT8oW1c"),
            provenance: Provenance(processChain: ["zsh", "git", "ssh"], cwd: "~/Projects/op-remote",
                                   machine: "studio.local", requestedAt: Date().addingTimeInterval(-2)),
            risk: .elevated, reason: "Production deploy key.", expiresAt: Date().addingTimeInterval(58), timeoutSec: 120),
    ]

    static let paired = PairedDevice(id: "dev-phone", name: "iPhone",
                                     sasWords: ["tide", "brass", "anchor", "harbor", "dusk", "iron"],
                                     relayURL: "https://relay.rowm.space", pairedAt: Date().addingTimeInterval(-86_400 * 9))

    static let settings = AppSettings(approvalTimeoutSec: 120, notificationsEnabled: true,
                                      historyRetentionDays: 30, relayURL: "https://relay.rowm.space",
                                      reduceMotion: false)

    /// A representative pairing payload (base64) for QR rendering in mock/preview.
    static let qrPayloadBase64 =
        "TEFUQ0gxAAABZGFlbW9uX3ZlcmlmeWluZ19rZXlfMzJieXRlc19oZXJlLi4uZGFlbW9uX2FncmVlbWVudF9rZXlfMzJieXRlc19oZXJlcGFpcmluZ19zZWNyZXRfMjU2Yml0X29uZV90aW1lX3ZhbHVlaHR0cHM6Ly9yZWxheS5yb3dtLnNwYWNl"
}
