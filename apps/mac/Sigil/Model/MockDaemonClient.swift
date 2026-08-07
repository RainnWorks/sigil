//  MockDaemonClient.swift
//  Realistic fixtures so every screen and every state in the brief renders with
//  no daemon running. This mirrors the phone app's mock transport: the app is
//  fully exercisable in a dev build and in SwiftUI previews.
//
//  The mock keeps mutable in-memory state so approve/deny/pair actually change
//  what the screens show, making the whole flow demoable end to end.

import Foundation

/// A tunable scenario so previews and the running app can select a state (armed,
/// pending, fail-closed).
enum MockScenario: Sendable {
    case armedIdle          // paired, armed, nothing pending
    case pendingRequests    // two requests waiting
    case biometricOnly      // no phone; biometric factor
    case failClosed         // no factor at all
}

actor MockDaemonClient: DaemonClient {
    /// Fixtures: the app must not read the real keystore or mint a real Secure
    /// Enclave key behind a preview.
    nonisolated var isFixtureClient: Bool { true }

    private var scenario: MockScenario
    private var leasesStore: [Lease]
    private var historyStore: [HistoryEntry]
    private var pendingStore: [PendingRequest]
    private var paired: PairedDevice?
    private var appSettings: AppSettings
    private var configStore: SigilConfig
    /// The in-memory SSH store and its routing state, so the SSH pane's list,
    /// add/remove, and the routing toggle all mutate faithfully in previews and
    /// the dev build.
    private var sshStore: SshKeyStore
    private var sshRouting: Bool
    /// Whether the local daemon process is listening. Start/Stop/Restart/Install
    /// flip this so the lifecycle card visibly changes in previews and the dev
    /// build. Defaults to running for every scenario except fail-closed.
    private var running: Bool
    /// Sealed inline env values, by source name: the mock's stand-in for the
    /// threshold-sealed blob. Never read back to the UI (the readout is keys-only
    /// via the source's `keys`); kept only so set/unset and edits behave faithfully.
    private var envValues: [String: [(String, String)]] = [:]

    init(scenario: MockScenario = .armedIdle, config: SigilConfig = Fixtures.config,
         sshKeys: SshKeyStore = Fixtures.sshKeys, sshRouting: Bool = false,
         running: Bool? = nil) {
        self.scenario = scenario
        self.running = running ?? (scenario != .failClosed)
        self.leasesStore = Fixtures.leases
        self.historyStore = Fixtures.history
        self.pendingStore = (scenario == .pendingRequests) ? Fixtures.pending : []
        self.paired = (scenario == .biometricOnly || scenario == .failClosed) ? nil : Fixtures.paired
        self.appSettings = Fixtures.settings
        self.configStore = config
        self.sshStore = sshKeys
        self.sshRouting = sshRouting
        for src in configStore.sources where src.provider == envProviderID {
            envValues[src.name] = src.keys.map { ($0, "sealed") }
        }
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
            daemonUp: scenario != .failClosed,
            socketPath: "/var/folders/xy/sigil/daemon.sock",
            shim: scenario == .failClosed
                ? ShimState(kind: .drift, path: "~/.sigil/bin/op", issue: "another op wins on PATH (/opt/homebrew/bin/op)")
                : ShimState(kind: .healthy, path: "~/.sigil/bin/op", issue: nil),
            opFound: true,
            opPath: "/opt/homebrew/bin/op",
            factor: factor,
            relayReachable: paired != nil ? true : nil,
            relayURL: paired?.relayURL
        )
    }

    func doctor() -> [DoctorCheck] {
        let s = status()
        var checks: [DoctorCheck] = [
            .init(label: "shim wins on PATH and is current", ok: s.shim.kind == .healthy,
                  hint: s.shim.issue ?? ""),
            .init(label: "daemon socket reachable", ok: s.daemonUp,
                  hint: s.daemonUp ? "" : "daemon not running (sigil start)"),
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

    // MARK: config (rules + their hidden env sources)
    // The mock mirrors core's referential rules loosely enough that the editor's
    // happy path and refusals both demo: a duplicate name or a dangling/held
    // source throws, everything else mutates the in-memory config.

    func config() -> SigilConfig { configStore }

    func addSource(_ source: SourceConfig) throws {
        guard !configStore.sources.contains(where: { $0.name == source.name }) else {
            throw DaemonError.cli("source \(source.name) already exists (remove it first to replace)")
        }
        configStore.sources.append(source)
    }

    func removeSource(name: String) throws {
        if let rule = configStore.rules.first(where: { $0.action.source == name }) {
            throw DaemonError.cli("source \(name) is still used by rule \(rule.name); remove the rule first")
        }
        configStore.sources.removeAll { $0.name == name }
        envValues[name] = nil   // purge the sealed blob with the source
    }

    // MARK: inline env values (write-once; the mock never reveals them)

    func sealEnv(source: String, secrets: [EnvSecret]) throws {
        guard configStore.source(named: source)?.provider == envProviderID else {
            throw DaemonError.cli("no inline env source named \(source)")
        }
        var pairs = envValues[source] ?? []
        for s in secrets {
            if let i = pairs.firstIndex(where: { $0.0 == s.key }) { pairs[i].1 = s.value }
            else { pairs.append((s.key, s.value)) }
        }
        envValues[source] = pairs
        syncEnvKeys(source)
    }

    func unsealEnv(source: String, key: String) throws {
        guard configStore.source(named: source)?.provider == envProviderID else {
            throw DaemonError.cli("no inline env source named \(source)")
        }
        var pairs = envValues[source] ?? []
        let before = pairs.count
        pairs.removeAll { $0.0 == key }
        guard pairs.count < before else { throw DaemonError.cli("no key \(key) on \(source)") }
        envValues[source] = pairs
        syncEnvKeys(source)
    }

    /// Mirror core: keep the source's public KEY names (sorted) in lockstep with
    /// the sealed pairs, never the values.
    private func syncEnvKeys(_ source: String) {
        guard let i = configStore.sources.firstIndex(where: { $0.name == source }) else { return }
        configStore.sources[i].keys = (envValues[source] ?? []).map(\.0).sorted()
    }

    func addRule(_ rule: RuleConfig) throws {
        guard !configStore.rules.contains(where: { $0.name == rule.name }) else {
            throw DaemonError.cli("rule \(rule.name) already exists (remove it first to replace)")
        }
        guard configStore.source(named: rule.action.source) != nil else {
            throw DaemonError.cli("rule \(rule.name) references unknown source \(rule.action.source)")
        }
        configStore.rules.append(rule)
    }

    func removeRule(name: String) { configStore.rules.removeAll { $0.name == name } }

    func importConfig(_ config: SigilConfig) { configStore = config }

    func leases() -> [Lease] { leasesStore }

    func revokeLease(grantPrefix: String) -> ControlResult {
        let before = leasesStore.count
        leasesStore.removeAll { $0.grantHex.hasPrefix(grantPrefix) }
        let n = before - leasesStore.count
        return n > 0 ? .ok(lines: ["revoked \(n) lease(s)"]) : .failed(lines: ["no lease matched \(grantPrefix)"])
    }

    func history() -> [HistoryEntry] { historyStore }

    func pending() -> [PendingRequest] { pendingStore }

    func approve(id: String, lease: Bool) -> ControlResult {
        guard let req = pendingStore.first(where: { $0.id == id }) else {
            return .failed(lines: ["no pending request with that id"])
        }
        pendingStore.removeAll { $0.id == id }
        historyStore.insert(.init(id: id, kind: req.kind, label: req.title,
                                  account: "Rowm work", process: req.provenance.processChain.joined(separator: " > "),
                                  cwd: req.provenance.cwd, decision: .approved, note: nil,
                                  at: Date(), via: "phone"), at: 0)
        if lease {
            leasesStore.insert(.init(grantHex: String(UUID().uuidString.prefix(12)).lowercased(),
                                     caller: req.provenance.processChain.last ?? "op",
                                     // The daemon scopes the lease to the matched
                                     // rule; the fixture rules are named after the
                                     // command they gate, so stand in with that.
                                     account: "Rowm work", scope: req.command.first ?? "rule",
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
                                  at: Date(), via: "phone"), at: 0)
        return .ok(lines: ["denied"])
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

    // The fixture ceremony above advances on a timer with no human gate to
    // wire, so there is nothing for a real confirmation to reach; kept only to
    // satisfy the protocol.
    nonisolated func confirmPairing(match: Bool) {}

    func unpair() -> ControlResult {
        paired = nil
        return .ok(lines: ["phone unpaired; the daemon will fail closed until you pair again"])
    }

    func installShim() -> ControlResult {
        .ok(lines: ["shim installed", "~/.sigil/bin/op -> /usr/local/bin/sigil"])
    }

    // MARK: daemon lifecycle
    // The mock flips an in-memory `running` flag so the auto-ensure and the
    // Restart/Stop controls visibly change the lifecycle card in previews and
    // the dev build.

    func daemonRunning() -> Bool { running }
    func daemonVersion() -> String? { "sigil 0.5.0" }
    nonisolated func daemonBinaryPath() -> String? { "~/.sigil/bin/sigil" }
    func ensureUp() { running = true }
    func stopDaemon() { running = false }
    func restartDaemon() { running = true }

    func settings() -> AppSettings { appSettings }
    func saveSettings(_ settings: AppSettings) { appSettings = settings }
    func wipe() -> ControlResult { .ok(lines: ["wiped: tokens, pairing, leases, history"]) }

    // MARK: SSH agent (served keys + managed ~/.ssh/config routing)
    // The mock mirrors the CLI loosely enough that the pane's happy path and its
    // dedupe refusal both demo: a duplicate item/path throws, everything else
    // mutates the in-memory store.

    func sshKeys() -> SshKeyStore { sshStore }

    func addSshOnePasswordKey(vault: String, item: String, field: String,
                              comment: String, hosts: [String], publicKey: String) throws {
        guard !sshStore.keys.contains(where: { $0.vault == vault && $0.item == item }) else {
            throw DaemonError.cli("op://\(vault)/\(item) is already served (remove it first to replace)")
        }
        sshStore.keys.append(SshKeyEntry(
            publicKey: publicKey, vault: vault, item: item,
            field: field.isEmpty ? "private key" : field, comment: comment, hosts: hosts))
    }

    func addSshFileKey(path: String, comment: String, hosts: [String]) throws {
        guard !sshStore.files.contains(where: { $0.path == path }) else {
            throw DaemonError.cli("\(path) is already served (remove it first to replace)")
        }
        sshStore.files.append(SshFileEntry(path: path, comment: comment, hosts: hosts))
    }

    func removeSshKey(item: String) {
        // The real CLI `remove <item>` matches 1Password items only; the mock
        // mirrors that but also drops a file path so previews can demo a removal.
        sshStore.keys.removeAll { $0.item == item }
        sshStore.files.removeAll { $0.path == item }
    }

    func installSshRouting() { sshRouting = true }
    func uninstallSshRouting() { sshRouting = false }
    func sshRoutingInstalled() -> Bool { sshRouting }

    func generatedSshConfig() -> String? {
        guard sshRouting else { return nil }
        let sock = "/var/folders/xy/sigil/ssh-agent.sock"
        var out = "# Generated by sigil ssh config. Do not edit; edit your keys and re-run.\n\n"
        for key in sshStore.served where key.isRouted {
            out += "Host \(key.hosts.joined(separator: " "))\n"
            out += "  IdentityAgent \(sock)\n"
            out += "  IdentitiesOnly yes\n\n"
        }
        return out
    }
}

// MARK: - Fixtures

enum Fixtures {
    static let leases: [Lease] = [
        // `scope` is a rule name (see Fixtures.config), never a command line.
        Lease(grantHex: "9f3c1a77be20", caller: "claude", account: "Rowm work",
              scope: "op", grantedAt: Date().addingTimeInterval(-300),
              expiresAt: Date().addingTimeInterval(600)),
        Lease(grantHex: "2b8ee410c9d1", caller: "rowm launcher", account: "Rowm work",
              scope: "gcloud",
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
            leasable: false, maxLeaseSecs: nil, reason: nil,
            expiresAt: Date().addingTimeInterval(96), timeoutSec: 120, coalesced: 3),
        PendingRequest(
            id: "req-2", kind: .sshSignature, command: ["ssh", "git@github.com"],
            secrets: [],
            ssh: SshChallenge(keyLabel: "github-deploy", host: "git@github.com",
                              fingerprint: "SHA256:9m8x1c0Vd2pKtqE7bQ4wZ+f3nR6uJ0aLyH5sT8oW1c"),
            provenance: Provenance(processChain: ["zsh", "git", "ssh"], cwd: "~/Projects/op-remote",
                                   machine: "studio.local", requestedAt: Date().addingTimeInterval(-2)),
            leasable: true, maxLeaseSecs: 900, reason: "Production deploy key.",
            expiresAt: Date().addingTimeInterval(58), timeoutSec: 120),
    ]

    static let paired = PairedDevice(id: "dev-phone", name: "iPhone",
                                     sasWords: ["tide", "brass", "anchor", "harbor", "dusk", "iron"],
                                     relayURL: "https://relay.rainn.works", pairedAt: Date().addingTimeInterval(-86_400 * 9))

    /// A representative config: two rules, each gating a command and injecting a
    /// write-once environment from its own hidden `env` source (named after the
    /// rule; never shown). The source `keys` are the KEY names the editor and the
    /// rule card read back; the VALUES live only in the sealed blob.
    static let config = SigilConfig(
        version: 1,
        sources: [
            SourceConfig(name: "op", provider: "env", keys: ["OP_SERVICE_ACCOUNT_TOKEN"]),
            SourceConfig(name: "gcloud", provider: "env",
                         keys: ["GOOGLE_APPLICATION_CREDENTIALS"]),
        ],
        rules: [
            RuleConfig(name: "op",
                       match: MatchConfig(command: "op"),
                       action: ActionConfig(mode: .gate, source: "op")),
            RuleConfig(name: "gcloud",
                       match: MatchConfig(command: "gcloud", argvContains: ["auth"],
                                          flagEquals: [FlagEqConfig(flag: "--project", value: "prod")]),
                       action: ActionConfig(mode: .gate, source: "gcloud",
                                            lease: .leasable(maxSecs: 900))),
        ])

    static let settings = AppSettings(approvalTimeoutSec: 120, notificationsEnabled: true,
                                      historyRetentionDays: 30, relayURL: "https://relay.rainn.works",
                                      reduceMotion: false)

    /// A representative SSH store: a 1Password "GitHub" key routed to github.com
    /// and gist.github.com, and a local key file that is served but not routed.
    /// The public-key line is a valid ed25519 blob so a fingerprint renders. Built
    /// by decoding the on-disk JSON shape so the fixture exercises the same path a
    /// real read does.
    static let sshKeys: SshKeyStore = {
        let json = """
        {
          "keys": [
            {
              "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl tom@studio",
              "vault": "Engineering",
              "item": "GitHub",
              "field": "private key",
              "comment": "tom@studio",
              "hosts": ["github.com", "gist.github.com"]
            }
          ],
          "files": [
            {
              "path": "~/.ssh/id_ed25519",
              "comment": "personal",
              "hosts": []
            }
          ]
        }
        """
        return (try? JSONDecoder().decode(SshKeyStore.self, from: Data(json.utf8))) ?? SshKeyStore()
    }()

    /// A representative pairing payload (base64) for QR rendering in mock/preview.
    static let qrPayloadBase64 =
        "TEFUQ0gxAAABZGFlbW9uX3ZlcmlmeWluZ19rZXlfMzJieXRlc19oZXJlLi4uZGFlbW9uX2FncmVlbWVudF9rZXlfMzJieXRlc19oZXJlcGFpcmluZ19zZWNyZXRfMjU2Yml0X29uZV90aW1lX3ZhbHVlaHR0cHM6Ly9yZWxheS5yb3dtLnNwYWNl"
}
