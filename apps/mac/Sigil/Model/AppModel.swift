//  AppModel.swift
//  The app's single source of truth. Holds the DaemonClient and the local
//  approver seams, polls the daemon for status/leases/pending, and exposes the
//  actions the window and menubar drive. @MainActor because it feeds SwiftUI.

import SwiftUI
import Observation

@MainActor
@Observable
final class AppModel {
    // Seams (swapped for mocks in previews / dev).
    let daemon: DaemonClient
    let approver: LocalApprovalService

    // Observed state.
    private(set) var status: StatusReport?
    private(set) var doctorChecks: [DoctorCheck] = []
    private(set) var leases: [Lease] = []
    private(set) var history: [HistoryEntry] = []
    private(set) var pending: [PendingRequest] = []
    private(set) var paired: PairedDevice?
    private(set) var settings = AppSettings()
    /// The if-this-then-that config: the rules the daemon gates on and the
    /// sources they inject from. Authored on the Rules screen.
    private(set) var config = SigilConfig()
    /// The SSH keys the agent serves and whether the managed `~/.ssh/config`
    /// routing is currently installed. Loaded alongside the other secondary
    /// screens; authored on the SSH screen.
    private(set) var sshKeys = SshKeyStore()
    private(set) var sshRoutingInstalled = false
    /// The local daemon's lifecycle, driven by the Status pane's daemon card:
    /// whether its control socket is listening, the binary's reported version, and
    /// the resolved binary path (for display). `daemonBusy` is true while a
    /// start/stop/restart/install action is in flight, so the card disables its
    /// buttons and shows an in-flight state.
    private(set) var daemonRunning = false
    private(set) var daemonVersion: String?
    private(set) var daemonBinaryPath: String?
    private(set) var daemonBusy = false
    /// Whether the first secondary load (config, history, settings) has completed.
    /// The Rules screen gates its teaching empty state on this so it never flashes
    /// before the load or on a pane re-select.
    private(set) var secondaryLoaded = false

    /// The last daemon error, surfaced as a calm banner rather than an alert.
    var lastError: String?
    /// The pairing ceremony, when running.
    var ceremony: PairingCeremony = .idle

    private var pollTask: Task<Void, Never>?
    private var pendingTask: Task<Void, Never>?

    init(daemon: DaemonClient, approver: LocalApprovalService) {
        self.daemon = daemon
        self.approver = approver
    }

    /// The coarse arm state that drives the menubar glyph and the header word.
    var armState: ArmState { status?.armState ?? .idle }

    var macApprovalsMode: MacApprovalsMode {
        approver.macApprovalsEnabled ? .enabled : .hardenedPhoneOnly
    }

    // MARK: lifecycle

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
        // The pending set is pushed live (socket subscription), not polled, so the
        // menubar reflects a new or resolved request the moment the daemon does.
        pendingTask = Task { [weak self] in
            guard let stream = self?.daemon.subscribePending() else { return }
            for await snapshot in stream {
                guard let self else { return }
                self.pending = snapshot
            }
        }
    }

    func stop() {
        pollTask?.cancel(); pollTask = nil
        pendingTask?.cancel(); pendingTask = nil
    }

    func refresh() async {
        do {
            async let s = daemon.status()
            async let l = daemon.leases()
            async let d = daemon.pairedDevice()
            status = try await s
            leases = try await l
            paired = try await d
            lastError = nil
        } catch {
            lastError = describe(error)
        }
    }

    /// A calm, human line for any daemon-call failure. `DaemonError`'s own
    /// cases already read like sentences (DaemonClient.swift); anything else
    /// — an unexpected Swift/Foundation error with no localized description —
    /// gets a generic banner instead of its debug dump (`Optional(POSIXError(
    /// ...))` reads like a crash log, not a message a person should see).
    private func describe(_ error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? "Something went wrong talking to the daemon."
    }

    /// Run a daemon control call and surface however it actually went: a
    /// `.failed` result (the daemon refused) and a thrown error (couldn't even
    /// reach it) both land in `lastError`, so a button tap can never look like
    /// it worked when it silently didn't. Always refreshes afterward. Returns
    /// whether it actually succeeded, for callers (like `unpair`) that must
    /// gate a UI transition on the real outcome instead of assuming it.
    @discardableResult
    private func performControl(_ operation: () async throws -> ControlResult) async -> Bool {
        let ok: Bool
        do {
            switch try await operation() {
            case .ok:
                lastError = nil
                ok = true
            case .failed(let lines):
                lastError = lines.joined(separator: "; ")
                ok = false
            }
        } catch {
            lastError = describe(error)
            ok = false
        }
        await refresh()
        return ok
    }

    func loadSecondaryScreens() async {
        doctorChecks = (try? await daemon.doctor()) ?? doctorChecks
        history = (try? await daemon.history()) ?? history
        settings = (try? await daemon.settings()) ?? settings
        config = (try? await daemon.config()) ?? config
        sshKeys = (try? await daemon.sshKeys()) ?? sshKeys
        sshRoutingInstalled = await daemon.sshRoutingInstalled()
        await refreshDaemonStatus()
        secondaryLoaded = true
    }

    /// Refresh the daemon lifecycle readout: is the control socket listening, what
    /// version does the binary report, and where is it. Cheap enough to run on
    /// every secondary load and after each lifecycle action.
    func refreshDaemonStatus() async {
        daemonRunning = await daemon.daemonRunning()
        daemonVersion = await daemon.daemonVersion()
        daemonBinaryPath = daemon.daemonBinaryPath()
    }

    // MARK: actions

    /// Approve a pending request at the Mac. Presents Touch ID (via the approver
    /// seam) to unwrap the DEK, then tells the daemon to release. If Mac
    /// approvals are off (hardened), this is unreachable in the UI; we still fail
    /// closed with the phone-only message.
    func approveLocally(_ req: PendingRequest, lease: Bool) async {
        guard approver.macApprovalsEnabled else {
            lastError = LocalApprovalError.noMacEnvelope.errorDescription
            return
        }
        do {
            // In the wired daemon, the daemon hands us the wrapped DEK for this
            // request; here the seam takes it and returns the unwrapped DEK. The
            // Touch ID sheet is presented inside approve(...).
            let reason = "Approve \(req.title)"
            _ = try await approver.approve(wrappedDEK: Data(), reason: reason)
            _ = try await daemon.approve(id: req.id, lease: lease)
            await refresh()
        } catch let e as LocalApprovalError {
            if case .userCancelled = e { return }   // cancel is not an error state
            lastError = e.errorDescription
        } catch {
            lastError = describe(error)
        }
    }

    func deny(_ req: PendingRequest) async {
        await performControl { try await self.daemon.deny(id: req.id) }
    }

    func lockdown(clear: Bool) async {
        await performControl { try await self.daemon.lockdown(clear: clear) }
    }

    func installShim() async {
        await performControl { try await self.daemon.installShim() }
    }

    // MARK: daemon lifecycle (start / stop / restart / install)

    /// Run a daemon lifecycle action, showing an in-flight state, surfacing any
    /// failure via `lastError` (e.g. `sigil start` refusing because something
    /// already holds the socket), and refreshing both the lifecycle readout and
    /// the status afterward. Mirrors `performControl`'s shape for the
    /// throwing-void service verbs.
    private func performLifecycle(_ operation: () async throws -> Void) async {
        daemonBusy = true
        do {
            try await operation()
            lastError = nil
        } catch {
            lastError = describe(error)
        }
        await refreshDaemonStatus()
        await refresh()
        daemonBusy = false
    }

    func startDaemon() async { await performLifecycle { try await self.daemon.startDaemon() } }
    func stopDaemon() async { await performLifecycle { try await self.daemon.stopDaemon() } }
    func restartDaemon() async { await performLifecycle { try await self.daemon.restartDaemon() } }
    func installDaemon() async { await performLifecycle { try await self.daemon.installDaemon() } }

    func revokeLease(_ lease: Lease) async {
        await performControl { try await self.daemon.revokeLease(grantPrefix: lease.grantHex) }
    }

    // MARK: config (rules + their hidden env sources)

    /// Save a rule authored on the Rules screen. A rule is its match; it has no
    /// user-facing name. The model mints a UNIQUE config identity (and a matching
    /// hidden `env` source) so `add_rule` can never reject it and the user never
    /// meets an "already exists": stacking two rules on the same base command (op,
    /// op with a flag, even a second identical op) is the point, not an error. A
    /// brand-new rule goes through `rule add`; an edit keeps the existing identity
    /// and round-trips the whole config through `import` (atomic, revalidated).
    /// Either way the draft's environment is then sealed: new and replaced VALUES
    /// are encrypted under the DEK in one pass, and removed KEYs are dropped.
    ///
    /// Returns whether it actually took, so the editor sheet dismisses only on a
    /// real success and stays open (with the reason) on a refusal. The reload runs
    /// inline before returning: a detached refresh Task cannot be observed by the
    /// caller's synchronous check.
    @discardableResult
    func saveRule(_ draft: RuleDraft, replacing oldName: String?) async -> Bool {
        var ok = false
        do {
            let cfg = try await daemon.config()
            // Identity: reuse an edit's stable id; else mint a unique one from the
            // match. A gate rule and its hidden source share the string.
            let name: String = oldName ?? draft.sourceName ?? uniqueName(from: draft.match, in: cfg)

            if draft.mode == .allow {
                // A passthrough: no source, no lease, no environment. Any hidden
                // env source a former gate rule left behind (an edit gate->allow)
                // is swept by pruneOrphanSources below, purging its sealed values.
                let rule = RuleConfig(name: name, match: draft.match,
                                      action: ActionConfig(mode: .allow))
                try await writeRule(rule, replacing: oldName)
            } else {
                let sourceName = draft.sourceName ?? name
                let priorKeys = cfg.source(named: sourceName)?.keys ?? []
                // Create the hidden env source on first save (an edit reuses it, so
                // its sealed values survive).
                if cfg.source(named: sourceName) == nil {
                    try await daemon.addSource(SourceConfig(name: sourceName, provider: envProviderID))
                }
                let rule = RuleConfig(
                    name: name,
                    match: draft.match,
                    action: ActionConfig(mode: .gate, source: sourceName,
                                         lease: draft.leasePolicy, timeoutSec: draft.timeoutSec))
                try await writeRule(rule, replacing: oldName)
                try await applyEnv(draft, source: sourceName, priorKeys: priorKeys)
            }
            lastError = nil
            ok = true
        } catch {
            lastError = describe(error)
        }
        // A failed add can leave a hidden env source with no rule; sweep those up
        // so they do not silently accumulate.
        await pruneOrphanSources()
        await loadSecondaryScreens()
        return ok
    }

    /// Persist one authored rule: a brand-new rule goes through `rule add`; an
    /// edit round-trips the whole config through `import` (atomic, revalidated),
    /// replacing the rule in place so its precedence in the list is preserved.
    private func writeRule(_ rule: RuleConfig, replacing oldName: String?) async throws {
        guard oldName != nil else {
            try await daemon.addRule(rule)
            return
        }
        var updated = try await daemon.config()
        if let idx = updated.rules.firstIndex(where: { $0.name == rule.name }) {
            updated.rules[idx] = rule
        } else {
            updated.rules.append(rule)
        }
        try await daemon.importConfig(updated)
    }

    /// Reorder the rules by drag. The rules array order IS the precedence: the
    /// daemon resolves a command by first match in config order (crates/sigil
    /// config.rs `resolve()` iterates the rules in order and returns the first
    /// whose match hits), and the Rules screen renders that array top to bottom,
    /// so the higher rule wins. A move is persisted through the same
    /// export -> mutate -> import seam an edit uses: export the whole config,
    /// reorder ONLY its rules array to match the new list order (sources are left
    /// untouched), and import it back. `import` preserves rules order (it is a
    /// Vec). The local array is reordered first so the drag lands instantly with
    /// the list's native move animation; the reload then confirms it.
    func moveRules(from offsets: IndexSet, to destination: Int) {
        config.rules.move(fromOffsets: offsets, toOffset: destination)
        let order = config.rules.map(\.name)
        Task {
            do {
                var cfg = try await daemon.config()
                cfg.rules.sort {
                    (order.firstIndex(of: $0.name) ?? .max) < (order.firstIndex(of: $1.name) ?? .max)
                }
                try await daemon.importConfig(cfg)
                lastError = nil
            } catch {
                lastError = describe(error)
            }
            await loadSecondaryScreens()
        }
    }

    func removeRule(_ rule: RuleConfig) async {
        do {
            try await daemon.removeRule(name: rule.name)
            // Remove the hidden env source too (this purges its sealed blob).
            try? await daemon.removeSource(name: rule.action.source)
            lastError = nil
        } catch {
            lastError = describe(error)
        }
        await pruneOrphanSources()
        await loadSecondaryScreens()
    }

    /// A unique config identity for a new rule, derived from its match summary
    /// (e.g. "op", "op-read", "op-account-prod") and disambiguated with a counter
    /// when that base is already taken, so two rules on the same command coexist.
    /// Unique across BOTH rule names and source names, since a rule and its hidden
    /// source share the string. The string is config-side plumbing; the rule's
    /// display is its match, which may repeat freely.
    private func uniqueName(from match: MatchConfig, in cfg: SigilConfig) -> String {
        let base = match.summary.sourceSlug
        let taken: (String) -> Bool = { n in
            cfg.rules.contains { $0.name == n } || cfg.sources.contains { $0.name == n }
        }
        if !taken(base) { return base }
        var n = 2
        while taken("\(base)-\(n)") { n += 1 }
        return "\(base)-\(n)"
    }

    /// Seal the draft's environment into `source`. New rows (and existing rows the
    /// user retyped) are sealed together in one `sealEnv` call so the DEK unwraps
    /// once; KEYs that were present before the edit but are gone from the draft are
    /// unset. Values live only for the moment of the seal, then are gone.
    private func applyEnv(_ draft: RuleDraft, source: String, priorKeys: [String]) async throws {
        let secrets: [EnvSecret] = draft.env.compactMap { row in
            let key = row.key.trimmed
            guard !key.isEmpty else { return nil }
            // A fresh row always seals (even an empty VALUE = KEY set to ""); an
            // existing row seals only when the user typed a replacement.
            if row.existing && row.value.isEmpty { return nil }
            return EnvSecret(key: key, value: row.value)
        }
        if !secrets.isEmpty {
            try await daemon.sealEnv(source: source, secrets: secrets)
        }
        let keptKeys = Set(draft.env.map { $0.key.trimmed })
        for removed in priorKeys where !keptKeys.contains(removed) {
            try await daemon.unsealEnv(source: source, key: removed)
        }
    }

    /// Remove hidden `env` sources no rule references any more. These are pure
    /// plumbing the model creates per rule; an orphan can only come from a failed
    /// save, so sweeping them keeps the store tidy and leaks no sealed values.
    private func pruneOrphanSources() async {
        guard let cfg = try? await daemon.config() else { return }
        let referenced = Set(cfg.rules.map(\.action.source))
        for src in cfg.sources where src.provider == envProviderID && !referenced.contains(src.name) {
            try? await daemon.removeSource(name: src.name)
        }
    }

    // MARK: SSH keys + routing

    /// Add a served SSH key from a draft: a 1Password reference (public key piped
    /// to the CLI on stdin) or a local key file. The CLI does all validation
    /// (ed25519, dedupe, safe host tokens); a refusal lands in `lastError` and the
    /// editor stays open. Returns whether it took, so the sheet dismisses only on
    /// a real success. Reloads inline so the caller's check sees the new list.
    @discardableResult
    func saveSshKey(_ draft: SSHKeyDraft) async -> Bool {
        var ok = false
        do {
            switch draft.source {
            case .onePassword:
                try await daemon.addSshOnePasswordKey(
                    vault: draft.vault.trimmed, item: draft.item.trimmed,
                    field: draft.field.trimmed, comment: draft.comment.trimmed,
                    hosts: draft.hosts, publicKey: draft.publicKey.trimmed)
            case .file:
                try await daemon.addSshFileKey(
                    path: draft.path.trimmed, comment: draft.comment.trimmed, hosts: draft.hosts)
            }
            lastError = nil
            ok = true
        } catch {
            lastError = describe(error)
        }
        await loadSecondaryScreens()
        return ok
    }

    /// Stop serving a key. The CLI `remove <item>` matches a 1Password item name;
    /// a file key is dropped by its path where the mock supports it.
    func removeSshKey(_ key: SshServedKey) async {
        do {
            try await daemon.removeSshKey(item: key.removeItem)
            lastError = nil
        } catch {
            lastError = describe(error)
        }
        await loadSecondaryScreens()
    }

    /// Toggle the managed `~/.ssh/config` routing on or off. On installs the block
    /// that sends the routed hosts through Sigil; off restores the normal agent.
    func setSshRouting(_ install: Bool) async {
        do {
            if install { try await daemon.installSshRouting() }
            else { try await daemon.uninstallSshRouting() }
            lastError = nil
        } catch {
            lastError = describe(error)
        }
        await loadSecondaryScreens()
    }

    /// The generated `~/.sigil/ssh/config` contents for the "View block"
    /// affordance, read on demand (nil when routing is not installed).
    func generatedSshConfig() async -> String? {
        await daemon.generatedSshConfig()
    }

    func setMacApprovals(_ mode: MacApprovalsMode) async {
        do {
            switch mode {
            case .enabled:
                let key = try approver.enableMacApprovals()
                // Hand the SE public key to the daemon so it wraps the DEK to it.
                try await daemon.setMacApprovals(.enabled)
                _ = key   // (the daemon call carries the key in the wired build)
            case .hardenedPhoneOnly:
                try approver.disableMacApprovals()
                try await daemon.setMacApprovals(.hardenedPhoneOnly)
            }
        } catch {
            lastError = describe(error)
        }
    }

    func beginPairing(relayURL: String) {
        Task {
            for await state in daemon.beginPairing(relayURL: relayURL) {
                ceremony = state
                if case .paired = state { await refresh() }
            }
        }
    }

    /// The human's decision at the `.confirmSAS` step. This is the real MITM
    /// backstop: the DEK is only sealed and sent once `match: true` reaches the
    /// running ceremony (see `DaemonClient.confirmPairing`). A mismatch tears
    /// the ceremony down here too, since the CLI side fails closed but has no
    /// way to push a friendlier reason than its own error string.
    func confirmSAS(match: Bool) {
        daemon.confirmPairing(match: match)
        if !match { ceremony = .failed(reason: "SAS words did not match; pairing cancelled") }
    }

    func unpair() async {
        // Optimistically flipping to .idle before the call would show
        // "unpaired" even when the daemon refused (socket down, etc.) - gate
        // the transition on the call actually succeeding.
        if await performControl({ try await self.daemon.unpair() }) {
            ceremony = .idle
        }
    }

    /// Wipe all daemon state. `SettingsView`'s confirmation dialog is the
    /// human gate; by the time this runs the human already said yes, so this
    /// only surfaces whether it actually happened, not whether to ask again.
    func wipe() async {
        await performControl { try await self.daemon.wipe() }
        await loadSecondaryScreens()
    }

    func saveSettings(_ s: AppSettings) async {
        settings = s
        try? await daemon.saveSettings(s)
    }
}
