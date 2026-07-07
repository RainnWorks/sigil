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
        secondaryLoaded = true
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

    func revokeLease(_ lease: Lease) async {
        await performControl { try await self.daemon.revokeLease(grantPrefix: lease.grantHex) }
    }

    // MARK: config (rules + their hidden env sources)

    /// Save a rule authored on the Rules screen. Each rule owns a hidden `env`
    /// source that holds its write-once environment; the model creates and manages
    /// that source so the user only ever sees the rule. A brand-new rule goes
    /// through the `rule add` verb (whose targeted errors surface a duplicate
    /// name); an in-place edit round-trips the whole config through `import`,
    /// which is atomic and revalidates referential integrity. Either way the
    /// draft's environment is then sealed: new and replaced VALUES are encrypted
    /// under the DEK in one pass (one Touch ID), and removed KEYs are dropped.
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
            let sourceName = envSourceName(for: draft, in: cfg)
            let priorKeys = cfg.source(named: sourceName)?.keys ?? []
            // Create the hidden env source on first save (an edit reuses the
            // existing one, so its sealed values survive even a rule rename).
            if cfg.source(named: sourceName) == nil {
                try await daemon.addSource(SourceConfig(name: sourceName, provider: envProviderID))
            }
            let rule = RuleConfig(
                name: draft.name.trimmed,
                match: draft.match,
                action: ActionConfig(source: sourceName, risk: draft.risk.rawValue,
                                     timeoutSec: draft.timeoutSec))
            if let oldName {
                var updated = try await daemon.config()
                updated.rules.removeAll { $0.name == oldName || $0.name == rule.name }
                updated.rules.append(rule)
                try await daemon.importConfig(updated)
            } else {
                try await daemon.addRule(rule)
            }
            try await applyEnv(draft, source: sourceName, priorKeys: priorKeys)
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

    /// The hidden `env` source backing a rule: reuse the one an edit carries (so
    /// its sealed values persist across a rename), else derive a fresh unique name
    /// from the rule name. The name is never shown; it only wires rule to source.
    private func envSourceName(for draft: RuleDraft, in cfg: SigilConfig) -> String {
        if let existing = draft.sourceName { return existing }
        var name = draft.name.trimmed.sourceSlug
        var n = 2
        while cfg.sources.contains(where: { $0.name == name }) {
            name = "\(draft.name.trimmed.sourceSlug)-\(n)"
            n += 1
        }
        return name
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
