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
    private(set) var accounts: [Account] = []
    private(set) var leases: [Lease] = []
    private(set) var history: [HistoryEntry] = []
    private(set) var pending: [PendingRequest] = []
    private(set) var paired: PairedDevice?
    private(set) var settings = AppSettings()

    /// The last daemon error, surfaced as a calm banner rather than an alert.
    var lastError: String?
    /// The pairing ceremony, when running.
    var ceremony: PairingCeremony = .idle

    private var pollTask: Task<Void, Never>?

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
    }

    func stop() { pollTask?.cancel(); pollTask = nil }

    func refresh() async {
        do {
            async let s = daemon.status()
            async let l = daemon.leases()
            async let p = daemon.pending()
            async let d = daemon.pairedDevice()
            status = try await s
            leases = try await l
            pending = try await p
            paired = try await d
            lastError = nil
        } catch {
            lastError = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        }
    }

    func loadSecondaryScreens() async {
        doctorChecks = (try? await daemon.doctor()) ?? doctorChecks
        accounts = (try? await daemon.accounts()) ?? accounts
        history = (try? await daemon.history()) ?? history
        settings = (try? await daemon.settings()) ?? settings
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
            lastError = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        }
    }

    func deny(_ req: PendingRequest) async {
        _ = try? await daemon.deny(id: req.id)
        await refresh()
    }

    func lockdown(clear: Bool) async {
        _ = try? await daemon.lockdown(clear: clear)
        await refresh()
    }

    func installShim() async {
        _ = try? await daemon.installShim()
        await refresh()
    }

    func revokeLease(_ lease: Lease) async {
        _ = try? await daemon.revokeLease(grantPrefix: lease.grantHex)
        await refresh()
    }

    @discardableResult
    func addAccount(label: String, token: String) async -> Account? {
        defer { Task { await loadSecondaryScreens() } }
        return try? await daemon.addAccount(label: label, token: token)
    }

    func removeAccount(_ account: Account) async {
        try? await daemon.removeAccount(id: account.id)
        await loadSecondaryScreens()
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
            lastError = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
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

    func unpair() async {
        _ = try? await daemon.unpair()
        ceremony = .idle
        await refresh()
    }

    func saveSettings(_ s: AppSettings) async {
        settings = s
        try? await daemon.saveSettings(s)
    }
}
