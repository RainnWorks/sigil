//  Updater.swift
//  In-app updates, through Sparkle. The app checks the appcast attached to each
//  GitHub Release, and every update is signed with the RainnWorks Sparkle key
//  whose public half is SUPublicEDKey in Info.plist.
//
//  A Homebrew cask marks this app `auto_updates true`, so `brew upgrade` leaves
//  updating to this class rather than replacing the bundle underneath it.

import Sparkle
import SwiftUI

@MainActor
@Observable
final class Updater {
    /// Why this build does not update itself, or nil when it does. The reason is
    /// shown, because a fixture run and a broken build must not read the same.
    enum Inert: String {
        case fixture = "It was started with SIGIL_MOCK set."
        case preview = "It is a SwiftUI preview."
    }

    private let controller: SPUStandardUpdaterController?
    /// Sparkle keeps only a weak reference to its delegate, so this holds it.
    private let delegate: RequestAwareDelegate?

    let inert: Inert?

    /// What this build calls itself, for the Settings row.
    let version: String

    /// When Sparkle last asked the feed. Read from Sparkle rather than stored by
    /// us, and refreshed by `refresh()`, because Sparkle also checks on its own
    /// schedule with nothing here to observe it.
    private(set) var lastChecked: Date?

    /// Mirrors Sparkle's own preference. Stored rather than computed so a change
    /// publishes to the view that owns the toggle.
    var checksAutomatically: Bool {
        didSet { controller?.updater.automaticallyChecksForUpdates = checksAutomatically }
    }

    convenience init(inert: Inert?, requestsPending: @escaping @MainActor () -> Bool = { false }) {
        self.init(inert: inert, starting: inert == nil, requestsPending: requestsPending)
    }

    /// A preview updater: renders the running state and starts nothing, so a
    /// canvas never reaches the network or offers to replace a bundle.
    static func preview(lastChecked: Date? = nil) -> Updater {
        let updater = Updater(inert: nil, starting: false, requestsPending: { false })
        updater.lastChecked = lastChecked
        updater.checksAutomatically = true
        return updater
    }

    private init(inert: Inert?, starting: Bool, requestsPending: @escaping @MainActor () -> Bool) {
        self.inert = inert
        version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "not set"
        if starting {
            let delegate = RequestAwareDelegate(requestsPending: requestsPending)
            self.delegate = delegate
            controller = SPUStandardUpdaterController(
                startingUpdater: true, updaterDelegate: delegate, userDriverDelegate: nil)
        } else {
            delegate = nil
            controller = nil
        }
        checksAutomatically = controller?.updater.automaticallyChecksForUpdates ?? false
        lastChecked = controller?.updater.lastUpdateCheckDate
    }

    func checkNow() {
        controller?.updater.checkForUpdates()
        refresh()
    }

    func refresh() {
        guard let controller else { return }
        lastChecked = controller.updater.lastUpdateCheckDate
    }
}

/// Holds an update check back while a request is waiting for a decision.
///
/// An update that arrives mid-decision relaunches the app, which takes the Deny
/// control away from the person; the request then resolves only by timing out.
/// Denying must never become the slower path, so no check starts while anything
/// is pending. Refusing the check rather than postponing the relaunch is what
/// keeps this to one method with no deferred handler to remember to call.
private final class RequestAwareDelegate: NSObject, SPUUpdaterDelegate {
    private let requestsPending: @MainActor () -> Bool

    init(requestsPending: @escaping @MainActor () -> Bool) {
        self.requestsPending = requestsPending
    }

    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {
        let pending = MainActor.assumeIsolated { requestsPending() }
        guard pending else { return }
        throw NSError(
            domain: "works.rainn.sigil.mac.updater", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "A request is waiting for a decision."])
    }
}
