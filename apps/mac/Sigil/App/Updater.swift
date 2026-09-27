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
    /// Absent in a build that must not reach the network: previews, and the
    /// SIGIL_MOCK fixture run. Every method below is then a no-op and the
    /// Settings section says so rather than offering a control that does nothing.
    private let controller: SPUStandardUpdaterController?

    /// What this build calls itself, for the Settings row.
    let version: String

    /// Mirrors Sparkle's own preference. Stored rather than computed so a change
    /// publishes to the view that owns the toggle.
    var checksAutomatically: Bool {
        didSet { controller?.updater.automaticallyChecksForUpdates = checksAutomatically }
    }

    init(enabled: Bool) {
        version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let controller = enabled
            ? SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
            : nil
        self.controller = controller
        checksAutomatically = controller?.updater.automaticallyChecksForUpdates ?? false
    }

    var isRunning: Bool { controller != nil }

    func checkNow() { controller?.updater.checkForUpdates() }
}
