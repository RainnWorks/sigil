//  SigilApp.swift
//  The app: a menubar pulse plus an on-demand configurator window. Agent app
//  (LSUIElement), so there is no Dock icon; the menubar is always present and the
//  window opens when asked.

import SwiftUI

@main
struct SigilApp: App {
    @State private var model: AppModel
    @State private var updater: Updater
    @Environment(\.openWindow) private var openWindow

    /// Both seams are built here rather than as default values, because the
    /// updater has to be able to ask the model whether a request is waiting.
    init() {
        let model = SigilApp.makeModel()
        _model = State(initialValue: model)
        _updater = State(initialValue: Updater(
            inert: SigilApp.inertReason(),
            requestsPending: { !model.pending.isEmpty }))
    }

    var body: some Scene {
        // The configurator: one window, source-list sidebar + detail.
        Window("Sigil", id: WindowID.configurator) {
            RootWindow()
                .environment(model)
                .environment(updater)
                .frame(minWidth: 720, minHeight: 480)
                .task { model.start(); await model.loadSecondaryScreens() }
        }
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified)

        // The menubar pulse: the shape states, a pending list, and Open Sigil.
        MenuBarExtra {
            MenubarContent(openConfigurator: { openConfigurator() })
                .environment(model)
                .frame(width: 320)
        } label: {
            Image(nsImage: MenubarGlyph.image(for: model.armState.menubar))
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(model)
                .environment(updater)
                .frame(width: 460)
        }
    }

    private func openConfigurator() {
        openWindow(id: WindowID.configurator)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Choose the real or mock seams. The app defaults to the real socket client,
    /// which speaks the daemon control socket and self-degrades to a calm "daemon
    /// not running" state when the socket is not listening (so no daemon probe is
    /// needed at launch — it tracks the daemon coming up and going down live). It
    /// falls back to the mock when `SIGIL_MOCK=1` (dev, demo, no daemon) so every
    /// screen renders. Previews use the mock directly.
    @MainActor
    private static func makeModel() -> AppModel {
        let useMock = ProcessInfo.processInfo.environment["SIGIL_MOCK"] == "1"
        if useMock {
            return AppModel(daemon: MockDaemonClient(scenario: .pendingRequests))
        }
        return AppModel(daemon: SocketDaemonClient())
    }

    /// Sparkle starts only in a real run. A preview and the SIGIL_MOCK fixture run
    /// both render every screen without a daemon, and neither should reach the
    /// network or offer to replace the bundle it is running from.
    private static func inertReason() -> Updater.Inert? {
        let env = ProcessInfo.processInfo.environment
        if env["XCODE_RUNNING_FOR_PREVIEWS"] == "1" { return .preview }
        if env["SIGIL_MOCK"] == "1" { return .fixture }
        return nil
    }
}

enum WindowID {
    static let configurator = "configurator"
}
