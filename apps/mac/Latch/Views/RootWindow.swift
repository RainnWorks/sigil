//  RootWindow.swift
//  The configurator: a source-list sidebar and a detail pane, a System Settings
//  sibling. Personal-tool scale.
//
//  The spine of the app is two authoring surfaces, Rules and Sources: a Rule
//  watches for a command and gates it on the phone; a Source is where the secret
//  it injects comes from. Everything else (Status, Pairing, Leases, History,
//  Settings) supports those two. The app gates any command, not one vendor's:
//  1Password is one source among peers, never the app's identity.

import SwiftUI

enum SidebarTab: String, CaseIterable, Identifiable {
    case status, rules, sources, pairing, leases, history, settings
    var id: String { rawValue }

    var title: String {
        switch self {
        case .status: return "Status"
        case .rules: return "Rules"
        case .sources: return "Sources"
        case .pairing: return "Pairing"
        case .leases: return "Leases"
        case .history: return "History"
        case .settings: return "Settings"
        }
    }
    var symbol: String {
        switch self {
        case .status: return "dot.radiowaves.left.and.right"
        case .rules: return "arrow.triangle.branch"
        case .sources: return "key.horizontal"
        case .pairing: return "qrcode"
        case .leases: return "clock.arrow.circlepath"
        case .history: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        }
    }
}

struct RootWindow: View {
    @Environment(AppModel.self) private var model
    @State private var selection: SidebarTab = .status

    var body: some View {
        NavigationSplitView {
            List(SidebarTab.allCases, selection: $selection) { tab in
                NavigationLink(value: tab) {
                    Label(tab.title, systemImage: tab.symbol)
                }
            }
            .navigationSplitViewColumnWidth(min: 168, ideal: 184, max: 220)
            .safeAreaInset(edge: .bottom) { sidebarFooter }
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .navigationTitle("Sigil")
        .task(id: selection) { await model.loadSecondaryScreens() }
    }

    @ViewBuilder private var detail: some View {
        switch selection {
        case .status: StatusView()
        case .rules: RulesView()
        case .sources: SourcesView()
        case .pairing: PairingView()
        case .leases: LeasesView()
        case .history: HistoryView()
        case .settings: SettingsView()
        }
    }

    /// The armed word and lockdown at the foot of the sidebar, always visible.
    private var sidebarFooter: some View {
        let tone: StateTone = switch model.armState {
        case .armed: .armed
        case .lockedDown: .lockedDown
        case .idle: .neutral
        }
        return HStack(spacing: 8) {
            Circle().fill(tone.color).frame(width: 8, height: 8)
            Text(tone.word).font(.system(size: 11, weight: .medium)).foregroundStyle(tone.color)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}

#Preview("Configurator") {
    RootWindow()
        .environment(AppModel(daemon: MockDaemonClient(scenario: .pendingRequests),
                              approver: MockApprover()))
        .frame(width: 820, height: 560)
}
