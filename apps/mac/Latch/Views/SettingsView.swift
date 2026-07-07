//  SettingsView.swift
//  Timeouts, notifications, retention, wipe. Also the Settings scene (Cmd+,).
//  The relay is chosen per pairing (task #36), not here. Voice stays calm and
//  factual.

import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var draft = AppSettings()
    @State private var loaded = false
    @State private var confirmingWipe = false

    var body: some View {
        Form {
            if let error = model.lastError {
                ErrorStrip(message: error)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }

            SwiftUI.Section("Approvals") {
                Stepper(value: $draft.approvalTimeoutSec, in: 30...600, step: 15) {
                    LabeledContent("Request timeout") {
                        MonoText("\(draft.approvalTimeoutSec)s", size: 11, color: .secondary)
                    }
                }
                Toggle("Notifications", isOn: $draft.notificationsEnabled)
                Toggle("Reduce motion (numeric countdowns)", isOn: $draft.reduceMotion)
            }

            SwiftUI.Section("Retention") {
                Stepper(value: $draft.historyRetentionDays, in: 1...365, step: 1) {
                    LabeledContent("Keep history") {
                        MonoText("\(draft.historyRetentionDays)d", size: 11, color: .secondary)
                    }
                }
            }

            SwiftUI.Section("Danger") {
                Button("Wipe all state", role: .destructive) { confirmingWipe = true }
                Text("Removes tokens, pairing, leases, and history. The daemon fails closed until you set it up again.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .task {
            await model.loadSecondaryScreens()
            if !loaded { draft = model.settings; loaded = true }
        }
        .onChange(of: draft) { _, new in Task { await model.saveSettings(new) } }
        .confirmationDialog("Wipe all state?", isPresented: $confirmingWipe, titleVisibility: .visible) {
            Button("Wipe", role: .destructive) { Task { await model.wipe() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This cannot be undone.")
        }
    }
}

#Preview {
    NavigationStack { SettingsView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 460, height: 520)
}
