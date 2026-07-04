//  SettingsView.swift
//  Timeouts, notifications, retention, transport (owned endpoint / relay), wipe.
//  Also the Settings scene (Cmd+,). Voice stays calm and factual.

import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var draft = AppSettings()
    @State private var loaded = false
    @State private var confirmingWipe = false

    var body: some View {
        Form {
            SwiftUI.Section("Approvals") {
                Stepper(value: $draft.approvalTimeoutSec, in: 30...600, step: 15) {
                    LabeledContent("Request timeout") {
                        MonoText("\(draft.approvalTimeoutSec)s", size: 11, color: .secondary)
                    }
                }
                Toggle("Notifications", isOn: $draft.notificationsEnabled)
                Toggle("Reduce motion (numeric countdowns)", isOn: $draft.reduceMotion)
            }

            SwiftUI.Section("Transport") {
                LabeledContent("Relay endpoint") {
                    TextField("https://relay.example", text: $draft.relayURL)
                        .textFieldStyle(.roundedBorder).font(.mono(11)).frame(minWidth: 220)
                }
                Text("The blind mailbox the Mac and phone meet on. Owned endpoint or a shared relay; it only ever carries sealed envelopes.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
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
            Button("Wipe", role: .destructive) { Task { _ = try? await model.daemon.wipe() } }
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
