//  HistoryView.swift
//  The audit log as a sortable native table, mono, decision-colored. Never
//  values: the log records what was decided and its provenance, not any secret.

import SwiftUI

struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @State private var sortOrder = [KeyPathComparator(\HistoryEntry.at, order: .reverse)]

    private var rows: [HistoryEntry] { model.history.sorted(using: sortOrder) }

    var body: some View {
        Group {
            if rows.isEmpty {
                ScrollView { empty.padding(20) }
            } else {
                Table(rows, sortOrder: $sortOrder) {
                    TableColumn("When", value: \.at) { entry in
                        MonoText(relativeShort(entry.at), size: 11, color: .secondary)
                    }
                    .width(min: 70, ideal: 80)

                    TableColumn("Decision", value: \.decision.rawValue) { entry in
                        DecisionDot(decision: entry.decision)
                    }
                    .width(min: 84, ideal: 92)

                    TableColumn("Item", value: \.label) { entry in
                        MonoText(entry.label, size: 11)
                    }
                    .width(min: 180, ideal: 240)

                    TableColumn("Process", value: \.process) { entry in
                        MonoText(entry.process, size: 11, color: .secondary)
                    }
                    .width(min: 120, ideal: 160)

                    TableColumn("Via", value: \.via) { entry in
                        Text(entry.via).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    .width(min: 60, ideal: 72)
                }
                .monospacedDigit()
            }
        }
        .navigationTitle("History")
        .task { await model.loadSecondaryScreens() }
    }

    private var empty: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No history yet").font(.system(size: 13, weight: .semibold))
            Text("Every approval, denial, and lockdown lands here as it happens, with its process, account, and how it was decided.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

#Preview {
    NavigationStack { HistoryView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle)))
        .frame(width: 760, height: 420)
}
