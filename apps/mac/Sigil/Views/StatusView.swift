//  StatusView.swift
//  `sigil doctor` / status as a native panel: daemon up, shim on PATH + drift,
//  the resolved factor, relay reachability. Whatever checks the daemon reports,
//  rendered as fix-it buttons, not error codes.

import SwiftUI

struct StatusView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if let error = model.lastError { ErrorStrip(message: error) }
                instrumentPanel
                doctorPanel
            }
            .padding(20)
        }
        .navigationTitle("Status")
        .task { await model.refresh(); await model.loadSecondaryScreens() }
    }

    private var header: some View {
        let tone: StateTone = switch model.armState {
        case .armed: .armed; case .lockedDown: .lockedDown; case .idle: .neutral
        }
        return HStack(spacing: 10) {
            Text("sigil").font(.mono(20, weight: .medium)).foregroundStyle(Palette.cobalt)
            StatePill(tone: tone)
            Spacer()
            if model.armState == .lockedDown {
                Button("Unseal") { Task { await model.lockdown(clear: true) } }
                    .buttonStyle(.glassProminent).tint(Palette.rust)
            } else {
                Button("Lock down") { Task { await model.lockdown(clear: false) } }
                    .buttonStyle(.glass)
            }
        }
    }

    @ViewBuilder private var instrumentPanel: some View {
        if let s = model.status {
            Section(title: "Instrument", subtitle: "every gated command needs a lease, else a fresh approval; fails closed") {
                VStack(spacing: 10) {
                    StatusRow(ok: s.daemonUp, warn: false, label: "daemon",
                              value: s.daemonUp ? s.socketPath : "socket not listening", mono: true,
                              fixTitle: s.daemonUp ? nil : "Start",
                              fix: s.daemonUp ? nil : { /* wired: sigil start */ })
                    Divider()
                    StatusRow(ok: s.shim.kind == .healthy, warn: s.shim.kind != .healthy,
                              label: "shim", value: s.shim.issue ?? s.shim.path, mono: true,
                              fixTitle: s.shim.kind == .healthy ? nil : "Install shim",
                              fix: s.shim.kind == .healthy ? nil : { Task { await model.installShim() } })
                }
            }
        } else {
            ProgressView().controlSize(.small)
        }
    }

    @ViewBuilder private var doctorPanel: some View {
        if !model.doctorChecks.isEmpty {
            Section(title: "Doctor", subtitle: "shim drift, factor, relay, socket, op") {
                VStack(spacing: 10) {
                    ForEach(Array(model.doctorChecks.enumerated()), id: \.element.id) { i, c in
                        if i > 0 { Divider() }
                        StatusRow(ok: c.ok, warn: !c.ok, label: c.label,
                                  value: c.hint.isEmpty ? nil : c.hint)
                    }
                }
            }
        }
    }
}

#Preview("Status armed") {
    NavigationStack { StatusView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 640, height: 620)
}

#Preview("Status fail-closed") {
    NavigationStack { StatusView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .failClosed), approver: MockApprover()))
        .frame(width: 640, height: 620)
}
