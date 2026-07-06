//  MenubarContent.swift
//  The menubar pulse: pending requests with Touch ID approve and deny, quick
//  lockdown, a recent-decision peek, and Open Sigil. Admin lives in the window;
//  nothing heavier lives here.

import SwiftUI

struct MenubarContent: View {
    @Environment(AppModel.self) private var model
    let openConfigurator: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .padding(.vertical, 8)
        .task { model.start(); await model.refresh() }
    }

    // MARK: header

    private var header: some View {
        let tone: StateTone = switch model.armState {
        case .armed: .armed; case .lockedDown: .lockedDown; case .idle: .neutral
        }
        return HStack(spacing: 8) {
            Text("latch").font(.mono(13, weight: .medium)).foregroundStyle(Palette.cobalt)
            StatePill(tone: tone)
            Spacer()
            if model.macApprovalsMode == .hardenedPhoneOnly {
                Text("phone-only").font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12).padding(.bottom, 6)
    }

    // MARK: content

    @ViewBuilder private var content: some View {
        if model.armState == .lockedDown {
            peek("Locked down. No requests will be served.", tone: .lockedDown)
        } else if model.pending.isEmpty {
            recentDecisionPeek
        } else {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                VStack(spacing: 8) {
                    ForEach(model.pending) { req in
                        PendingCard(request: req, now: context.date,
                                    reduceMotion: model.settings.reduceMotion,
                                    canApproveLocally: model.macApprovalsMode == .enabled,
                                    onApprove: { lease in Task { await model.approveLocally(req, lease: lease) } },
                                    onDeny: { Task { await model.deny(req) } })
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 6)
            }
        }
    }

    private var recentDecisionPeek: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No requests waiting").font(.system(size: 12)).foregroundStyle(.secondary)
            if let last = model.history.first {
                HStack(spacing: 6) {
                    DecisionDot(decision: last.decision)
                    MonoText(last.label, size: 10, color: .secondary)
                    Spacer()
                    MonoText(relativeShort(last.at), size: 10, color: Color(.tertiaryLabelColor))
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private func peek(_ text: String, tone: StateTone) -> some View {
        HStack(spacing: 6) {
            Circle().fill(tone.color).frame(width: 7, height: 7)
            Text(text).font(.system(size: 11)).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    // MARK: footer

    private var footer: some View {
        HStack(spacing: 8) {
            if model.armState == .lockedDown {
                Button { Task { await model.lockdown(clear: true) } } label: {
                    Label("Unseal", systemImage: "lock.open").font(.system(size: 11))
                }
                .buttonStyle(.glass).tint(Palette.rust)
            } else {
                Button { Task { await model.lockdown(clear: false) } } label: {
                    Label("Lock down", systemImage: "lock").font(.system(size: 11))
                }
                .buttonStyle(.glass)
            }
            Spacer()
            Button("Open Sigil", action: openConfigurator).buttonStyle(.glass)
            Button { NSApplication.shared.terminate(nil) } label: {
                Image(systemName: "power")
            }
            .buttonStyle(.glass)
        }
        .padding(.horizontal, 12).padding(.top, 6)
    }
}

/// A pending request in the menubar: the readout well, provenance, gauge, and
/// the approve/deny controls. Approve is the bespoke sea-green capsule.
private struct PendingCard: View {
    let request: PendingRequest
    let now: Date
    var reduceMotion: Bool
    let canApproveLocally: Bool
    let onApprove: (_ lease: Bool) -> Void
    let onDeny: () -> Void

    private var riskTone: StateTone {
        switch request.risk {
        case .routine: return .neutral
        case .elevated: return .warn
        case .critical: return .denied
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    // Readout well: brightest is the item name / SSH host.
                    Text(request.title).font(.mono(13, weight: .semibold))
                    if let ssh = request.ssh {
                        MonoText(ssh.keyLabel, size: 10, color: .secondary)
                        MonoText(ssh.fingerprint, size: 10, color: .secondary)
                    } else if let secret = request.secrets.first {
                        MonoText(secret.segments.joined(separator: "/"), size: 10, color: .secondary)
                    }
                }
                Spacer()
                GaugeRing(fraction: request.fraction(now: now),
                          secondsRemaining: Int(request.remaining(now: now)),
                          reduceMotion: reduceMotion, size: 38)
            }

            // Provenance, mono, hairline-separated.
            MonoText(request.provenance.processChain.joined(separator: " > "), size: 10, color: .secondary)
            HStack(spacing: 6) {
                MonoText(request.provenance.cwd, size: 10, color: Color(.tertiaryLabelColor))
                if request.coalesced > 0 {
                    Text("+\(request.coalesced) coalesced").font(.system(size: 10)).foregroundStyle(.tertiary)
                }
            }
            if request.risk != .routine, let reason = request.reason {
                HStack(spacing: 5) {
                    StatePill(tone: riskTone, text: request.risk.rawValue)
                    Text(reason).font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }

            if canApproveLocally {
                HStack(spacing: 8) {
                    ApproveCapsule(title: "Approve", enabled: true) { onApprove(false) }
                    Button("Deny", role: .destructive, action: onDeny)
                        .buttonStyle(.glass)
                        .tint(Palette.rust)
                }
                Button("Approve as session lease") { onApprove(true) }
                    .buttonStyle(.plain)
                    .font(.system(size: 10))
                    .foregroundStyle(Palette.seaGreen)
            } else {
                // Hardened / phone-only: degrade, never error.
                HStack(spacing: 6) {
                    Image(systemName: "iphone").foregroundStyle(Palette.cobalt).font(.system(size: 11))
                    Text("Approve on iPhone. This Mac holds no approval envelope.")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }
                Button("Deny", role: .destructive, action: onDeny)
                    .buttonStyle(.glass).tint(Palette.rust).controlSize(.small)
            }
        }
        .padding(12)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

#Preview("Menubar pending") {
    MenubarContent(openConfigurator: {})
        .environment(AppModel(daemon: MockDaemonClient(scenario: .pendingRequests), approver: MockApprover()))
        .frame(width: 320)
}

#Preview("Menubar hardened") {
    MenubarContent(openConfigurator: {})
        .environment(AppModel(daemon: MockDaemonClient(scenario: .hardenedPhoneOnly), approver: MockApprover(macApprovalsEnabled: false)))
        .frame(width: 320)
}

#Preview("Menubar locked") {
    MenubarContent(openConfigurator: {})
        .environment(AppModel(daemon: MockDaemonClient(scenario: .lockedDown), approver: MockApprover()))
        .frame(width: 320)
}
