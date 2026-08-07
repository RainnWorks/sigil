//  LeasesView.swift
//  Active leases with live TTL countdowns and revoke. Creation stays on the
//  approval itself (signed by the phone); this screen only views and revokes.

import SwiftUI

struct LeasesView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let error = model.lastError { ErrorStrip(message: error) }
                if model.leases.isEmpty {
                    empty
                } else {
                    // Each row names its rule and, in the daemon's own words, what
                    // that rule matches. Those words describe a rule, not a command
                    // line, so the breadth is stated once for the whole list rather
                    // than repeated on every row (as `sigil lease list` does).
                    Text("Each lease covers any command its rule matches, run from anywhere on this Mac, until it expires.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    // One shared clock drives every countdown.
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        VStack(spacing: 10) {
                            ForEach(model.leases) { lease in
                                LeaseRow(lease: lease, now: context.date,
                                         reduceMotion: model.settings.reduceMotion,
                                         onRevoke: { Task { await model.revokeLease(lease) } })
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .navigationTitle("Leases")
        .task { await model.refresh() }
    }

    private var empty: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No active leases").font(.system(size: 13, weight: .semibold))
            Text("A lease is granted when you approve with the session option. It covers any command that rule matches, run from anywhere on this Mac, until it expires. A rule that injects sealed values also keeps those values in memory for the window.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

private struct LeaseRow: View {
    let lease: Lease
    let now: Date
    var reduceMotion: Bool
    let onRevoke: () -> Void

    var body: some View {
        let remaining = lease.remaining(now: now)
        let total = lease.expiresAt.timeIntervalSince(lease.grantedAt)
        let fraction = total > 0 ? remaining / total : 0

        HStack(spacing: 14) {
            GaugeRing(fraction: fraction, secondsRemaining: Int(remaining),
                      reduceMotion: reduceMotion, size: 44)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    // The daemon retains the grant key, not the caller provenance,
                    // so `caller` is empty over the socket: lead with the account.
                    if lease.caller.isEmpty {
                        Text(lease.account).font(.system(size: 12, weight: .semibold))
                    } else {
                        Text(lease.caller).font(.system(size: 12, weight: .semibold))
                        Text("·").foregroundStyle(.tertiary)
                        Text(lease.account).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                // `scope` is the matched rule's name, not a command line: the
                // lease auto-approves anything that rule matches for this
                // caller. Next to the name sits the daemon's coverage label for
                // that rule, the same words the approver consented to; without
                // one (an older daemon) the generic breadth stands in.
                HStack(spacing: 5) {
                    MonoText(lease.scope, size: 11, color: .secondary)
                    Text("·").font(.system(size: 11)).foregroundStyle(.tertiary)
                    Text(lease.covers ?? "any matching command")
                        .font(.system(size: 11)).foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                MonoText("grant \(lease.grantHex)  ·  \(clockRemaining(remaining)) left",
                         size: 10, color: Color(.tertiaryLabelColor))
            }
            Spacer()
            Button("Revoke", role: .destructive, action: onRevoke)
                .buttonStyle(.glass).controlSize(.small)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

#Preview {
    NavigationStack { LeasesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle)))
        .frame(width: 640, height: 480)
}
