//  MenubarContent.swift
//  The menubar pulse: pending requests with a deny and an "approve on iPhone"
//  pointer, a recent-decision peek, and Open Sigil. Approving is the phone's job
//  (a request unseals only with the phone's per-approval partial), so this Mac
//  never approves locally. Admin lives in the window; nothing heavier lives here.

import SwiftUI

struct MenubarContent: View {
    @Environment(AppModel.self) private var model
    let openConfigurator: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if let error = model.lastError { errorStrip(error) }
            if model.keystore.state.blocksDaemon || model.keystore.state.isAlarm { keystoreStrip }
            Divider()
            content
            Divider()
            footer
        }
        .padding(.vertical, 8)
        .task { model.start(); await model.refresh() }
    }

    /// A compact ErrorStrip for the ~320pt popover: the Deny control here routes
    /// through AppModel.performControl, which already captures a refusal or a
    /// failure into `lastError` - this
    /// is what makes that visible. Without it a failed deny reads as a
    /// successful one: the popover just sits there looking unchanged, and the
    /// person walks away believing they denied something they did not.
    private func errorStrip(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(Palette.brass).font(.system(size: 10))
            Text(message).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    /// The at-rest layer, but only in the states that earn a line here: the
    /// daemon cannot work, or the protection was removed by something other than
    /// the sanctioned unwrap. Silence in the first case would leave the popover
    /// looking idle while nothing could possibly run; silence in the second would
    /// hide the only evidence that the file was replaced.
    ///
    /// Four states reach this strip, so it branches four ways. They are
    /// sealed-and-unusable, could-not-be-opened, protection-removed, and
    /// protection-removed-but-unconfirmed: different facts with different fixes,
    /// and collapsing any of them told a person the wrong thing to go and do.
    ///
    /// The glyph is never `exclamationmark.triangle`: `errorStrip` above already
    /// owns that shape in brass, and two triangles in different colors stacked in
    /// one popover read as one thing shouting twice. These carry lock shapes,
    /// which differ from each other and from the triangle without relying on color.
    private var keystoreStrip: some View {
        let (glyph, headline, action): (String, String, String) = switch model.keystore.state {
        case .downgraded:
            ("lock.open", "Keystore protection was removed outside Sigil.", "Open Sigil to see what happened.")
        case .downgradeUnverified:
            // A distinct shape, not a softer wording of the same one: the file is
            // plaintext either way, and the difference is only whether this Mac
            // would confirm it. The strip says which of the two it is looking at.
            ("lock.trianglebadge.exclamationmark",
             "Keystore plaintext; this Mac will not say whether its key survived.",
             "Open Sigil to see what happened.")
        case .failed:
            ("xmark.octagon", "The keystore could not be opened.", "Open Sigil for the reason.")
        default:
            // Sealed but not open. Nothing else reaches this strip: it renders
            // only for the states that block the daemon or raise the alarm.
            ("lock", "Keystore sealed, not open. The daemon does not hold it.", "Open Sigil to provision it.")
        }
        return HStack(alignment: .top, spacing: 6) {
            Image(systemName: glyph).foregroundStyle(Palette.rust).font(.system(size: 10))
            VStack(alignment: .leading, spacing: 2) {
                Text(headline).font(.system(size: 10)).foregroundStyle(.secondary)
                Text(action).font(.system(size: 10)).foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    // MARK: header

    private var header: some View {
        let tone: StateTone = switch model.armState {
        case .armed: .armed; case .idle: .neutral
        }
        return HStack(spacing: 8) {
            Text("sigil").font(.mono(13, weight: .medium)).foregroundStyle(Palette.cobalt)
            StatePill(tone: tone)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.bottom, 6)
    }

    // MARK: content

    @ViewBuilder private var content: some View {
        if model.pending.isEmpty {
            recentDecisionPeek
        } else {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                VStack(spacing: 8) {
                    ForEach(model.pending) { req in
                        PendingCard(request: req, now: context.date,
                                    reduceMotion: model.settings.reduceMotion,
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

    // MARK: footer

    private var footer: some View {
        HStack(spacing: 8) {
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
/// the deny control. Approving happens on the iPhone, so the card points there
/// and never offers a local approve.
private struct PendingCard: View {
    let request: PendingRequest
    let now: Date
    var reduceMotion: Bool
    let onDeny: () -> Void

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
                Spacer()
                // Sent until the phone acknowledges receipt, then Delivered. A
                // missing receipt just stays Sent; it never blocks approval.
                Text(request.delivered ? "Delivered" : "Sent")
                    .font(.system(size: 10))
                    .foregroundStyle(request.delivered ? Palette.seaGreen : Color(.tertiaryLabelColor))
            }
            if let reason = request.reason {
                Text(reason).font(.system(size: 10)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Approving is the phone's job: a request unseals only with the
            // phone's per-approval partial, so the Mac points there. Deny needs
            // nothing and stays here.
            HStack(spacing: 6) {
                Image(systemName: "iphone").foregroundStyle(Palette.cobalt).font(.system(size: 11))
                Text("Approve on your iPhone.")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            Button("Deny", role: .destructive, action: onDeny)
                .buttonStyle(.glass).tint(Palette.rust).controlSize(.small)
        }
        .padding(12)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

#Preview("Menubar pending") {
    MenubarContent(openConfigurator: {})
        .environment(AppModel(daemon: MockDaemonClient(scenario: .pendingRequests)))
        .frame(width: 320)
}

#Preview("Menubar keystore sealed") {
    // The daemon is up but holds no keystore material, so nothing can run. The
    // popover has to say why rather than look merely idle.
    MenubarContent(openConfigurator: {})
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .armedIdle),
            keystore: KeystoreCoordinator(previewState: .sealedUnprovisioned(
                path: "/Users/you/.sigil/keystore.json",
                reason: "The daemon refused the keystore material: digest mismatch."))))
        .frame(width: 320)
}

#Preview("Menubar deny failed") {
    // The state a silently-failed deny would otherwise hide: lastError set,
    // nothing else about the popover changed.
    let model = AppModel(daemon: MockDaemonClient(scenario: .pendingRequests))
    model.lastError = "daemon unreachable: socket not listening"
    return MenubarContent(openConfigurator: {})
        .environment(model)
        .frame(width: 320)
}
