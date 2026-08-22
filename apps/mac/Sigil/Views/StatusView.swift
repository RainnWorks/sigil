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
                daemonPanel
                keystorePanel
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
        case .armed: .armed; case .idle: .neutral
        }
        return HStack(spacing: 10) {
            Text("sigil").font(.mono(20, weight: .medium)).foregroundStyle(Palette.cobalt)
            StatePill(tone: tone)
            Spacer()
        }
    }

    private var daemonPanel: some View {
        Section(title: "Daemon", subtitle: "the local agent that gates every command. It keeps itself running; repair or restart it here if something looks off") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    StatePill(tone: model.daemonRunning ? .armed : .denied,
                              text: model.daemonRunning ? "Running" : "Stopped")
                    if model.daemonBusy { ProgressView().controlSize(.small) }
                    Spacer(minLength: 12)
                    if let version = model.daemonVersion {
                        MonoText(version, size: 11, color: .secondary)
                    }
                }
                if let path = model.daemonBinaryPath {
                    MonoText(path, size: 11, color: .secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack(spacing: 8) {
                    // No Start button: the app auto-ensures the daemon at
                    // launch (`sigil up`), and Repair reruns the same
                    // idempotent keystone for anything that drifts since.
                    Button("Repair") { Task { await model.ensureUp() } }
                        .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    if model.daemonRunning {
                        Button("Restart") { Task { await model.restartDaemon() } }
                            .buttonStyle(.glass)
                        Button("Stop") { Task { await model.stopDaemon() } }
                            .buttonStyle(.glass)
                    }
                    Spacer()
                }
                .controlSize(.small)
                .disabled(model.daemonBusy)
            }
        }
    }

    /// The at-rest layer: what the keystore file on disk is protected by. Its
    /// subtitle states the scope plainly, because the failure mode of a card like
    /// this is a reader who assumes it protects more than it does.
    private var keystorePanel: some View {
        Section(title: "Keystore",
                subtitle: "the daemon identity and this Mac's share, as they sit on disk; device binding, not runtime protection") {
            KeystoreCard(state: model.keystore.state,
                         notice: model.keystore.adoptionNotice,
                         onRetry: { Task { await model.syncKeystore() } },
                         onRewrap: { Task { await model.rewrapKeystore() } })
        }
    }

    @ViewBuilder private var instrumentPanel: some View {
        if let s = model.status {
            Section(title: "Instrument", subtitle: "every gated command needs a lease, else a fresh approval; fails closed") {
                VStack(spacing: 10) {
                    StatusRow(ok: s.daemonUp, warn: false, label: "daemon",
                              value: s.daemonUp ? s.socketPath : "socket not listening", mono: true,
                              fixTitle: s.daemonUp ? nil : "Repair",
                              fix: s.daemonUp ? nil : { Task { await model.ensureUp() } })
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

/// One state of the at-rest layer. Every case names the file, says what is and
/// is not true of it, and offers a retry only where retrying is the actual fix.
private struct KeystoreCard: View {
    let state: KeystoreProtection
    let notice: String?
    let onRetry: () -> Void
    let onRewrap: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                StatePill(tone: tone, text: word)
                Spacer(minLength: 12)
                if case .checking = state { ProgressView().controlSize(.small) }
                if retryable {
                    Button("Retry", action: onRetry).buttonStyle(.glass).controlSize(.small)
                }
                if state.isAlarm {
                    Button("Wrap again", action: onRewrap)
                        .buttonStyle(.glassProminent).tint(Palette.cobalt).controlSize(.small)
                }
            }
            Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !state.path.isEmpty {
                MonoText(state.path, size: 11, color: Color(.tertiaryLabelColor))
                    .lineLimit(1).truncationMode(.middle)
            }
            // The adoption line, shown on the launch that wrapped the file. Not a
            // sheet and not a congratulation: a fact about a file that changed.
            if let notice {
                Text(notice).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var tone: StateTone {
        switch state {
        case .sealed: return .armed
        case .sealedUnprovisioned, .failed, .downgraded, .downgradeUnverified: return .denied
        case .plaintext, .checking, .absent: return .neutral
        }
    }

    private var word: String {
        switch state {
        case .checking: return "Checking"
        case .absent: return "Empty"
        case .sealed: return "Sealed, open"
        case .sealedUnprovisioned: return "Sealed, not open"
        case .plaintext: return "Plaintext"
        case .downgraded: return "Downgraded"
        // Not "Unknown": what is unknown is the wrapping key, and the file being
        // plaintext is already established. The pill names the thing to act on.
        case .downgradeUnverified: return "Downgrade, unconfirmed"
        case .failed: return "Failed"
        }
    }

    private var detail: String {
        switch state {
        case .checking:
            return "Reading the keystore file."
        case .absent:
            return "No keystore file yet. One appears the first time the daemon stores its identity, and it is wrapped then."
        case .sealed:
            // The scope belongs here rather than in the section subtitle: a reader
            // who has just seen the word "Sealed" is exactly the reader about to
            // over-read it.
            return "Encrypted to this Mac's Secure Enclave and handed to the daemon when it starts, with no prompt. A copy in a backup, a Time Machine snapshot, a synced home folder, or a disk image cannot be opened anywhere else. Anything running as you on this Mac still can, by design, and no secret opens without the phone either way."
        case .sealedUnprovisioned(_, let reason):
            return "The file is sealed but the daemon does not hold it, so every gated command fails closed. \(sentence(reason))"
        case .plaintext(_, let reason):
            return sentence(reason)
        case .downgraded:
            return "The wrapping key is still on this Mac, but the file has gone back to plaintext. No sanctioned unwrap does that: an unwrap destroys the key. Either the file was replaced, or an unwrap stopped halfway. Check where this file came from before wrapping it again."
        case .downgradeUnverified(_, let reason):
            return "The file is plaintext and this Mac would not say whether the wrapping key survived (\(clause(reason))). Until it answers, this counts as a downgrade: wrapping the file again now would overwrite the only evidence of one. Check where this file came from first."
        case .failed(_, let reason):
            return sentence(reason)
        }
    }

    /// Reasons that came from an error start lowercase, matching the CLI's
    /// convention for the same strings. Here they are a sentence in a card, so
    /// they start like one.
    private func sentence(_ text: String) -> String {
        guard let first = text.first else { return text }
        return first.uppercased() + text.dropFirst()
    }

    /// The same strings set inside a sentence rather than as one: keep the
    /// lowercase start, drop a trailing stop that would land next to a bracket.
    private func clause(_ text: String) -> String {
        text.hasSuffix(".") ? String(text.dropLast()) : text
    }

    /// Retry is offered only where the app can actually change the outcome by
    /// trying again. A Mac with no Enclave gets no button to press.
    private var retryable: Bool {
        switch state {
        case .sealedUnprovisioned, .failed: return true
        // No Retry on either downgrade state: re-reading the file cannot change
        // what happened to it, and the deliberate control is "Wrap again". The
        // unconfirmed one does re-evaluate on the next daemon reconnect, and it
        // should: a keychain that answers is strictly better information than one
        // that would not, whichever way it answers.
        case .checking, .absent, .sealed, .plaintext, .downgraded, .downgradeUnverified: return false
        }
    }
}

#Preview("Status armed") {
    NavigationStack { StatusView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle)))
        .frame(width: 640, height: 620)
}

#Preview("Status fail-closed") {
    NavigationStack { StatusView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .failClosed)))
        .frame(width: 640, height: 620)
}

#Preview("Status · daemon stopped") {
    NavigationStack { StatusView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, running: false)))
        .frame(width: 640, height: 660)
}

#Preview("Status · keystore just adopted") {
    NavigationStack { StatusView() }
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .armedIdle),
            keystore: KeystoreCoordinator(
                previewState: .sealed(path: "/Users/you/.sigil/keystore.json"),
                adoptionNotice: "Wrapped to this Mac's Secure Enclave. A copy of the file taken off this Mac can no longer be opened.")))
        .frame(width: 640, height: 700)
}

#Preview("Status · keystore not provisioned") {
    NavigationStack { StatusView() }
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .failClosed),
            keystore: KeystoreCoordinator(previewState: .sealedUnprovisioned(
                path: "/Users/you/.sigil/keystore.json",
                reason: "The daemon refused the keystore material: digest mismatch."))))
        .frame(width: 640, height: 700)
}

#Preview("Status · keystore downgraded") {
    // The alarm state: the wrapping key survives but the file went back to
    // plaintext, which no sanctioned path produces.
    NavigationStack { StatusView() }
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .armedIdle),
            keystore: KeystoreCoordinator(
                previewState: .downgraded(path: "/Users/you/.sigil/keystore.json"))))
        .frame(width: 640, height: 700)
}

#Preview("Status · keystore downgrade unconfirmed") {
    // The same alarm, one certainty short: the file is plaintext and the keychain
    // would not say whether the wrapping key is still there. Rendered as an alarm
    // rather than as the calm plaintext line, because adopting to clear it is
    // exactly what would destroy the evidence.
    NavigationStack { StatusView() }
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .armedIdle),
            keystore: KeystoreCoordinator(previewState: .downgradeUnverified(
                path: "/Users/you/.sigil/keystore.json",
                reason: "keychain lookup failed: User interaction is not allowed."))))
        .frame(width: 640, height: 700)
}

#Preview("Status · no Secure Enclave") {
    NavigationStack { StatusView() }
        .environment(AppModel(
            daemon: MockDaemonClient(scenario: .armedIdle),
            keystore: KeystoreCoordinator(previewState: .plaintext(
                path: "/Users/you/.sigil/keystore.json",
                reason: "This Mac has no Secure Enclave, so the keystore stays a 0600 file. That is the protection it had before, unchanged."))))
        .frame(width: 640, height: 700)
}
