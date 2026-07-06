//  PairingView.swift
//  The QR + six-word fingerprint ceremony, the paired-device list, the "Enable
//  Mac approvals" toggle and its hardened phone-only opposite.

import SwiftUI

struct PairingView: View {
    @Environment(AppModel.self) private var model
    @State private var relayURL = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let paired = model.paired {
                    pairedList(paired)
                    macApprovalsToggle
                    Divider()
                    Text("Re-pair").font(.system(size: 13, weight: .semibold))
                    Text("Pairing again replaces the current phone.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                ceremonyPanel
            }
            .padding(20)
        }
        .navigationTitle("Pairing")
        .onAppear { if relayURL.isEmpty { relayURL = model.paired?.relayURL ?? model.settings.relayURL } }
    }

    private func pairedList(_ paired: PairedDevice) -> some View {
        Section(title: "Paired device") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "iphone").foregroundStyle(Palette.cobalt)
                    Text(paired.name).font(.system(size: 13, weight: .medium))
                    Spacer()
                    MonoText("since \(relativeShort(paired.pairedAt))", size: 10, color: .secondary)
                }
                HStack(spacing: 6) {
                    Text("fingerprint").font(.system(size: 10)).foregroundStyle(.tertiary)
                    MonoText(paired.sasWords.joined(separator: " · "), size: 11, color: Palette.cobalt)
                }
                MonoText(paired.relayURL, size: 10, color: .secondary)
                HStack {
                    Spacer()
                    Button("Unpair", role: .destructive) { Task { await model.unpair() } }
                        .buttonStyle(.glass).controlSize(.small)
                }
            }
        }
    }

    private var macApprovalsToggle: some View {
        let enabled = model.macApprovalsMode == .enabled
        return Section(title: "Mac approvals",
                       subtitle: "Local approval is a real factor: a live Touch ID unwraps the DEK inside the Secure Enclave. Malware running as you cannot fake it.") {
            VStack(alignment: .leading, spacing: 10) {
                Toggle(isOn: Binding(
                    get: { enabled },
                    set: { on in Task { await model.setMacApprovals(on ? .enabled : .hardenedPhoneOnly) } }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Enable Mac approvals").font(.system(size: 12, weight: .medium))
                        Text(enabled
                             ? "This Mac holds a Secure Enclave envelope of the DEK; the menubar can approve under Touch ID."
                             : "Hardened, phone-only. This Mac cannot approve; every request needs the iPhone.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.switch)
                .tint(Palette.seaGreen)

                if !model.approver.biometricsAvailable {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(Palette.brass)
                        Text("No usable Touch ID on this Mac. Approvals stay phone-only.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    @ViewBuilder private var ceremonyPanel: some View {
        switch model.ceremony {
        case .idle:
            if model.paired == nil { startPanel }
        case .awaitingPhone(let payload):
            ceremonyStep {
                QRCodeView(payload: payload)
                Text("Scan this with the Latch approver on your phone.")
                    .font(.system(size: 12))
                Text("Waiting for the phone to respond...")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                ProgressView().controlSize(.small)
            }
        case .confirmSAS(let words):
            ceremonyStep {
                Text("Confirm these six words match your phone's screen.")
                    .font(.system(size: 12))
                MonoText(words.joined(separator: " · "), size: 15, color: Palette.cobalt, weight: .medium)
                Text("Reading them aloud is the human backstop; a mismatch is loud. The key is not sent until you confirm.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button("Doesn't match", role: .destructive) { model.confirmSAS(match: false) }
                        .buttonStyle(.glass).controlSize(.small)
                    Button("Words match") { model.confirmSAS(match: true) }
                        .buttonStyle(.glassProminent).tint(Palette.seaGreen).controlSize(.small)
                }
            }
        case .paired(let device):
            ceremonyStep {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(Palette.seaGreen)
                    Text("Paired with \(device.name).").font(.system(size: 13, weight: .medium))
                }
                Text("The daemon now gates every request on your phone.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        case .failed(let reason):
            ceremonyStep {
                HStack(spacing: 8) {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(Palette.rust)
                    Text("Pairing failed.").font(.system(size: 13, weight: .medium))
                }
                MonoText(reason, size: 11, color: .secondary)
                Button("Try again") { model.ceremony = .idle }.buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    private var startPanel: some View {
        Section(title: "Pair a phone",
                subtitle: "The relay is the blind mailbox the Mac and phone meet on. Use your own relay URL.") {
            VStack(alignment: .leading, spacing: 10) {
                TextField("https://relay.example", text: $relayURL)
                    .textFieldStyle(.roundedBorder).font(.mono(11))
                Button("Render QR") { model.beginPairing(relayURL: relayURL) }
                    .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    .disabled(relayURL.isEmpty)
            }
        }
    }

    private func ceremonyStep<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10, content: content)
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

#Preview("Paired") {
    NavigationStack { PairingView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 640, height: 640)
}

#Preview("Unpaired") {
    NavigationStack { PairingView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .failClosed), approver: MockApprover()))
        .frame(width: 640, height: 560)
}
