//  SSHKeyEditorSheet.swift
//  Add a served SSH key from a local key file: the CLI reads the sibling `.pub`
//  for the public line and the private key is read only at sign time. The draft
//  carries an optional label and the hosts to route through Sigil. It never
//  authors config in Swift; Save hands the draft to the model, which drives the
//  `sigil ssh …` verbs, and the CLI does all validation (ed25519, dedupe, safe
//  host tokens), so a refusal surfaces its own message.
//
//  Only the key-file source is offered right now. A threshold "stored key"
//  source (Sigil holds the private key, sealed, opened per-sign with the phone)
//  is planned; the 1Password path is a gated-command source that is not surfaced
//  here yet. See docs/design/secret-model.md.

import SwiftUI

struct SSHKeyEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var draft = SSHKeyDraft()
    @State private var saving = false

    /// Why Save is blocked, or nil. The CLI validates for real; this only stops an
    /// obviously incomplete draft from a round trip that would just be refused.
    private var blocker: String? {
        if draft.path.trimmed.isEmpty { return "Give the path to the private key." }
        return nil
    }

    private var canSave: Bool { blocker == nil && !saving }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let error = model.lastError { ErrorStrip(message: error) }
                    fileSection
                    hostsSection
                    labelSection
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 540, height: 560)
    }

    private var header: some View {
        HStack {
            Text("Add SSH key").font(.system(size: 15, weight: .semibold))
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var footer: some View {
        VStack(spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "info.circle").font(.system(size: 9)).foregroundStyle(.tertiary)
                Text("The destination shown on your phone is best-effort context, not a verified hostname. A new key is served within a couple of seconds.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            HStack {
                Text(blocker ?? " ").font(.system(size: 10)).foregroundStyle(.tertiary)
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
                Button("Add key") { Task { await save() } }
                    .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    .disabled(!canSave)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: key-file source

    private var fileSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Key file", "Sigil serves a local key file to the agent and gates every signature on your phone. A threshold stored-key source is planned.")
            labelled("Private key path") {
                VStack(alignment: .leading, spacing: 4) {
                    TextField("~/.ssh/id_ed25519", text: $draft.path)
                        .textFieldStyle(.roundedBorder).font(.mono(11))
                    Text("The sibling .pub next to it supplies the public key. The private key is read only at sign time.")
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: hosts + label

    private var hostsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Routed hosts", "The hosts to send through Sigil for this key, when routing is on. Leave empty to serve the key without routing any host.")
            TokenListEditor(title: "Hosts", placeholder: "github.com", tokens: $draft.hosts)
        }
    }

    private var labelSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Label", "An optional comment. When empty, the public key line's own comment is used.")
            TextField("optional", text: $draft.comment)
                .textFieldStyle(.roundedBorder).font(.system(size: 11))
        }
    }

    // MARK: save

    private func save() async {
        saving = true
        defer { saving = false }
        if await model.saveSshKey(draft) { dismiss() }
    }

    // MARK: small view builders

    private func sectionTitle(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 12, weight: .semibold))
            Text(subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func labelled<Content: View>(_ title: String,
                                         @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            content()
        }
    }
}

#Preview("Add SSH key") {
    SSHKeyEditorSheet()
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle)))
}
