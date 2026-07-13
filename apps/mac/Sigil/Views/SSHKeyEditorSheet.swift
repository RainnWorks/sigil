//  SSHKeyEditorSheet.swift
//  Add a served SSH key: a 1Password reference (the private key is fetched per
//  signature; only the public line is stored here) or a local key file (the CLI
//  reads the sibling `.pub`). Both carry an optional label and the hosts to route
//  through Sigil. It never authors config in Swift; Save hands the draft to the
//  model, which drives the `sigil ssh …` verbs, and the CLI does all validation
//  (ed25519, dedupe, safe host tokens), so a refusal surfaces its own message.
//
//  There are exactly two sources: 1Password and Key file. A Secure Enclave signer
//  is not built, so it is not offered here.

import SwiftUI

struct SSHKeyEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var draft = SSHKeyDraft()
    @State private var saving = false

    /// Why Save is blocked, or nil. The CLI validates for real; these only stop an
    /// obviously incomplete draft from a round trip that would just be refused.
    private var blocker: String? {
        switch draft.source {
        case .onePassword:
            if draft.vault.trimmed.isEmpty || draft.item.trimmed.isEmpty {
                return "Name the vault and item."
            }
            if draft.publicKey.trimmed.isEmpty { return "Paste the public key line." }
        case .file:
            if draft.path.trimmed.isEmpty { return "Give the path to the private key." }
        }
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
                    sourceSection
                    switch draft.source {
                    case .onePassword: onePasswordSection
                    case .file: fileSection
                    }
                    hostsSection
                    labelSection
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 540, height: 640)
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

    // MARK: source

    private var sourceSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Source", "Where the key lives. A 1Password key is fetched per signature; a key file is read from disk at sign time.")
            Picker("Source", selection: $draft.source) {
                Text("1Password").tag(SSHKeyDraft.Source.onePassword)
                Text("Key file").tag(SSHKeyDraft.Source.file)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
        }
    }

    // MARK: 1Password branch

    private var onePasswordSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            twoUp(
                labelled("Vault") {
                    TextField("Engineering", text: $draft.vault)
                        .textFieldStyle(.roundedBorder).font(.mono(11))
                },
                labelled("Item") {
                    TextField("GitHub", text: $draft.item)
                        .textFieldStyle(.roundedBorder).font(.mono(11))
                }
            )
            labelled("Field") {
                TextField("private key", text: $draft.field)
                    .textFieldStyle(.roundedBorder).font(.mono(11))
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Reference").font(.system(size: 11)).foregroundStyle(.secondary)
                MonoText(draft.opReference, size: 11, color: Palette.cobalt)
                    .lineLimit(1).truncationMode(.middle)
            }

            labelled("Public key") {
                VStack(alignment: .leading, spacing: 4) {
                    TextField("ssh-ed25519 AAAA\u{2026} comment", text: $draft.publicKey, axis: .vertical)
                        .textFieldStyle(.roundedBorder).font(.mono(11))
                        .lineLimit(3...6)
                    Text("The public key line only. The private key stays in 1Password and is fetched per signature.")
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: key-file branch

    private var fileSection: some View {
        VStack(alignment: .leading, spacing: 12) {
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

    private func twoUp<A: View, B: View>(_ a: A, _ b: B) -> some View {
        HStack(alignment: .top, spacing: 12) { a; b }
    }
}

#Preview("Add SSH key") {
    SSHKeyEditorSheet()
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}
