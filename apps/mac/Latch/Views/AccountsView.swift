//  AccountsView.swift
//  Configured secret sources: a 1Password service-account token (live vault
//  probe warns if it sees no usable vault) or an env-file path. 1Password is
//  provider #1, not the only shape; add starts with a provider picker.

import SwiftUI
import UniformTypeIdentifiers

struct AccountsView: View {
    @Environment(AppModel.self) private var model
    @State private var showingAdd = false
    @State private var rotating: Account?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let error = model.lastError { ErrorStrip(message: error) }
                if model.accounts.isEmpty {
                    emptyState
                } else {
                    ForEach(model.accounts) { account in
                        AccountCard(account: account,
                                    onRotate: { rotating = account },
                                    onRemove: { Task { await model.removeAccount(account) } })
                    }
                }
            }
            .padding(20)
        }
        .navigationTitle("Accounts")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showingAdd = true } label: { Label("Add", systemImage: "plus") }
            }
        }
        .sheet(isPresented: $showingAdd) { AddAccountSheet() }
        .sheet(item: $rotating) { account in AddAccountSheet(rotating: account) }
        .task { await model.loadSecondaryScreens() }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No sources").font(.system(size: 13, weight: .semibold))
            Text("Add a 1Password service-account token or an env file. Either way, secret values never leave the source the daemon reads them from.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            Button("Add a source") { showingAdd = true }
                .buttonStyle(.glassProminent).tint(Palette.cobalt).padding(.top, 4)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

private struct AccountCard: View {
    let account: Account
    let onRotate: () -> Void
    let onRemove: () -> Void

    private var healthTone: StateTone {
        switch account.health {
        case .healthy: return .approved
        case .rotate: return .denied
        case .expiring: return .warn
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(account.label).font(.system(size: 13, weight: .semibold))
                StatePill(tone: .neutral, text: account.provider.displayName)
                if account.provider == .onePassword {
                    StatePill(tone: healthTone, text: account.health.rawValue)
                }
                Spacer()
                if let last = account.lastUsedAt {
                    MonoText("used \(relativeShort(last))", size: 10, color: .secondary)
                }
            }
            switch account.provider {
            case .onePassword:
                if account.vaults.isEmpty {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(Palette.brass).font(.system(size: 11))
                        Text("No usable vault visible to this token. Service accounts cannot see built-in Personal or Shared vaults.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                } else {
                    HStack(spacing: 6) {
                        Text("vaults").font(.system(size: 10)).foregroundStyle(.tertiary)
                        ForEach(account.vaults, id: \.self) { v in
                            MonoText(v, size: 11, color: .secondary)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Palette.cobalt.opacity(0.10), in: .capsule)
                        }
                    }
                }
            case .envFile:
                HStack(spacing: 6) {
                    Text("file").font(.system(size: 10)).foregroundStyle(.tertiary)
                    MonoText(account.path ?? "", size: 11, color: .secondary)
                }
            }
            if let detail = account.detail {
                MonoText(detail, size: 10, color: healthTone.color)
            }
            HStack {
                Spacer()
                // Rotate replaces a stored token; an env-file source has none,
                // just a path to reconfigure by removing and re-adding it.
                if account.provider == .onePassword {
                    Button("Rotate", action: onRotate).buttonStyle(.glass).controlSize(.small)
                }
                Button("Remove", role: .destructive, action: onRemove).buttonStyle(.glass).controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

/// Add or rotate. Rotate only ever applies to a 1Password account (replacing
/// its token), so it skips the picker; adding starts by choosing a provider,
/// then shows only that provider's fields; a service-account token for
/// 1Password, a file path for env-file. Neither shape leaks into the other.
struct AddAccountSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var rotating: Account?

    @State private var provider: SourceProvider = .onePassword
    @State private var label = ""
    @State private var token = ""
    @State private var name = ""
    @State private var path = ""
    @State private var showingFileImporter = false
    @State private var probing = false
    @State private var result: Account?

    private var isRotate: Bool { rotating != nil }

    private var canSubmit: Bool {
        if isRotate { return !token.isEmpty }
        switch provider {
        case .onePassword: return !label.isEmpty && !token.isEmpty
        case .envFile: return !name.isEmpty && !path.isEmpty
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(isRotate ? "Rotate \(rotating!.label)" : "Add a source")
                .font(.system(size: 15, weight: .semibold))

            if let error = model.lastError { ErrorStrip(message: error) }

            if !isRotate {
                Picker("Provider", selection: $provider) {
                    ForEach(SourceProvider.allCases) { p in Text(p.displayName).tag(p) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }

            if isRotate {
                tokenField
            } else {
                switch provider {
                case .onePassword:
                    labelField
                    tokenField
                case .envFile:
                    nameField
                    pathField
                }
            }

            if let result, result.provider == .onePassword {
                probeResult(result)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
                Button(isRotate ? "Rotate" : "Add") { Task { await submit() } }
                    .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    .disabled(!canSubmit || probing)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private var labelField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Label").font(.system(size: 11)).foregroundStyle(.secondary)
            TextField("Rowm work", text: $label).textFieldStyle(.roundedBorder)
        }
    }

    private var tokenField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Service-account token").font(.system(size: 11)).foregroundStyle(.secondary)
            SecureField("ops_eyJ...", text: $token)
                .textFieldStyle(.roundedBorder)
                .font(.mono(11))
            Text("Read from this field, encrypted under the DEK, then wiped. Never written in the clear.")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
    }

    private var nameField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Name").font(.system(size: 11)).foregroundStyle(.secondary)
            TextField("ci-secrets", text: $name).textFieldStyle(.roundedBorder)
        }
    }

    private var pathField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("File").font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                TextField("/path/to/secrets.env", text: $path)
                    .textFieldStyle(.roundedBorder).font(.mono(11))
                Button("Choose") { showingFileImporter = true }.buttonStyle(.glass)
            }
            Text("A KEY=VALUE file. Its values are read only after an approval, and only for the moment the command runs.")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
        .fileImporter(isPresented: $showingFileImporter, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result { path = url.path }
        }
    }

    private func probeResult(_ result: Account) -> some View {
        Group {
            if result.vaults.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(Palette.brass)
                    Text("Probed: no usable vault visible to this token.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
            } else {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.seaGreen)
                    Text("Probed vaults: \(result.vaults.joined(separator: ", "))")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func submit() async {
        probing = true
        defer { probing = false }
        if let rotating {
            result = await model.rotateAccount(id: rotating.id, token: token)
        } else {
            let draft: AccountDraft = provider == .onePassword
                ? .onePassword(label: label, token: token)
                : .envFile(name: name, path: path)
            result = await model.addAccount(draft)
        }
        token = ""
        guard let result else { return }   // failed; model.lastError is set, sheet stays open
        if result.provider == .envFile || !result.vaults.isEmpty {
            dismiss()
        } else {
            try? await Task.sleep(for: .seconds(1.2))
            dismiss()
        }
    }
}

#Preview("Accounts") {
    NavigationStack { AccountsView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 640, height: 560)
}
