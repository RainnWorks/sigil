//  AccountsView.swift
//  Add a service-account token (live vault probe warns if it sees no usable
//  vault), name it, rotate it, remove it.

import SwiftUI

struct AccountsView: View {
    @Environment(AppModel.self) private var model
    @State private var showingAdd = false
    @State private var rotating: Account?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
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
            Text("No accounts").font(.system(size: 13, weight: .semibold))
            Text("Add a 1Password service-account token. It is encrypted under the DEK; the plaintext is never stored.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            Button("Add account") { showingAdd = true }
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
                StatePill(tone: healthTone, text: account.health.rawValue)
                Spacer()
                if let last = account.lastUsedAt {
                    MonoText("used \(relativeShort(last))", size: 10, color: .secondary)
                }
            }
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
            if let detail = account.detail {
                MonoText(detail, size: 10, color: healthTone.color)
            }
            HStack {
                Spacer()
                Button("Rotate", action: onRotate).buttonStyle(.glass).controlSize(.small)
                Button("Remove", role: .destructive, action: onRemove).buttonStyle(.glass).controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

/// Add or rotate: paste the token, name it, probe vaults live.
struct AddAccountSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var rotating: Account?

    @State private var label = ""
    @State private var token = ""
    @State private var probing = false
    @State private var result: Account?

    private var isRotate: Bool { rotating != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(isRotate ? "Rotate \(rotating!.label)" : "Add account")
                .font(.system(size: 15, weight: .semibold))

            if !isRotate {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Label").font(.system(size: 11)).foregroundStyle(.secondary)
                    TextField("Rowm work", text: $label).textFieldStyle(.roundedBorder)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Service-account token").font(.system(size: 11)).foregroundStyle(.secondary)
                SecureField("ops_eyJ...", text: $token)
                    .textFieldStyle(.roundedBorder)
                    .font(.mono(11))
                Text("Read from this field, encrypted under the DEK, then wiped. Never written in the clear.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }

            if let result {
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

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
                Button(isRotate ? "Rotate" : "Add") { Task { await submit() } }
                    .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    .disabled(token.isEmpty || (!isRotate && label.isEmpty) || probing)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func submit() async {
        probing = true
        defer { probing = false }
        if let rotating {
            result = try? await model.daemon.rotateAccount(id: rotating.id, token: token)
        } else {
            result = await model.addAccount(label: label, token: token)
        }
        token = ""
        if let result, !result.vaults.isEmpty { dismiss() }
        else if result != nil { try? await Task.sleep(for: .seconds(1.2)); dismiss() }
    }
}

#Preview("Accounts") {
    NavigationStack { AccountsView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 640, height: 560)
}
