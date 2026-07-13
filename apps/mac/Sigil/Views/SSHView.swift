//  SSHView.swift
//  The SSH surface. Sigil's agent already serves the user's registered SSH keys
//  and gates every signature through the phone; this pane is where those keys are
//  listed, added, and removed, and where the managed `~/.ssh/config` routing is
//  turned on or off.
//
//  The layering it makes legible: Sigil answers only the hosts a key names
//  (routed through a small managed block in `~/.ssh/config`, the way 1Password's
//  app does it), and every other host stays on the user's normal agent. The floor
//  row at the bottom states that out loud so the pane never reads as "Sigil took
//  over SSH".
//
//  Writes go through the `sigil ssh …` CLI (AppModel), which owns all validation;
//  reads decode `~/.sigil/ssh-keys.json` and check `~/.ssh/config` directly. SSH
//  signing is run-once: every signature is a fresh phone tap, so there is no lease
//  control here.

import SwiftUI

/// Horizontal inset matching the other panes' 20pt content margin.
private let sshContentInset: CGFloat = 20

struct SSHView: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false
    /// The key awaiting a remove confirmation. Removing stops serving it; the
    /// running daemon drops it within a couple of seconds (hot-reloaded).
    @State private var confirmingRemove: SshServedKey?
    /// The generated block, loaded on demand for the "View block" sheet.
    @State private var viewingBlock = false
    @State private var blockText: String?

    private var served: [SshServedKey] { model.sshKeys.served }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let error = model.lastError {
                    ErrorStrip(message: error)
                }
                statusStrip
                keysHeader
                if served.isEmpty {
                    if model.secondaryLoaded { emptyState }
                } else {
                    VStack(spacing: 10) {
                        ForEach(served) { key in
                            SSHKeyCard(key: key) { confirmingRemove = key }
                        }
                    }
                    floorRow
                }
            }
            .padding(.horizontal, sshContentInset)
            .padding(.vertical, 20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .scrollContentBackground(.hidden)
        .navigationTitle("SSH")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { adding = true } label: { Label("Add", systemImage: "plus") }
            }
        }
        .sheet(isPresented: $adding) {
            SSHKeyEditorSheet()
        }
        .sheet(isPresented: $viewingBlock) {
            SSHBlockSheet(text: blockText)
        }
        .confirmationDialog(
            confirmingRemove.map { "Stop serving \($0.label)?" } ?? "Stop serving this key?",
            isPresented: Binding(get: { confirmingRemove != nil },
                                 set: { if !$0 { confirmingRemove = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let key = confirmingRemove { Task { await model.removeSshKey(key) } }
                confirmingRemove = nil
            }
            Button("Cancel", role: .cancel) { confirmingRemove = nil }
        } message: {
            Text("The running agent stops serving it within a couple of seconds.")
        }
        .task { await model.loadSecondaryScreens() }
    }

    // MARK: status strip

    /// The agent's served count and the routing toggle. Honest about what it can
    /// show without parsing CLI text: the served count and a short guidance line,
    /// never a fabricated socket path.
    private var statusStrip: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "terminal")
                    .font(.system(size: 13)).foregroundStyle(Palette.cobalt)
                Text("ssh-agent").font(.system(size: 12, weight: .semibold))
                Text(servedCountText).font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer(minLength: 8)
            }
            Text("Point ssh and git at the agent with the socket from \(Text("sigil sshagent").font(.mono(11))). Every signature is approved on your phone.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            Toggle(isOn: Binding(
                get: { model.sshRoutingInstalled },
                set: { on in Task { await model.setSshRouting(on) } }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sigil manages \(Text("~/.ssh/config").font(.mono(12, weight: .medium)))")
                        .font(.system(size: 12, weight: .medium))
                    Text(routingSubtitle).font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(.switch)
            .tint(Palette.cobalt)

            if model.sshRoutingInstalled {
                Button("View block") {
                    Task {
                        blockText = await model.generatedSshConfig()
                        viewingBlock = true
                    }
                }
                .buttonStyle(.glass).controlSize(.small)
            } else if routedCount == 0 && !served.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "info.circle").font(.system(size: 10)).foregroundStyle(Palette.brass)
                    Text("No key names hosts yet, so there is nothing to route. Add hosts to a key first.")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }

    private var servedCountText: String {
        let n = served.count
        return n == 1 ? "1 key served" : "\(n) keys served"
    }

    private var routedCount: Int { served.filter(\.isRouted).count }

    private var routingSubtitle: String {
        if model.sshRoutingInstalled {
            return "Routed hosts go through Sigil. Every other host stays on your normal agent."
        }
        return "Off. Your normal SSH agent answers every host."
    }

    // MARK: keys

    private var keysHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Served keys").font(.system(size: 13, weight: .semibold))
            if !served.isEmpty {
                Text("Each key is served to the agent. A key that names hosts also routes them through Sigil when routing is on.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No keys served").font(.system(size: 13, weight: .semibold))
            Text("Add a key for the agent to serve. It can live in 1Password (fetched per signature) or be a local key file. Name the hosts you want routed through Sigil, or leave them empty to serve the key without routing.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Every signature is approved on your phone.")
                .font(.system(size: 11)).foregroundStyle(.tertiary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }

    /// The persistent floor: the layer under every served key. Dashed and
    /// non-interactive, it states that unrouted hosts stay on the normal agent.
    private var floorRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "arrow.turn.down.right")
                .font(.system(size: 11)).foregroundStyle(.tertiary)
            Text("Every other host").font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
            Text("\u{b7} unmanaged \u{b7}").font(.system(size: 11)).foregroundStyle(.tertiary)
            Text("your normal SSH agent answers").font(.system(size: 11)).foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(Color.primary.opacity(0.12),
                              style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
        )
    }
}

// MARK: - Served-key card

private struct SSHKeyCard: View {
    let key: SshServedKey
    let onRemove: () -> Void

    @State private var hovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text(key.label).font(.system(size: 13, weight: .semibold))
                    .lineLimit(1).truncationMode(.tail)
                SourceChip(source: key.source)
                Spacer(minLength: 8)
            }

            // The mono reference: op://… or the file path, the identifying content.
            MonoText(key.ref, size: 11, color: .secondary)
                .lineLimit(1).truncationMode(.middle)

            // The fingerprint where we could derive it; otherwise the ref above is
            // the only content shown (a file key stores no public-key line here).
            if let fingerprint = key.fingerprint {
                MonoText(fingerprint, size: 10, color: .secondary)
                    .lineLimit(1).truncationMode(.middle)
            }

            if key.isRouted {
                HStack(alignment: .top, spacing: 6) {
                    Text("routed").font(.system(size: 10)).foregroundStyle(.tertiary).padding(.top, 1)
                    MonoText(key.hosts.joined(separator: "  "), size: 11, color: .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                HStack(spacing: 6) {
                    Image(systemName: "circle.dashed").font(.system(size: 10)).foregroundStyle(.tertiary)
                    Text("served, not routed").font(.system(size: 10)).foregroundStyle(.tertiary)
                    Spacer(minLength: 0)
                }
            }

            HStack {
                Spacer()
                Button("Remove", role: .destructive, action: onRemove)
                    .buttonStyle(.glass).controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(hovering ? Palette.cobalt.opacity(0.30) : Color.primary.opacity(0.08),
                              lineWidth: 1)
        )
        .onHover { hovering = $0 }
    }
}

/// The source chip: 1Password is cobalt-tinted (a key fetched per signature), a
/// key file is a plain neutral chip.
private struct SourceChip: View {
    let source: SshServedKey.Source

    var body: some View {
        Text(source.label)
            .font(.system(size: 10, weight: .medium))
            .foregroundStyle(source == .onePassword ? Palette.cobalt : Color.secondary)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background((source == .onePassword ? Palette.cobalt : Color.secondary).opacity(0.12),
                        in: .capsule)
    }
}

// MARK: - Generated block sheet

/// The generated `~/.sigil/ssh/config` the managed block includes, shown read
/// only so the user can see exactly what routing installed.
private struct SSHBlockSheet: View {
    @Environment(\.dismiss) private var dismiss
    let text: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Managed SSH config").font(.system(size: 15, weight: .semibold))
                Spacer()
            }
            .padding(.horizontal, 20).padding(.vertical, 14)
            Divider()
            ScrollView {
                if let text, !text.isEmpty {
                    MonoText(text, size: 11, color: .primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                } else {
                    Text("No generated block found. It is written when routing is installed and at least one key names hosts.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                }
            }
            .background(Palette.ink.opacity(0.04))
            Divider()
            HStack {
                Text("~/.sigil/ssh/config").font(.mono(10)).foregroundStyle(.tertiary)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(.glass)
            }
            .padding(.horizontal, 20).padding(.vertical, 14)
        }
        .frame(width: 540, height: 460)
    }
}

// MARK: - Previews

#Preview("SSH") {
    NavigationStack { SSHView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 720, height: 640)
}

// Routing on, so the "View block" affordance and the routed-through wording show.
#Preview("SSH - routing on") {
    NavigationStack { SSHView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, sshRouting: true),
                              approver: MockApprover()))
        .frame(width: 720, height: 640)
}

#Preview("SSH - empty") {
    NavigationStack { SSHView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, sshKeys: SshKeyStore()),
                              approver: MockApprover()))
        .frame(width: 720, height: 640)
}
