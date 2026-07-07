//  RulesView.swift
//  The if-this-then-that surface, the whole spine of the configurator. A rule
//  watches for a command you run (match on command, subcommand, argv, flags),
//  gates it on your phone, and injects the write-once environment you gave it.
//  The screen leads with one-tap quick starts so the first rule is never a blank
//  form, then lists the rules you have, each editable in full.
//
//  There is no source or provider surface: 1Password is just a command you gate,
//  and its token is one of the environment values you inject. Everything here
//  drives the `sigil-config` seam (rule verbs, a whole-config import for an edit,
//  and the sealed `source env` values); no gating logic lives in Swift.

import SwiftUI

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var editor: EditorContext?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let error = model.lastError { ErrorStrip(message: error) }
                quickStarts
                rules
            }
            .padding(20)
        }
        .navigationTitle("Rules")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    editor = EditorContext(draft: RuleDraft(), editingName: nil)
                } label: {
                    Label("Add", systemImage: "plus")
                }
            }
        }
        .sheet(item: $editor) { ctx in
            RuleEditorSheet(draft: ctx.draft, editingName: ctx.editingName)
        }
        .task { await model.loadSecondaryScreens() }
    }

    // MARK: quick starts

    private var quickStarts: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Start from a command").font(.system(size: 13, weight: .semibold))
                Text("Pre-fill the command to gate and the environment it wants, then fill in the values. You can always author one from scratch.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 10)], spacing: 10) {
                ForEach(QuickStart.catalog) { start in
                    QuickStartCard(start: start) {
                        editor = EditorContext(draft: start.draft(), editingName: nil)
                    }
                }
            }
        }
    }

    // MARK: rules

    @ViewBuilder private var rules: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Your rules").font(.system(size: 13, weight: .semibold))
            if model.config.rules.isEmpty {
                // Hold the teaching block until the first load lands, so it never
                // flashes before config arrives or on a pane re-select.
                if model.secondaryLoaded { emptyState }
            } else {
                ForEach(model.config.rules) { rule in
                    RuleCard(rule: rule,
                             source: model.config.source(named: rule.action.source),
                             onEdit: {
                                 editor = EditorContext(
                                     draft: RuleDraft(editing: rule, in: model.config),
                                     editingName: rule.name)
                             },
                             onRemove: { Task { await model.removeRule(rule) } })
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No rules yet").font(.system(size: 13, weight: .semibold))
            Text("A rule watches for a command you run and holds it for approval on your phone. It has two parts:")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                modelRow(number: "1", title: "Match", detail: "the command to watch, e.g. op read")
                modelRow(number: "2", title: "Environment", detail: "the KEY=VALUE secrets to hand it, sealed on save")
            }
            .padding(.vertical, 2)
            Text("Pick a command above to start, or add one from scratch.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }

    private func modelRow(number: String, title: String, detail: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(number)
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(Palette.cobalt)
                .frame(width: 16, height: 16)
                .background(Palette.cobalt.opacity(0.12), in: .circle)
            Text(title).font(.system(size: 11, weight: .semibold))
            Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }
}

/// Identifies the editor sheet and carries its starting draft. Its `id` changes
/// per invocation so a quick-start tap always re-presents with fresh defaults.
private struct EditorContext: Identifiable {
    let id = UUID()
    let draft: RuleDraft
    let editingName: String?
}

// MARK: - Quick-start card

private struct QuickStartCard: View {
    let start: QuickStart
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: start.symbol)
                    .font(.system(size: 15))
                    .foregroundStyle(Palette.cobalt)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 3) {
                    Text(start.title).font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text(start.subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .frame(maxWidth: .infinity, minHeight: 76, alignment: .topLeading)
            .background(.background.secondary, in: .rect(cornerRadius: 12))
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Rule card

private struct RuleCard: View {
    let rule: RuleConfig
    let source: SourceConfig?
    let onEdit: () -> Void
    let onRemove: () -> Void

    private var keys: [String] { source?.keys ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text(rule.name).font(.system(size: 13, weight: .semibold))
                Spacer()
            }

            // What it watches for.
            HStack(spacing: 6) {
                Text("when").font(.system(size: 10)).foregroundStyle(.tertiary)
                MonoText(rule.match.summary, size: 11, color: .secondary)
            }

            // What it injects (KEY names only; values are sealed and unreadable).
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("sets").font(.system(size: 10)).foregroundStyle(.tertiary)
                if keys.isEmpty {
                    Text("no environment").font(.system(size: 11)).foregroundStyle(.tertiary)
                } else {
                    FlowKeys(keys: keys)
                }
            }

            HStack {
                Spacer()
                Button("Edit", action: onEdit).buttonStyle(.glass).controlSize(.small)
                Button("Remove", role: .destructive, action: onRemove)
                    .buttonStyle(.glass).controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }
}

/// The KEY names as small mono capsules, wrapping across lines.
private struct FlowKeys: View {
    let keys: [String]
    var body: some View {
        // A rule rarely injects more than a handful of keys, so a simple wrapping
        // HStack via a LazyVGrid of adaptive chips reads cleanly without a custom
        // flow layout.
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 90), spacing: 6, alignment: .leading)],
                  alignment: .leading, spacing: 6) {
            ForEach(keys, id: \.self) { key in
                MonoText(key, size: 11, color: .secondary)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Palette.cobalt.opacity(0.10), in: .capsule)
            }
        }
    }
}

#Preview("Rules") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 720, height: 640)
}
