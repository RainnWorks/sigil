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
//
//  The rule LIST ORDER is precedence: the daemon resolves a command by first
//  match in config order, so the rule higher in the list wins. The list is a
//  native reorderable List (drag a rule up or down via `.onMove`), and each move
//  is persisted by reordering the config's rules array through the same
//  export -> mutate -> import seam an edit uses (AppModel.moveRules).

import SwiftUI

/// Horizontal inset matching the other panes' 20pt content padding. The screen
/// is a plain `List` (so quick starts and rules scroll together and the rules can
/// be dragged to reorder), which zeroes the default row insets, so every row
/// restores this margin itself.
private let contentInset: CGFloat = 20

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var editor: EditorContext?
    /// The rule awaiting a remove confirmation. Removing a rule also purges its
    /// sealed values, which cannot be recovered, so it is a deliberate two-step.
    @State private var confirmingRemove: RuleConfig?

    var body: some View {
        List {
            if let error = model.lastError {
                ErrorStrip(message: error)
                    .row(top: 20, bottom: 0)
            }
            quickStarts
                .row(top: model.lastError == nil ? 20 : 16, bottom: 20)
            rulesHeader
                .row(top: 0, bottom: 8)
            if model.config.rules.isEmpty {
                // Hold the teaching block until the first load lands, so it never
                // flashes before config arrives or on a pane re-select.
                if model.secondaryLoaded {
                    emptyState.row(top: 0, bottom: 20)
                }
            } else {
                ForEach(model.config.rules) { rule in
                    RuleCard(rule: rule,
                             rank: rank(of: rule),
                             source: model.config.source(named: rule.action.source),
                             onEdit: {
                                 editor = EditorContext(
                                     draft: RuleDraft(editing: rule, in: model.config),
                                     editingName: rule.name)
                             },
                             onRemove: { confirmingRemove = rule })
                        .row(top: 0, bottom: 10)
                }
                // Dragging a rule up or down rewrites its precedence; the move is
                // persisted by reordering the config's rules array (AppModel).
                .onMove { model.moveRules(from: $0, to: $1) }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
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
        .confirmationDialog(
            confirmingRemove.map { "Remove rule \($0.match.summary)?" } ?? "Remove rule?",
            isPresented: Binding(get: { confirmingRemove != nil },
                                 set: { if !$0 { confirmingRemove = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let rule = confirmingRemove { Task { await model.removeRule(rule) } }
                confirmingRemove = nil
            }
            Button("Cancel", role: .cancel) { confirmingRemove = nil }
        } message: {
            Text("Its sealed values cannot be recovered.")
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

    /// The section title and, once there are rules, the one quiet line that makes
    /// the ordering's meaning legible: the list is precedence, top wins.
    private var rulesHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Your rules").font(.system(size: 13, weight: .semibold))
            if !model.config.rules.isEmpty {
                Text("Checked top to bottom; the first match wins. Drag to reorder.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// A rule's 1-based precedence, its position in the config order. Shown on the
    /// card so the ordering reads as ranked, not incidental.
    private func rank(of rule: RuleConfig) -> Int {
        (model.config.rules.firstIndex { $0.id == rule.id } ?? 0) + 1
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
    let rank: Int
    let source: SourceConfig?
    let onEdit: () -> Void
    let onRemove: () -> Void

    private var keys: [String] { source?.keys ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // A rule is its match: the match summary is the label (it may repeat
            // across rules; the user drags to order them and the higher one wins).
            // The grip signals the whole row is draggable; the rank names its
            // precedence, so the ordering reads as deliberate.
            HStack(spacing: 8) {
                Image(systemName: "line.3.horizontal")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
                Text("when").font(.system(size: 10)).foregroundStyle(.tertiary)
                Text(rule.match.summary).font(.mono(13, weight: .medium))
                Spacer()
                Text("#\(rank)").font(.mono(10)).foregroundStyle(.tertiary)
                    .accessibilityLabel("Precedence \(rank)")
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

// MARK: - Row styling

private extension View {
    /// Restore the pane's content margins and card rhythm on a plain-`List` row:
    /// no separator, no row fill (the card carries its own background), the shared
    /// horizontal inset, and the caller's vertical gaps.
    func row(top: CGFloat, bottom: CGFloat) -> some View {
        self.listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: top, leading: contentInset,
                                      bottom: bottom, trailing: contentInset))
    }
}

#Preview("Rules") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 720, height: 640)
}

// A layered list where two rules match the same base command: the specific
// `op --account=prod` sits above the general `op`, so it wins first. This is the
// precedence the drag-to-reorder exists to author.
#Preview("Rules - ordering") {
    let layered = SigilConfig(
        version: 1,
        sources: [
            SourceConfig(name: "op-prod", provider: "env", keys: ["OP_SERVICE_ACCOUNT_TOKEN"]),
            SourceConfig(name: "op", provider: "env", keys: ["OP_SERVICE_ACCOUNT_TOKEN"]),
            SourceConfig(name: "aws", provider: "env",
                         keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
        ],
        rules: [
            RuleConfig(name: "op-prod",
                       match: MatchConfig(command: "op",
                                          flagEquals: [FlagEqConfig(flag: "--account", value: "prod")]),
                       action: ActionConfig(source: "op-prod", risk: "routine", timeoutSec: nil)),
            RuleConfig(name: "op",
                       match: MatchConfig(command: "op"),
                       action: ActionConfig(source: "op", risk: "routine", timeoutSec: nil)),
            RuleConfig(name: "aws",
                       match: MatchConfig(command: "aws"),
                       action: ActionConfig(source: "aws", risk: "routine", timeoutSec: nil)),
        ])
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, config: layered),
                              approver: MockApprover()))
        .frame(width: 720, height: 640)
}

#Preview("Rules - empty") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, config: SigilConfig()),
                              approver: MockApprover()))
        .frame(width: 720, height: 640)
}
