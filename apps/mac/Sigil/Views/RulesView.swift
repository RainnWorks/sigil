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

    /// Hover lifts the whole card: the border warms to cobalt and the grip lights
    /// up, so a row reads as a distinct, grabbable object rather than a flat blob.
    @State private var hovering = false
    /// The env KEY names this rule injects. `export` drops the keys of an env
    /// source with no sealed value, so an unsealed source arrives here empty and
    /// reads as a plain gate ("no environment"), never as falsely "set".
    private var keys: [String] { source?.keys ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Primary line: the match is what the rule IS. The grip on the left
            // signals the whole row lifts to reorder; the rank on the right names
            // its precedence (top = #1 = wins first). The summary may repeat across
            // rules, and the user drags to order them, so the higher one wins.
            HStack(spacing: 8) {
                grip
                Text("when").font(.system(size: 10)).foregroundStyle(.tertiary)
                Text(rule.match.summary).font(.mono(13, weight: .medium))
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 8)
                Text("#\(rank)").font(.mono(11, weight: .medium)).foregroundStyle(.secondary)
                    .accessibilityLabel("Precedence \(rank)")
            }

            // Secondary line: an allow rule reads plainly as a passthrough; a gate
            // rule shows the KEY names it injects (values sealed, never shown) and,
            // when leasable, its session-lease cap.
            if rule.action.mode == .allow {
                allowLine
            } else {
                HStack(alignment: .top, spacing: 6) {
                    Text("sets").font(.system(size: 10)).foregroundStyle(.tertiary)
                        .padding(.top, 3)
                    if keys.isEmpty {
                        Text("no environment").font(.system(size: 11)).foregroundStyle(.tertiary)
                            .padding(.top, 1)
                    } else {
                        FlowKeys(keys: keys)
                    }
                }
                if case .leasable(let cap) = rule.action.lease { leaseLine(cap) }
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
        .overlay(
            // A hairline edge gives each card its own footprint against the pane;
            // it warms on hover to reinforce that the row is liftable.
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(hovering ? Palette.cobalt.opacity(0.30) : Color.primary.opacity(0.08),
                              lineWidth: 1)
        )
        .onHover { hovering = $0 }
    }

    /// An allow rule's passthrough readout. Brass, not cobalt: this rule runs
    /// unapproved, so it is stated as the quiet heads-up it is.
    private var allowLine: some View {
        HStack(spacing: 6) {
            Image(systemName: "arrow.right.circle").font(.system(size: 11)).foregroundStyle(Palette.brass)
            Text("runs without asking").font(.system(size: 11)).foregroundStyle(.primary)
            Text("no approval, no injection").font(.system(size: 10)).foregroundStyle(.tertiary)
            Spacer(minLength: 0)
        }
    }

    /// A gate rule's lease cap, shown only when the rule is leasable.
    private func leaseLine(_ cap: Int) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "clock.arrow.circlepath").font(.system(size: 10)).foregroundStyle(.tertiary)
            Text("leasable up to \(LeaseDuration.short(cap))")
                .font(.system(size: 10)).foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
    }

    /// The reorder handle. It does not itself drive the drag (the whole List row
    /// lifts via `.onMove`); it is the visible affordance, so it takes the grab
    /// cursor and brightens with the card to read as "grab me".
    private var grip: some View {
        Image(systemName: "line.3.horizontal")
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(hovering ? Palette.cobalt : Color.secondary)
            .frame(width: 20, height: 24)
            .background(hovering ? Palette.cobalt.opacity(0.10) : Color.clear,
                        in: .rect(cornerRadius: 6))
            .pointerStyle(.grabIdle)
            .accessibilityHidden(true)
    }
}

/// The KEY names as mono chips that wrap as whole units and never break a key
/// mid-identifier. A key too wide for the row truncates with an ellipsis and
/// keeps its full name in a hover tooltip.
private struct FlowKeys: View {
    let keys: [String]
    var body: some View {
        FlowLayout(spacing: 6, lineSpacing: 6) {
            ForEach(keys, id: \.self) { key in
                Text(key)
                    .font(.mono(11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(Palette.cobalt.opacity(0.10), in: .capsule)
                    .help(key)
            }
        }
    }
}

/// A minimal wrapping layout: places subviews left to right and drops to the next
/// line when the current one is full, so chips wrap as whole units. A subview
/// wider than the row is clamped to the row width (its own truncation then
/// applies) rather than overflowing.
private struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    var lineSpacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, lineHeight: CGFloat = 0, widest: CGFloat = 0
        for sub in subviews {
            var size = sub.sizeThatFits(.unspecified)
            size.width = min(size.width, maxWidth)
            if x > 0, x + size.width > maxWidth {
                y += lineHeight + lineSpacing
                x = 0
                lineHeight = 0
            }
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
            widest = max(widest, min(x - spacing, maxWidth))
        }
        let width = maxWidth.isFinite ? maxWidth : widest
        return CGSize(width: width, height: y + lineHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let maxWidth = bounds.width
        var x: CGFloat = 0, y: CGFloat = 0, lineHeight: CGFloat = 0
        for sub in subviews {
            var size = sub.sizeThatFits(.unspecified)
            size.width = min(size.width, maxWidth)
            if x > 0, x + size.width > maxWidth {
                y += lineHeight + lineSpacing
                x = 0
                lineHeight = 0
            }
            sub.place(at: CGPoint(x: bounds.minX + x, y: bounds.minY + y),
                      anchor: .topLeading,
                      proposal: ProposedViewSize(width: size.width, height: size.height))
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
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

/// A layered config for previews: the specific `op --account=prod` (leasable)
/// above the general `op`, so it wins first; a two-key `aws` rule; and an `allow`
/// passthrough. Exercises ordering, a long single key (OP_SERVICE_ACCOUNT_TOKEN),
/// multi-key chip wrapping, a lease cap, and the allow-vs-gate readout in one list.
private func previewLayeredConfig() -> SigilConfig {
    SigilConfig(
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
                       action: ActionConfig(mode: .gate, source: "op-prod",
                                            lease: .leasable(maxSecs: 900))),
            RuleConfig(name: "op",
                       match: MatchConfig(command: "op"),
                       action: ActionConfig(mode: .gate, source: "op")),
            RuleConfig(name: "aws",
                       match: MatchConfig(command: "aws"),
                       action: ActionConfig(mode: .gate, source: "aws")),
            RuleConfig(name: "git-status",
                       match: MatchConfig(command: "git", subcommand: "status"),
                       action: ActionConfig(mode: .allow)),
        ])
}

#Preview("Rules") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle)))
        .frame(width: 720, height: 640)
}

// The precedence the drag-to-reorder exists to author, at a comfortable width.
#Preview("Rules - ordering") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, config: previewLayeredConfig())))
        .frame(width: 720, height: 640)
}

// The same list at a narrow width: the long key and the two-key aws rule must
// wrap as whole chips and truncate cleanly, never breaking mid-identifier and
// never overflowing into a horizontal scroll.
#Preview("Rules - narrow") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, config: previewLayeredConfig())))
        .frame(width: 360, height: 620)
}

#Preview("Rules - empty") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle, config: SigilConfig())))
        .frame(width: 720, height: 640)
}
