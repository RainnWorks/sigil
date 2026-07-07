//  RulesView.swift
//  The if-this-then-that surface, the spine of the configurator. A rule watches
//  for a command you run (match on command, subcommand, argv, flags), gates it on
//  your phone, and injects the environment from a source you name. The screen
//  leads with one-click recipes so the first rule is never a blank form, then
//  lists the rules you have, each editable in full.
//
//  Provider-blind by construction: a rule names a source, never a vendor. The
//  1Password recipe is one tile among peers. Everything here drives the
//  `sigil-config` seam (rule/source verbs, or a whole-config import for an edit);
//  no gating logic lives in Swift.

import SwiftUI

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var editor: EditorContext?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let error = model.lastError { ErrorStrip(message: error) }
                recipes
                rules
            }
            .padding(20)
        }
        .navigationTitle("Rules")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { editor = EditorContext(draft: RuleDraft(), editingName: nil) } label: {
                    Label("Add", systemImage: "plus")
                }
            }
        }
        .sheet(item: $editor) { ctx in
            RuleEditorSheet(draft: ctx.draft, editingName: ctx.editingName,
                            ingredients: model.accounts)
        }
        .task { await model.loadSecondaryScreens() }
    }

    // MARK: recipes

    private var recipes: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Start from a recipe").font(.system(size: 13, weight: .semibold))
                Text("Lay down a working rule for a common tool, then confirm the source and risk. You can always author one from scratch.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 10)], spacing: 10) {
                ForEach(Recipe.catalog) { recipe in
                    RecipeCard(recipe: recipe) {
                        editor = EditorContext(draft: recipe.draft(),
                                               editingName: nil)
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
                emptyState
            } else {
                ForEach(model.config.rules) { rule in
                    RuleCard(rule: rule,
                             source: model.config.source(named: rule.action.source),
                             onEdit: {
                                 editor = EditorContext(
                                     draft: RuleDraft(editing: rule, in: model.config,
                                                      ingredients: model.accounts),
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
            Text("A rule watches for a command you run and holds it for approval on your phone before any secret is read. It has three parts:")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                modelRow(number: "1", title: "Match", detail: "the command to watch, e.g. op read")
                modelRow(number: "2", title: "Source", detail: "where its secret comes from")
                modelRow(number: "3", title: "Risk", detail: "how much friction the approval takes")
            }
            .padding(.vertical, 2)
            Text("Pick a recipe above to lay one down, or add a custom rule.")
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
/// per invocation so a recipe tap always re-presents with fresh defaults.
private struct EditorContext: Identifiable {
    let id = UUID()
    let draft: RuleDraft
    let editingName: String?
}

// MARK: - Recipe card

private struct RecipeCard: View {
    let recipe: Recipe
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: recipe.symbol)
                    .font(.system(size: 15))
                    .foregroundStyle(Palette.cobalt)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 3) {
                    Text(recipe.title).font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text(recipe.subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
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

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text(rule.name).font(.system(size: 13, weight: .semibold))
                RiskPill(risk: rule.action.riskLevel)
                Spacer()
                if let timeout = rule.action.timeoutSec {
                    MonoText("\(timeout)s", size: 10, color: .secondary)
                }
            }

            // What it watches for.
            HStack(spacing: 6) {
                Text("when").font(.system(size: 10)).foregroundStyle(.tertiary)
                MonoText(rule.match.summary, size: 11, color: .secondary)
            }

            // Where it injects from.
            HStack(spacing: 6) {
                Text("into").font(.system(size: 10)).foregroundStyle(.tertiary)
                if let source {
                    StatePill(tone: .neutral, text: source.knownProvider?.displayName ?? source.provider)
                    MonoText(source.origin, size: 11, color: .secondary)
                } else {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(Palette.brass).font(.system(size: 10))
                        Text("source \(rule.action.source) is missing; this rule fails closed")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
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

/// The risk policy as a tinted pill. Routine is calm; elevated and critical carry
/// the brief's brass and rust so the friction reads at a glance.
struct RiskPill: View {
    let risk: RiskLevel
    private var tone: StateTone {
        switch risk {
        case .routine: return .neutral
        case .elevated: return .warn
        case .critical: return .denied
        }
    }
    var body: some View {
        StatePill(tone: tone, text: risk.displayName)
    }
}

// RiskLevel gains the small surface the pickers and pills need. Kept here (not in
// the wire-facing Domain type) since it is display-only.
extension RiskLevel: CaseIterable, Identifiable {
    static var allCases: [RiskLevel] { [.routine, .elevated, .critical] }
    var id: String { rawValue }
    var displayName: String { rawValue.capitalized }
}

#Preview("Rules") {
    NavigationStack { RulesView() }
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
        .frame(width: 720, height: 640)
}
