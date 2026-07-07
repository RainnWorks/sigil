//  RuleEditorSheet.swift
//  Author or edit one rule: what command to watch (match), which source to inject
//  from, and how much friction the approval takes (risk + timeout). Opened blank
//  from the toolbar, pre-filled from a recipe, or seeded from an existing rule for
//  an in-place edit. It never authors config in Swift; Save hands the draft to the
//  model, which drives the `sigil-config` verbs.
//
//  A rule references a Source. Rather than make the source its own first step, the
//  picker lists the sources you already have (from the Sources screen) and, if you
//  need a new one, lets you add it inline. A 1Password credential is wired to its
//  routing source automatically on save, so you pick an ingredient, not plumbing.

import SwiftUI

struct RuleEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let editingName: String?
    /// The provider the source picker is pinned to (a recipe's choice), or nil to
    /// let the picker span every provider (the custom path).
    private let pinnedProvider: SourceProvider?

    @State private var draft: RuleDraft
    /// The chosen ingredient, by `Account.id`. An env-file ingredient is a config
    /// source already; a 1Password ingredient is a credential the model wires to a
    /// routing source on save.
    @State private var ingredientID: String?
    @State private var addingSource = false
    @State private var saving = false
    @State private var usesTimeout: Bool

    init(draft: RuleDraft, editingName: String?, ingredients: [Account]) {
        self.editingName = editingName
        self.pinnedProvider = draft.custom ? nil : draft.provider
        _draft = State(initialValue: draft)
        _usesTimeout = State(initialValue: draft.timeoutSec != nil)
        _ingredientID = State(initialValue: Self.initialIngredient(draft, ingredients))
    }

    private var isEdit: Bool { editingName != nil }

    /// Ingredients the picker offers: filtered to the pinned provider, or all when
    /// the provider is free (custom).
    private var candidates: [Account] {
        guard let pinnedProvider else { return model.accounts }
        return model.accounts.filter { $0.provider == pinnedProvider }
    }

    private var selectedIngredient: Account? {
        model.accounts.first { $0.id == ingredientID }
    }

    private var canSave: Bool {
        !draft.name.trimmed.isEmpty && !draft.match.isEmpty && selectedIngredient != nil && !saving
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let error = model.lastError { ErrorStrip(message: error) }
                    nameSection
                    matchSection
                    sourceSection
                    riskSection
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 540, height: 640)
        .sheet(isPresented: $addingSource) {
            // A recipe pins the provider; the neutral custom path defaults to an
            // env file rather than 1Password, so op is not the premise.
            AddAccountSheet(initialProvider: pinnedProvider ?? .envFile)
        }
    }

    private var header: some View {
        HStack {
            Text(isEdit ? "Edit rule" : "New rule")
                .font(.system(size: 15, weight: .semibold))
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var footer: some View {
        HStack {
            Text(draft.match.isEmpty ? "Add at least one match condition." : " ")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
            Spacer()
            Button("Cancel") { dismiss() }.buttonStyle(.glass)
            Button(isEdit ? "Save" : "Add rule") { Task { await save() } }
                .buttonStyle(.glassProminent).tint(Palette.cobalt)
                .disabled(!canSave)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: name

    private var nameSection: some View {
        fieldGroup(title: "Name", hint: "A label for this rule, unique across your rules.") {
            TextField("op-read", text: $draft.name).textFieldStyle(.roundedBorder)
        }
    }

    // MARK: match

    private var matchSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Match", "Every condition you set must hold. Leave a field blank to ignore it.")

            twoUp(
                labelled("Command") {
                    TextField("op", text: $draft.command).textFieldStyle(.roundedBorder).font(.mono(11))
                },
                labelled("Subcommand") {
                    TextField("read", text: $draft.subcommand).textFieldStyle(.roundedBorder).font(.mono(11))
                }
            )

            TokenListEditor(title: "Argv contains", placeholder: "a substring of some argument",
                            tokens: $draft.argvContains)
            TokenListEditor(title: "Flags present", placeholder: "--vault",
                            tokens: $draft.flagPresent)
            FlagEqEditor(pairs: $draft.flagEquals)
        }
    }

    // MARK: source

    private var sourceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Source", "Where this rule injects its secret from after your phone approves.")
            if candidates.isEmpty {
                noSourceCallout
            } else {
                Picker("Source", selection: $ingredientID) {
                    ForEach(candidates) { account in
                        Text(sourceLabel(account)).tag(Optional(account.id))
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                Button {
                    addingSource = true
                } label: {
                    Label("Add a source", systemImage: "plus").font(.system(size: 11))
                }
                .buttonStyle(.plain).foregroundStyle(Palette.cobalt)
            }
        }
        .onChange(of: model.accounts) { _, accounts in
            // A source just added inline: select it so the rule can save.
            if ingredientID == nil || !accounts.contains(where: { $0.id == ingredientID }) {
                ingredientID = Self.firstMatch(pinnedProvider, accounts)
            }
        }
    }

    private var noSourceCallout: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(pinnedProvider.map { "No \($0.displayName) source yet." } ?? "No sources yet.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            Button("Add a source") { addingSource = true }
                .buttonStyle(.glass).controlSize(.small)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.brass.opacity(0.08), in: .rect(cornerRadius: 10))
    }

    // MARK: risk + timeout

    private var riskSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Risk", "Scales the approve control on your phone. Deny is always one tap.")
            Picker("Risk", selection: $draft.risk) {
                ForEach(RiskLevel.allCases) { risk in Text(risk.displayName).tag(risk) }
            }
            .pickerStyle(.segmented).labelsHidden()
            Text(riskGloss).font(.system(size: 10)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle(isOn: $usesTimeout.animation()) {
                Text("Custom approval timeout").font(.system(size: 12))
            }
            .toggleStyle(.switch).controlSize(.small)
            if usesTimeout {
                Stepper(value: Binding(
                    get: { draft.timeoutSec ?? model.settings.approvalTimeoutSec },
                    set: { draft.timeoutSec = $0 }
                ), in: 15...600, step: 15) {
                    LabeledContent("Timeout") {
                        MonoText("\(draft.timeoutSec ?? model.settings.approvalTimeoutSec)s", size: 11, color: .secondary)
                    }
                }
            }
            Text("If no decision arrives before the timeout, the request fails closed and is denied.")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .onChange(of: usesTimeout) { _, on in
            if !on { draft.timeoutSec = nil }
            else if draft.timeoutSec == nil { draft.timeoutSec = model.settings.approvalTimeoutSec }
        }
    }

    // MARK: save

    private func save() async {
        guard let ingredient = selectedIngredient else { return }
        saving = true
        defer { saving = false }
        // Dismiss only when the save actually took. On a refusal the model leaves
        // lastError set and returns false, so the sheet stays open with the reason
        // showing rather than pretending it worked.
        if await model.saveRule(draft, source: ingredient, replacing: editingName) {
            dismiss()
        }
    }

    // MARK: helpers

    /// A one-line gloss of what the selected risk changes on the phone. Deny is
    /// always one tap; risk only scales the approve side.
    private var riskGloss: String {
        switch draft.risk {
        case .routine: return "Routine: approve with a single tap on your phone."
        case .elevated: return "Elevated: approve takes a deliberate confirm, so it is not a reflex tap."
        case .critical: return "Critical: approve takes the firmest confirmation the phone offers."
        }
    }

    private func sourceLabel(_ account: Account) -> String {
        let where_ = account.provider == .envFile ? (account.path ?? account.label) : account.label
        return "\(account.provider.displayName) · \(where_)"
    }

    private static func initialIngredient(_ draft: RuleDraft, _ ingredients: [Account]) -> String? {
        // Editing: land on the ingredient the rule's source resolves to.
        if !draft.sourceKey.isEmpty {
            switch draft.provider {
            case .onePassword:
                if let hit = ingredients.first(where: { $0.provider == .onePassword && $0.label == draft.sourceKey }) {
                    return hit.id
                }
            case .envFile:
                if let hit = ingredients.first(where: { $0.id == draft.sourceKey }) { return hit.id }
            }
        }
        return firstMatch(draft.custom ? nil : draft.provider, ingredients)
    }

    private static func firstMatch(_ provider: SourceProvider?, _ ingredients: [Account]) -> String? {
        if let provider { return ingredients.first { $0.provider == provider }?.id }
        return ingredients.first?.id
    }

    // MARK: small view builders

    private func sectionTitle(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 12, weight: .semibold))
            Text(subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func fieldGroup<Content: View>(title: String, hint: String?,
                                           @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            content()
            if let hint {
                Text(hint).font(.system(size: 10)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
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

// MARK: - Token list editor

/// A compact repeated-string editor: type a value, Return or Add appends it, and
/// each added token shows with a remove control. Used for argv-contains and the
/// flags-present list.
private struct TokenListEditor: View {
    let title: String
    let placeholder: String
    @Binding var tokens: [String]
    @State private var draft = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                TextField(placeholder, text: $draft)
                    .textFieldStyle(.roundedBorder).font(.mono(11))
                    .onSubmit(add)
                Button("Add", action: add).buttonStyle(.glass).controlSize(.small)
                    .disabled(draft.trimmed.isEmpty)
            }
            ForEach(Array(tokens.enumerated()), id: \.offset) { index, token in
                HStack(spacing: 6) {
                    MonoText(token, size: 11, color: .secondary)
                    Spacer()
                    Button { tokens.remove(at: index) } label: {
                        Image(systemName: "minus.circle").font(.system(size: 12))
                    }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel("Remove \(token)")
                }
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(.quaternary, in: .rect(cornerRadius: 6))
            }
        }
    }

    private func add() {
        let value = draft.trimmed
        guard !value.isEmpty else { return }
        tokens.append(value)
        draft = ""
    }
}

// MARK: - Flag-equals editor

/// A repeated `{flag, value}` editor, e.g. --project = prod.
private struct FlagEqEditor: View {
    @Binding var pairs: [FlagEqConfig]
    @State private var flag = ""
    @State private var value = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Flag equals").font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                TextField("--project", text: $flag)
                    .textFieldStyle(.roundedBorder).font(.mono(11)).frame(maxWidth: 160)
                Text("=").foregroundStyle(.tertiary)
                TextField("prod", text: $value)
                    .textFieldStyle(.roundedBorder).font(.mono(11))
                Button("Add", action: add).buttonStyle(.glass).controlSize(.small)
                    .disabled(flag.trimmed.isEmpty || value.trimmed.isEmpty)
            }
            ForEach(Array(pairs.enumerated()), id: \.offset) { index, pair in
                HStack(spacing: 6) {
                    MonoText("\(pair.flag)=\(pair.value)", size: 11, color: .secondary)
                    Spacer()
                    Button { pairs.remove(at: index) } label: {
                        Image(systemName: "minus.circle").font(.system(size: 12))
                    }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel("Remove \(pair.flag)=\(pair.value)")
                }
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(.quaternary, in: .rect(cornerRadius: 6))
            }
        }
    }

    private func add() {
        let f = flag.trimmed, v = value.trimmed
        guard !f.isEmpty, !v.isEmpty else { return }
        pairs.append(FlagEqConfig(flag: f, value: v))
        flag = ""; value = ""
    }
}

#Preview("New rule") {
    RuleEditorSheet(draft: Recipe.catalog[0].draft(), editingName: nil,
                    ingredients: Fixtures.accounts)
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}

#Preview("Custom rule") {
    RuleEditorSheet(draft: RuleDraft(), editingName: nil, ingredients: Fixtures.accounts)
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}
