//  RuleEditorSheet.swift
//  Author or edit one rule: the command to watch (match) and the write-once
//  environment to inject into it. Opened blank from the toolbar, pre-filled from
//  a quick start, or seeded from an existing rule for an in-place edit. It never
//  authors config in Swift; Save hands the draft to the model, which drives the
//  `sigil-config` verbs and seals the values under the DEK.
//
//  The environment is the whole point: each row is a KEY (always shown) and a
//  VALUE (write-only). A value you type is sealed on save and never shown again;
//  re-opening the rule shows the KEY with a masked, "unchanged" value you can
//  replace or remove but never read back. Sealing a value asks for Touch ID.

import SwiftUI

struct RuleEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let editingName: String?

    @State private var draft: RuleDraft
    @State private var saving = false

    init(draft: RuleDraft, editingName: String?) {
        self.editingName = editingName
        _draft = State(initialValue: draft)
    }

    private var isEdit: Bool { editingName != nil }

    /// The reason Save is blocked, or nil when the draft is authorable. Ordered so
    /// the most fundamental gap surfaces first.
    private var blocker: String? {
        if draft.name.trimmed.isEmpty { return "Give the rule a name." }
        if draft.match.isEmpty { return "Add at least one match condition." }
        return envError
    }

    /// What is wrong with the environment rows, or nil. Keys must be valid and
    /// unique, and any typed value needs a KEY to hold it.
    private var envError: String? {
        var seen = Set<String>()
        for row in draft.env {
            let key = row.key.trimmed
            if key.isEmpty {
                if !row.value.isEmpty { return "Give every value a KEY name." }
                continue
            }
            if !EnvKey.isValid(key) { return "\(key) is not a valid variable name." }
            if !seen.insert(key).inserted { return "Each KEY must be set once (\(key) repeats)." }
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
                    nameSection
                    matchSection
                    environmentSection
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
            Text(isEdit ? "Edit rule" : "New rule")
                .font(.system(size: 15, weight: .semibold))
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var footer: some View {
        HStack {
            Text(blocker ?? " ")
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

    // MARK: environment

    private var environmentSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Environment",
                         "The KEY=VALUE secrets to inject after your phone approves. Each value is sealed on your device the moment you save and is never shown again.")
            EnvEditor(rows: $draft.env)
        }
    }

    // MARK: save

    private func save() async {
        saving = true
        defer { saving = false }
        // Dismiss only when the save actually took. On a refusal the model leaves
        // lastError set and returns false, so the sheet stays open with the reason.
        if await model.saveRule(draft, replacing: editingName) {
            dismiss()
        }
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

// MARK: - Environment editor

/// A rows-of-KEY-plus-VALUE editor. KEY is always visible; VALUE is a SecureField
/// that writes only. An existing KEY (loaded from a saved rule) has a read-only
/// name and a masked "unchanged" value: typing replaces it, the minus removes it.
/// A fresh row is a KEY you name and a VALUE you set now.
private struct EnvEditor: View {
    @Binding var rows: [EnvRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if rows.isEmpty {
                Text("No environment. This rule will gate the command without injecting anything.")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach($rows) { $row in
                    EnvRowView(row: $row) { remove(row) }
                }
            }
            Button {
                rows.append(EnvRow())
            } label: {
                Label("Add variable", systemImage: "plus").font(.system(size: 11))
            }
            .buttonStyle(.plain).foregroundStyle(Palette.cobalt)
        }
    }

    private func remove(_ row: EnvRow) {
        rows.removeAll { $0.id == row.id }
    }
}

private struct EnvRowView: View {
    @Binding var row: EnvRow
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            TextField("KEY", text: $row.key)
                .textFieldStyle(.roundedBorder).font(.mono(11))
                .frame(maxWidth: 200)
                .disabled(row.existing)   // a sealed KEY cannot be renamed in place
            Text("=").foregroundStyle(.tertiary)
            SecureField(row.existing ? "unchanged" : "value", text: $row.value)
                .textFieldStyle(.roundedBorder).font(.mono(11))
            Button(action: onRemove) {
                Image(systemName: "minus.circle").font(.system(size: 12))
            }
            .buttonStyle(.plain).foregroundStyle(.secondary)
            .accessibilityLabel(row.key.isEmpty ? "Remove variable" : "Remove \(row.key)")
        }
    }
}

/// Environment-variable-name validation, mirroring core's `valid_env_key`
/// (crates/sigil/src/cli.rs): non-empty and free of `=`, whitespace, and control
/// characters, so it can never corrupt the child's environment or the sealed wire.
enum EnvKey {
    static func isValid(_ key: String) -> Bool {
        guard !key.isEmpty else { return false }
        return !key.unicodeScalars.contains { s in
            s == "=" || s.value == 0 || s.properties.isWhitespace
                || (s.value < 0x20) || s.value == 0x7f
        }
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

#Preview("New rule from quick start") {
    RuleEditorSheet(draft: QuickStart.catalog[0].draft(), editingName: nil)
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}

#Preview("Blank rule") {
    RuleEditorSheet(draft: RuleDraft(), editingName: nil)
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}

#Preview("Editing (masked values)") {
    RuleEditorSheet(
        draft: RuleDraft(editing: Fixtures.config.rules[0], in: Fixtures.config),
        editingName: "op")
        .environment(AppModel(daemon: MockDaemonClient(scenario: .armedIdle), approver: MockApprover()))
}
