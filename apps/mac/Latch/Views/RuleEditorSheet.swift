//  RuleEditorSheet.swift
//  Author or edit one rule: the command to watch (match) and the write-once
//  environment to inject into it. Opened blank from the toolbar, pre-filled from
//  a quick start, or seeded from an existing rule for an in-place edit. It never
//  authors config in Swift; Save hands the draft to the model, which drives the
//  `sigil-config` verbs and seals the values under the DEK.
//
//  The environment is the whole point: each row is a KEY (always shown) and a
//  VALUE (write-only). A value you type is sealed on save and never shown again;
//  re-opening the rule shows the KEY with a masked, "sealed" value you can
//  replace or remove but never read back. Sealing encrypts the value under the
//  local device key (the host DEK). On a Secure Enclave keystore that unwrap is
//  gated by Touch ID; the app currently runs the dev file keystore (SE wrap is
//  task #24/#49), which seals without a prompt, so the copy never promises one.

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

    /// The reason Save is blocked, or nil when the draft is authorable. A rule is
    /// its match, so the only gates are a non-empty match and a sound environment.
    /// A rule is NEVER blocked for duplicating another; the model mints a unique
    /// id, so stacking rules (even an identical one) always succeeds.
    private var blocker: String? {
        if draft.match.isEmpty { return "Add at least one match condition." }
        return envError
    }

    /// A soft, non-blocking heads-up when this exact match already exists. The user
    /// may still add it (they order the list; the higher one wins); this only says
    /// so out loud. Never disables Save.
    private var duplicateMatchHint: String? {
        guard !draft.match.isEmpty else { return nil }
        guard model.config.rules.contains(where: { $0.match == draft.match && $0.name != editingName })
        else { return nil }
        return "Another rule already matches this exactly. Whichever sits higher in your rules list wins first."
    }

    /// What is wrong with the environment rows, or nil. Keys must be valid and
    /// unique; any typed value needs a KEY to hold it; and a fresh KEY must be
    /// given a value, so a blank one can never silently seal an empty-string
    /// secret that then masquerades as "sealed" forever. An existing row left
    /// blank is the deliberate keep-unchanged case, so it is not a gap.
    private var envError: String? {
        var seen = Set<String>()
        for row in draft.env {
            let key = row.key.trimmed
            if key.isEmpty {
                if !row.value.isEmpty { return "Give every value a KEY name." }
                continue
            }
            if !EnvKey.isValid(key) { return "\(key) is not a valid variable name." }
            if !row.existing && row.value.isEmpty {
                return "Give \(key) a value, or remove the row."
            }
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
        VStack(spacing: 8) {
            // The reinforcing cue at the commit point: a sealed value cannot be
            // recovered from here or anywhere else, so keep a copy if you need one.
            HStack(spacing: 6) {
                Image(systemName: "lock.fill").font(.system(size: 9)).foregroundStyle(.tertiary)
                Text("Values are sealed on save and cannot be read back afterward. Keep your own copy if you need one.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            HStack {
                Text(blocker ?? " ")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
                Button(isEdit ? "Save" : "Add rule") { Task { await save() } }
                    .buttonStyle(.glassProminent).tint(Palette.cobalt)
                    .disabled(!canSave)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: match

    private var matchSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Match", "The command to gate, and the conditions that must hold. Every condition you set must match; leave a field blank to ignore it. This is also how the rule is labelled.")

            twoUp(
                labelled("Command") {
                    TextField("op", text: $draft.command).textFieldStyle(.roundedBorder).font(.mono(11))
                },
                labelled("Subcommand") {
                    TextField("read", text: $draft.subcommand).textFieldStyle(.roundedBorder).font(.mono(11))
                }
            )

            TokenListEditor(title: "Argument contains", placeholder: "a substring of some argument",
                            tokens: $draft.argvContains)
            TokenListEditor(title: "Flags present", placeholder: "--vault",
                            tokens: $draft.flagPresent)
            FlagEqEditor(pairs: $draft.flagEquals)

            if let hint = duplicateMatchHint {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "info.circle").font(.system(size: 10)).foregroundStyle(Palette.brass)
                    Text(hint).font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
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
    /// The sealed row awaiting a remove confirmation. Removing a sealed value
    /// unseals it permanently, so it must not look like discarding a blank new
    /// row; a fresh row is removed outright (nothing is lost).
    @State private var confirmingRemoval: EnvRow?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if rows.isEmpty {
                Text("No environment. This rule will gate the command without injecting anything.")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach($rows) { $row in
                    EnvRowView(row: $row) {
                        if row.existing { confirmingRemoval = row } else { remove(row) }
                    }
                }
            }
            Button {
                rows.append(EnvRow())
            } label: {
                Label("Add variable", systemImage: "plus").font(.system(size: 11))
            }
            .buttonStyle(.plain).foregroundStyle(Palette.cobalt)
        }
        .confirmationDialog(
            confirmingRemoval.map { "Remove \($0.key)?" } ?? "Remove sealed value?",
            isPresented: Binding(get: { confirmingRemoval != nil },
                                 set: { if !$0 { confirmingRemoval = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let row = confirmingRemoval { remove(row) }
                confirmingRemoval = nil
            }
            Button("Cancel", role: .cancel) { confirmingRemoval = nil }
        } message: {
            Text("Its sealed value cannot be recovered. The key is dropped on save.")
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
            // A sealed row carries a lock so keep-vs-replace is obvious at a glance;
            // a fresh row has none.
            Image(systemName: "lock.fill")
                .font(.system(size: 10))
                .foregroundStyle(row.existing ? Palette.brass : .clear)
                .accessibilityHidden(!row.existing)
            TextField("KEY", text: $row.key)
                .textFieldStyle(.roundedBorder).font(.mono(11))
                .frame(maxWidth: 190)
                .disabled(row.existing)   // a sealed KEY cannot be renamed in place
            Text("=").foregroundStyle(.tertiary)
            SecureField(row.existing ? "sealed, leave blank to keep" : "value", text: $row.value)
                .textFieldStyle(.roundedBorder).font(.mono(11))
            // Distinct destructive affordance on a sealed row (trash, rust) so
            // unsealing never looks like discarding a blank new row (minus).
            Button(action: onRemove) {
                Image(systemName: row.existing ? "trash" : "minus.circle").font(.system(size: 12))
            }
            .buttonStyle(.plain)
            .foregroundStyle(row.existing ? Palette.rust : .secondary)
            .accessibilityLabel(
                row.existing ? "Remove sealed value \(row.key)"
                             : (row.key.isEmpty ? "Remove variable" : "Remove \(row.key)"))
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

// The op quick start lays down OP_SERVICE_ACCOUNT_TOKEN with an empty value, so
// this preview also pins the P0 guard: Add rule is disabled and the footer reads
// "Give OP_SERVICE_ACCOUNT_TOKEN a value, or remove the row." until the token is
// typed, so a blank value can never silently seal an empty secret.
#Preview("Quick start (empty value blocks save)") {
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
