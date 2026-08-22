//! Citation checker for `docs/security-claims.md`.
//!
//! That document is the project's security record: every claim row names the
//! code that enforces it and the test that proves it. A row whose proving test
//! no longer exists still *reads* as proven, and it is what a future reviewer
//! cites instead of reading the code. A prose comment asserting a property
//! cannot be checked mechanically, but a claim naming a test can be, so this
//! crate checks it.
//!
//! What it does: parse the "Proving test" column of every table in the
//! document, pull out every backticked citation, and confirm that each one
//! still resolves against the working tree. A citation is either a test name
//! (`file.rs::some_test_name`, or a bare `some_test_name` continuing a list) or
//! a file (`apps/phone/src/lib/format.selftest.ts`). Both forms decay the same
//! way and both are checked.
//!
//! Deliberate limits, so that a failure always means something real:
//!
//! - Only the "Proving test" column is read. The "Enforcing code" column cites
//!   symbols (types, methods, ObjC functions), which are not enumerable with
//!   the same cheap confidence, and a noisy gate gets ignored.
//! - A cited name that exists as a plain function but not as a `#[test]` is
//!   reported as a warning, never a failure. The proving-test column contains
//!   prose that legitimately names non-test symbols, and blocking on those
//!   would make the gate wrong more often than the document is.
//! - Only Rust test names are resolved as tests. The phone's checks are plain
//!   `bun run` scripts whose cases are string arguments, not identifiers, so
//!   the document cites them by file, and by file is how they are checked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Citations that are already dead in the tree, recorded here so the gate can
/// report them without blocking the build.
///
/// THIS LIST MUST ONLY EVER SHRINK. It is not a place to park a new dead
/// citation: adding an entry means editing this file, which puts it in front of
/// a reviewer, and the gate fails if an entry here is no longer dead, so a row
/// that gets fixed forces its entry out. Every name below belongs to a claim
/// row in docs/security-claims.md whose proving test was renamed or deleted
/// underneath it. The rows are owned by the security-reviewer; fixing them is
/// re-citing the row against a test that exists (or marking the claim
/// UNPROVEN), not deleting the entry here.
///
/// Recorded 2026-08-08 against the state of `feat/config-rule-engine`.
pub const KNOWN_STALE: &[&str] = &[
    // Section 14 (P-256 SE wrap): se_ecies.rs was absorbed into
    // sigil-proto/src/threshold.rs, taking every test name its rows cite.
    "a_non_point_recipient_key_is_refused",
    "a_tampered_ciphertext_is_rejected",
    "a_tampered_ephemeral_key_is_rejected",
    "a_truncated_blob_is_rejected",
    "each_wrap_uses_a_fresh_ephemeral_key",
    "sealed_blob_has_the_apple_wire_length",
    "unwrap_dek_p256",
    "wrap_unwrap_round_trips_the_dek",
    "wrong_se_key_cannot_unwrap",
    "x963_kdf_matches_a_known_answer",
    // Section 2 (DEK handoff) and section 3 (daemon inert at rest): the
    // pairing/secrets test names moved during the lease and keystore work.
    "a_replayed_dek_envelope_is_rejected",
    "approve_carries_the_dek_and_deny_never_does",
    "dek_debug_does_not_leak",
    "dek_from_a_forged_sender_is_rejected",
    "dek_is_never_delivered_before_sas_confirmation",
    "dek_is_random_each_call",
    "dek_not_delivered_before_confirmation",
    "dek_to_the_wrong_recipient_cannot_be_opened",
    "malformed_dek_base64_fails_closed_to_none",
    "nonce_is_unique_so_ciphertext_differs",
    "store_persists_ciphertext_only",
    "tampered_ciphertext_is_rejected",
    "truncated_ciphertext_is_rejected",
    "wrong_dek_fails_to_decrypt",
    // Config / provider / shim rows.
    "add_get_remove_round_trip_and_reject_duplicates",
    "an_unconfigured_command_does_not_resolve",
    "config_entry_resolves_to_a_served_identity",
    "fetch_and_sign_fails_closed_when_the_token_is_wrong",
    "op_provider_needs_an_account_and_env_file_does_not",
    "run_streams_op_child_output_to_the_caller_fd",
    // Sealed env-file rows.
    "env_blob_is_ciphertext_at_rest_and_round_trips",
    "inline_env_blob_keys_must_match_the_approved_set_or_fail_closed",
    "inline_env_command_runs_gated_and_injects_sealed_values",
    "inline_env_with_no_sealed_values_fails_closed",
    // Keystore, ssh signer, code identity, threshold rows.
    "each_account_gets_a_unique_ephemeral_and_routes",
    "fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature",
    "remote_v2_threshold_approval_decrypts_via_two_party_combine",
    "se_paths_refuse_until_verified",
    "sigil_cdhash_for_path",
    "v1_and_v2_accounts_coexist_and_each_takes_its_own_path",
    // Files cited by rows that outlived them: the SE self-test tool was never
    // committed, and the relay's TypeScript worker suite went away when the
    // relay was rewritten in Rust.
    "apps/mac/Tools/se-selftest.swift",
    "protocol.test.ts",
];

/// Directory names never worth walking: build output, vendored trees, and the
/// read-only prior-art checkout.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".expo",
    "Pods",
    "build",
    "dist",
    "node_modules",
    "reference",
    "target",
];

const SOURCE_EXTENSIONS: &[&str] = &["rs", "ts", "tsx", "swift", "m", "h", "js", "py", "html"];

/// What a citation turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `some_test_name`, with or without a `file.rs::` prefix.
    TestName,
    /// A path or bare filename with a source extension.
    File,
}

/// One backticked citation, as written, with where it was written.
#[derive(Debug, Clone)]
pub struct Citation {
    pub line: usize,
    pub claim: String,
    /// The whole backtick span it came from, before brace expansion.
    pub raw: String,
    /// The resolved name: a test fn name, or a path.
    pub name: String,
    /// The `file.rs` part of a `file.rs::name` citation, if there was one.
    pub module: Option<String>,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Resolves: the test or the file is in the tree.
    Live,
    /// Nothing in the tree answers to this name.
    Dead,
    /// The name exists as a function but carries no `#[test]`. Reported, never
    /// fatal: the column contains prose that names non-test symbols.
    NotATest,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub citation: Citation,
    pub verdict: Verdict,
    /// Why it probably broke, and what to look at.
    pub cause: String,
}

/// An index of what the working tree actually contains.
pub struct Tree {
    /// test fn name -> the files that define it.
    pub test_fns: BTreeMap<String, Vec<String>>,
    /// every fn name -> the files that define it.
    pub all_fns: BTreeMap<String, Vec<String>>,
    /// Every source file, as a path relative to the repo root.
    pub files: BTreeSet<String>,
    /// Every source file basename.
    pub basenames: BTreeSet<String>,
}

impl Tree {
    pub fn index(root: &Path) -> std::io::Result<Self> {
        let mut tree = Tree {
            test_fns: BTreeMap::new(),
            all_fns: BTreeMap::new(),
            files: BTreeSet::new(),
            basenames: BTreeSet::new(),
        };
        tree.walk(root, root)?;
        Ok(tree)
    }

    fn walk(&mut self, root: &Path, dir: &Path) -> std::io::Result<()> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            // An unreadable directory is not a citation problem; skip it rather
            // than fail the gate on a permissions quirk.
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                self.walk(root, &path)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !SOURCE_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            self.basenames.insert(name);
            self.files.insert(rel.clone());
            if ext == "rs" {
                if let Ok(text) = fs::read_to_string(&path) {
                    for (fn_name, is_test) in rust_fns(&text) {
                        if is_test {
                            self.test_fns
                                .entry(fn_name.clone())
                                .or_default()
                                .push(rel.clone());
                        }
                        self.all_fns.entry(fn_name).or_default().push(rel.clone());
                    }
                }
            }
        }
        Ok(())
    }

    fn has_file(&self, cited: &str) -> bool {
        if self.files.contains(cited) {
            return true;
        }
        let base = cited.rsplit('/').next().unwrap_or(cited);
        self.basenames.contains(base)
    }

    /// The closest existing test name, when it is close enough to be worth
    /// naming as the likely rename.
    fn closest_test(&self, name: &str) -> Option<(&str, &str)> {
        let wanted: BTreeSet<&str> = name.split('_').filter(|t| !t.is_empty()).collect();
        let mut best: Option<(f64, &str, &str)> = None;
        for (candidate, files) in &self.test_fns {
            let theirs: BTreeSet<&str> = candidate.split('_').filter(|t| !t.is_empty()).collect();
            let shared = wanted.intersection(&theirs).count() as f64;
            let union = wanted.union(&theirs).count() as f64;
            if union == 0.0 {
                continue;
            }
            let score = shared / union;
            if best.map(|(b, _, _)| score > b).unwrap_or(true) {
                let file = files.first().map(String::as_str).unwrap_or("");
                best = Some((score, candidate, file));
            }
        }
        match best {
            Some((score, candidate, file)) if score >= 0.5 => Some((candidate, file)),
            _ => None,
        }
    }
}

/// Pull every fn in a Rust source, paired with whether it carries a test
/// attribute. Attributes may span lines (`#[cfg_attr(not(feature = "x"),
/// ignore = "...")]`), so bracket depth is tracked rather than assuming one
/// attribute per line.
fn rust_fns(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut attrs = String::new();
    let mut depth: i32 = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if depth > 0 {
            attrs.push_str(trimmed);
            depth += bracket_delta(trimmed);
            continue;
        }
        if trimmed.starts_with("#[") {
            attrs.push_str(trimmed);
            depth += bracket_delta(trimmed);
            continue;
        }
        if let Some(name) = fn_name(trimmed) {
            let is_test = attrs.contains("#[test]")
                || attrs.contains("#[test(")
                || attrs.contains("::test]")
                || attrs.contains("::test(");
            out.push((name, is_test));
            attrs.clear();
            continue;
        }
        // Blank lines and doc comments sit between an attribute and its fn, so
        // they do not end the attribute run. Anything else does.
        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            attrs.clear();
        }
    }
    out
}

fn bracket_delta(line: &str) -> i32 {
    line.chars().filter(|c| *c == '[').count() as i32
        - line.chars().filter(|c| *c == ']').count() as i32
}

fn fn_name(trimmed: &str) -> Option<String> {
    let mut rest = trimmed;
    for prefix in [
        "pub(crate) ",
        "pub(super) ",
        "pub ",
        "default ",
        "const ",
        "async ",
        "unsafe ",
        "extern \"C\" ",
    ] {
        while let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
        }
    }
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Every citation in the "Proving test" column of every table in the document.
pub fn extract_citations(doc: &str) -> Vec<Citation> {
    let mut out = Vec::new();
    let mut column: Option<usize> = None;
    for (index, line) in doc.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            column = None;
            continue;
        }
        let cells = split_row(trimmed);
        if let Some(found) = cells
            .iter()
            .position(|c| normalize_header(c) == "proving test")
        {
            column = Some(found);
            continue;
        }
        if is_separator(trimmed) {
            continue;
        }
        let Some(column) = column else { continue };
        let Some(cell) = cells.get(column) else {
            continue;
        };
        let claim = summarize_claim(cells.first().map(String::as_str).unwrap_or(""));
        for raw in backtick_spans(cell) {
            let mut expanded = Vec::new();
            expand_braces(&raw, &mut expanded);
            for token in expanded {
                if let Some(citation) = classify(&token) {
                    out.push(Citation {
                        line: line_no,
                        claim: claim.clone(),
                        raw: raw.clone(),
                        ..citation
                    });
                }
            }
        }
    }
    out
}

/// Check every citation against the tree.
pub fn check(doc: &str, tree: &Tree) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut reported: BTreeSet<(String, usize)> = BTreeSet::new();
    for citation in extract_citations(doc) {
        let verdict = match citation.kind {
            Kind::File => {
                if tree.has_file(&citation.name) {
                    Verdict::Live
                } else {
                    Verdict::Dead
                }
            }
            Kind::TestName => {
                if tree.test_fns.contains_key(&citation.name) {
                    Verdict::Live
                } else if tree.all_fns.contains_key(&citation.name) {
                    Verdict::NotATest
                } else {
                    Verdict::Dead
                }
            }
        };
        if verdict == Verdict::Live {
            continue;
        }
        if !reported.insert((citation.name.clone(), citation.line)) {
            continue;
        }
        let cause = explain(&citation, verdict, tree);
        out.push(Finding {
            citation,
            verdict,
            cause,
        });
    }
    out
}

fn explain(citation: &Citation, verdict: Verdict, tree: &Tree) -> String {
    match verdict {
        Verdict::Live => String::new(),
        Verdict::NotATest => {
            let where_at = tree
                .all_fns
                .get(&citation.name)
                .and_then(|f| f.first())
                .cloned()
                .unwrap_or_default();
            format!(
                "exists as a function in {where_at} but carries no #[test]; either the row is naming a \
                 symbol rather than a test, or the attribute was dropped"
            )
        }
        Verdict::Dead => match citation.kind {
            Kind::File => "no file of that name is in the tree; deleted, moved, or never committed"
                .to_string(),
            Kind::TestName => {
                if let Some(module) = &citation.module {
                    if !tree.has_file(module) {
                        return format!(
                            "gone with its module: the row cites {module}, which is not in the tree \
                             either, so the whole file was renamed or absorbed elsewhere"
                        );
                    }
                }
                match tree.closest_test(&citation.name) {
                    Some((closest, file)) => format!(
                        "likely renamed: the closest test in the tree is {closest} in {file}"
                    ),
                    None => {
                        "no test of a similar name exists; deleted, or never existed".to_string()
                    }
                }
            }
        },
    }
}

/// Format findings for a human. Groups by verdict so the fatal ones lead.
pub fn report(findings: &[Finding], known_stale: &[&str]) -> String {
    let stale: BTreeSet<&str> = known_stale.iter().copied().collect();
    let mut new_dead = Vec::new();
    let mut allowed = Vec::new();
    let mut warnings = Vec::new();
    for finding in findings {
        match finding.verdict {
            Verdict::NotATest => warnings.push(finding),
            Verdict::Dead if stale.contains(finding.citation.name.as_str()) => {
                allowed.push(finding)
            }
            Verdict::Dead => new_dead.push(finding),
            Verdict::Live => {}
        }
    }

    let mut out = String::new();
    if !new_dead.is_empty() {
        let _ = writeln!(
            out,
            "docs/security-claims.md cites {} test(s) that do not exist in the tree.\n\
             A claim row citing a dead test reads as proven and is not. Re-cite the row against a \
             test that exists, or mark the claim UNPROVEN.\n",
            new_dead.len()
        );
        for finding in &new_dead {
            let _ = writeln!(out, "{}", detail(finding));
        }
    }
    if !allowed.is_empty() {
        let _ = writeln!(
            out,
            "{} citation(s) were already dead before this gate existed (KNOWN_STALE in \
             crates/sigil-doccheck/src/lib.rs). They are reported, not enforced. This list must \
             only shrink.\n",
            allowed.len()
        );
        for finding in &allowed {
            let _ = writeln!(out, "{}", detail(finding));
        }
    }
    if !warnings.is_empty() {
        let _ = writeln!(
            out,
            "{} name(s) in a proving-test column resolve to a function with no #[test]. Not \
             enforced (the column names symbols in prose too), but worth an eye.\n",
            warnings.len()
        );
        for finding in &warnings {
            let _ = writeln!(out, "{}", detail(finding));
        }
    }
    out
}

fn detail(finding: &Finding) -> String {
    format!(
        "  line {}: {}\n    claim: {}\n    cause: {}",
        finding.citation.line, finding.citation.name, finding.citation.claim, finding.cause
    )
}

/// Names in `known_stale` that no longer describe a dead citation. Each one is
/// a ratchet click that has to be given up: the row was fixed (or removed), so
/// the entry has to go.
pub fn stale_allowlist_entries(findings: &[Finding], known_stale: &[&str]) -> Vec<String> {
    let dead: BTreeSet<&str> = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Dead)
        .map(|f| f.citation.name.as_str())
        .collect();
    known_stale
        .iter()
        .filter(|name| !dead.contains(*name))
        .map(|name| (*name).to_string())
        .collect()
}

/// Findings that must fail the build: dead citations nobody has recorded.
pub fn fatal<'a>(findings: &'a [Finding], known_stale: &[&str]) -> Vec<&'a Finding> {
    let stale: BTreeSet<&str> = known_stale.iter().copied().collect();
    findings
        .iter()
        .filter(|f| f.verdict == Verdict::Dead && !stale.contains(f.citation.name.as_str()))
        .collect()
}

/// The repo root, found by walking up from this crate.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sigil-doccheck sits two levels below the repo root")
        .to_path_buf()
}

// --- document parsing ------------------------------------------------------

/// Split a table row on unescaped pipes, dropping the empty cells the leading
/// and trailing pipe produce.
fn split_row(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                current.push(ch);
            }
            '|' => {
                cells.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    cells.push(current.trim().to_string());
    if cells.first().map(String::is_empty).unwrap_or(false) {
        cells.remove(0);
    }
    if cells.last().map(String::is_empty).unwrap_or(false) {
        cells.pop();
    }
    cells
}

fn is_separator(line: &str) -> bool {
    line.chars()
        .all(|c| matches!(c, '|' | '-' | ':' | ' ' | '\t'))
}

fn normalize_header(cell: &str) -> String {
    cell.trim()
        .trim_matches(|c| c == '*' || c == '`' || c == '#')
        .trim()
        .to_lowercase()
}

fn backtick_spans(cell: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = cell;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else { break };
        let span = after[..end].trim();
        if !span.is_empty() {
            out.push(span.to_string());
        }
        rest = &after[end + 1..];
    }
    out
}

/// `a::{b,c}d` becomes `a::bd`, `a::cd`. The document uses this shorthand
/// heavily, including with a shared suffix outside the braces.
fn expand_braces(token: &str, out: &mut Vec<String>) {
    if let Some(open) = token.find('{') {
        if let Some(offset) = token[open..].find('}') {
            let close = open + offset;
            let (pre, inner, post) = (&token[..open], &token[open + 1..close], &token[close + 1..]);
            for part in inner.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                expand_braces(&format!("{pre}{part}{post}"), out);
            }
            return;
        }
    }
    out.push(token.to_string());
}

/// Decide whether a token is a citation this gate can check, and of what kind.
/// Anything ambiguous is dropped: a gate that fires on prose is a gate people
/// learn to skip.
fn classify(token: &str) -> Option<Citation> {
    let token = token.trim();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    let token = token
        .trim_matches(|c: char| matches!(c, '(' | ')' | '.' | ',' | ';' | ':' | '\'' | '"'))
        .trim_end_matches("()");
    // A file, optionally with a :line suffix.
    let without_line = match token.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => token,
    };
    if let Some((_, ext)) = without_line.rsplit_once('.') {
        if SOURCE_EXTENSIONS.contains(&ext) {
            return Some(Citation {
                line: 0,
                claim: String::new(),
                raw: token.to_string(),
                name: without_line.to_string(),
                module: None,
                kind: Kind::File,
            });
        }
    }
    // A test name, with or without a `file.rs::` prefix.
    let (module, name) = match token.rsplit_once("::") {
        Some((head, tail)) => (
            Some(head.rsplit("::").next().unwrap_or(head).to_string()),
            tail,
        ),
        None => (None, token),
    };
    if !is_test_name(name) {
        return None;
    }
    let module = module.filter(|m| {
        m.rsplit_once('.')
            .map(|(_, ext)| SOURCE_EXTENSIONS.contains(&ext))
            .unwrap_or(false)
    });
    Some(Citation {
        line: 0,
        claim: String::new(),
        raw: token.to_string(),
        name: name.to_string(),
        module,
        kind: Kind::TestName,
    })
}

/// Rust test names in this repo are whole sentences in snake_case. Requiring
/// two underscores keeps ordinary identifiers (`grant_key`, `peer_pid`) and
/// constants out of the citation set.
fn is_test_name(name: &str) -> bool {
    name.len() >= 8
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.matches('_').count() >= 2
}

fn summarize_claim(cell: &str) -> String {
    let plain: String = cell
        .chars()
        .filter(|c| !matches!(c, '`' | '*' | '|'))
        .collect();
    let plain = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    let limit = 96;
    if plain.chars().count() <= limit {
        return plain;
    }
    let cut: String = plain.chars().take(limit).collect();
    format!("{}...", cut.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_cites_the_test_column_only() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| A thing holds | `secrets.rs::encrypt_token_helper` | `secrets.rs::the_thing_holds` |
";
        let cited: Vec<String> = extract_citations(doc).into_iter().map(|c| c.name).collect();
        assert_eq!(cited, vec!["the_thing_holds".to_string()]);
    }

    #[test]
    fn brace_shorthand_expands_with_a_shared_prefix_and_suffix() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | `replay.rs::{first_case_is_rejected,second_case_is_rejected}`, `hostile_relay.rs::{bumped_counter,rewound_counter}_is_rejected` |
";
        let cited: Vec<String> = extract_citations(doc).into_iter().map(|c| c.name).collect();
        assert_eq!(
            cited,
            vec![
                "first_case_is_rejected",
                "second_case_is_rejected",
                "bumped_counter_is_rejected",
                "rewound_counter_is_rejected",
            ]
        );
    }

    #[test]
    fn a_bare_continuation_name_is_a_citation_and_prose_is_not() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | `pairing.rs::forged_tag_is_rejected`, `stripped_tag_is_rejected`; see `REPLAY_WINDOW_MS` and `bun run proto:selftest` and `grant_key` |
";
        let cited: Vec<String> = extract_citations(doc).into_iter().map(|c| c.name).collect();
        assert_eq!(
            cited,
            vec!["forged_tag_is_rejected", "stripped_tag_is_rejected"]
        );
    }

    #[test]
    fn a_file_citation_is_recognised_with_or_without_a_line_number() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | `apps/phone/src/lib/format.selftest.ts`, `protocol.ts:325` |
";
        let cited: Vec<(String, Kind)> = extract_citations(doc)
            .into_iter()
            .map(|c| (c.name, c.kind))
            .collect();
        assert_eq!(
            cited,
            vec![
                (
                    "apps/phone/src/lib/format.selftest.ts".to_string(),
                    Kind::File
                ),
                ("protocol.ts".to_string(), Kind::File),
            ]
        );
    }

    #[test]
    fn a_verdict_column_does_not_shift_which_cell_is_read() {
        let doc = "\
| Claim | Enforcing code | Proving test | Verdict |
|---|---|---|---|
| c | `code.rs::enforcing_symbol_here` | `t.rs::the_proving_test_here` | **SOUND** |
";
        let cited: Vec<String> = extract_citations(doc).into_iter().map(|c| c.name).collect();
        assert_eq!(cited, vec!["the_proving_test_here".to_string()]);
    }

    #[test]
    fn an_escaped_pipe_inside_a_cell_does_not_split_it() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| sent \\| refused | e | `t.rs::the_only_real_test_name` |
";
        let cited: Vec<String> = extract_citations(doc).into_iter().map(|c| c.name).collect();
        assert_eq!(cited, vec!["the_only_real_test_name".to_string()]);
    }

    #[test]
    fn a_table_without_a_proving_test_column_is_skipped() {
        let doc = "\
| # | Property | Verdict |
|---|---|---|
| 1 | `some_property_name_here` | **SOUND** |
";
        assert!(extract_citations(doc).is_empty());
    }

    #[test]
    fn tests_are_recognised_through_multi_line_attributes() {
        let source = r#"
            #[test]
            fn a_plain_test() {}

            #[tokio::test]
            async fn an_async_test() {}

            #[test]
            #[cfg_attr(
                not(feature = "real-relay"),
                ignore = "needs the relay [see readme]"
            )]
            fn a_conditionally_ignored_test() {}

            /// Not a test at all.
            pub fn an_ordinary_function() {}
        "#;
        let found: BTreeMap<String, bool> = rust_fns(source).into_iter().collect();
        assert!(found["a_plain_test"]);
        assert!(found["an_async_test"]);
        assert!(found["a_conditionally_ignored_test"]);
        assert!(!found["an_ordinary_function"]);
    }

    #[test]
    fn a_dead_citation_names_its_row_and_a_likely_cause() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| Tokens are ciphertext at rest | `secrets.rs::encrypt_token` | `secrets.rs::store_persists_only_ciphertext` |
";
        let tree = Tree {
            test_fns: BTreeMap::from([(
                "store_persists_ciphertext_only".to_string(),
                vec!["crates/sigil/src/secrets.rs".to_string()],
            )]),
            all_fns: BTreeMap::new(),
            files: BTreeSet::from(["crates/sigil/src/secrets.rs".to_string()]),
            basenames: BTreeSet::from(["secrets.rs".to_string()]),
        };
        let findings = check(doc, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].verdict, Verdict::Dead);
        assert_eq!(findings[0].citation.line, 3);
        assert_eq!(findings[0].citation.claim, "Tokens are ciphertext at rest");
        assert!(
            findings[0].cause.contains("store_persists_ciphertext_only"),
            "the rename hint should name the surviving test, got: {}",
            findings[0].cause
        );
    }

    #[test]
    fn a_dead_module_is_named_as_the_cause() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| ECIES matches Apple | `se_ecies.rs::wrap_dek_p256` | `se_ecies.rs::wrap_unwrap_round_trips_the_dek` |
";
        let tree = Tree {
            test_fns: BTreeMap::new(),
            all_fns: BTreeMap::new(),
            files: BTreeSet::new(),
            basenames: BTreeSet::new(),
        };
        let findings = check(doc, &tree);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cause.contains("se_ecies.rs"),
            "cause should name the vanished module, got: {}",
            findings[0].cause
        );
    }

    #[test]
    fn a_recorded_stale_citation_is_reported_but_not_fatal() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | `t.rs::a_test_that_went_away` |
";
        let tree = Tree {
            test_fns: BTreeMap::new(),
            all_fns: BTreeMap::new(),
            files: BTreeSet::from(["t.rs".to_string()]),
            basenames: BTreeSet::from(["t.rs".to_string()]),
        };
        let findings = check(doc, &tree);
        assert!(fatal(&findings, &["a_test_that_went_away"]).is_empty());
        assert_eq!(fatal(&findings, &[]).len(), 1);
        assert!(report(&findings, &["a_test_that_went_away"]).contains("must only shrink"));
    }

    #[test]
    fn an_allowlist_entry_that_came_back_to_life_is_surrendered() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | `t.rs::a_test_that_exists_again` |
";
        let tree = Tree {
            test_fns: BTreeMap::from([(
                "a_test_that_exists_again".to_string(),
                vec!["t.rs".to_string()],
            )]),
            all_fns: BTreeMap::new(),
            files: BTreeSet::from(["t.rs".to_string()]),
            basenames: BTreeSet::from(["t.rs".to_string()]),
        };
        let findings = check(doc, &tree);
        assert_eq!(
            stale_allowlist_entries(&findings, &["a_test_that_exists_again"]),
            vec!["a_test_that_exists_again".to_string()]
        );
    }

    #[test]
    fn a_symbol_that_is_not_a_test_is_reported_without_failing() {
        let doc = "\
| Claim | Enforcing code | Proving test |
|---|---|---|
| c | e | reviewed by inspection; `unwrap_dek_from_the_wrap` was hardened here |
";
        let tree = Tree {
            test_fns: BTreeMap::new(),
            all_fns: BTreeMap::from([(
                "unwrap_dek_from_the_wrap".to_string(),
                vec!["crates/sigil/src/keystore.rs".to_string()],
            )]),
            files: BTreeSet::new(),
            basenames: BTreeSet::new(),
        };
        let findings = check(doc, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].verdict, Verdict::NotATest);
        assert!(fatal(&findings, &[]).is_empty());
    }
}
