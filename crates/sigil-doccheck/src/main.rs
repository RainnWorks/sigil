//! Prints the full citation report for docs/security-claims.md.
//!
//! `cargo test` enforces the same thing (see tests/security_claims_citations.rs);
//! this binary exists so CI can print the whole picture on every run, including
//! the citations that are already dead. A ratchet nobody can see is a ratchet
//! that quietly stops turning.
//!
//! Exit 0 when every dead citation is one of the recorded ones, 1 otherwise.

use std::process::ExitCode;

use sigil_doccheck::{check, fatal, repo_root, report, stale_allowlist_entries, Tree, KNOWN_STALE};

fn main() -> ExitCode {
    let root = repo_root();
    let doc_path = root.join("docs/security-claims.md");
    let doc = match std::fs::read_to_string(&doc_path) {
        Ok(doc) => doc,
        Err(err) => {
            eprintln!("cannot read {}: {err}", doc_path.display());
            return ExitCode::FAILURE;
        }
    };
    let tree = match Tree::index(&root) {
        Ok(tree) => tree,
        Err(err) => {
            eprintln!("cannot index {}: {err}", root.display());
            return ExitCode::FAILURE;
        }
    };

    let findings = check(&doc, &tree);
    let text = report(&findings, KNOWN_STALE);
    if text.is_empty() {
        println!("security-claims citations: all live, and nothing recorded as stale.");
        return ExitCode::SUCCESS;
    }
    print!("{text}");

    let surrendered = stale_allowlist_entries(&findings, KNOWN_STALE);
    if !surrendered.is_empty() {
        println!(
            "{} KNOWN_STALE entr(ies) are no longer dead and must be deleted from \
             crates/sigil-doccheck/src/lib.rs:",
            surrendered.len()
        );
        for name in &surrendered {
            println!("  {name}");
        }
    }

    if fatal(&findings, KNOWN_STALE).is_empty() && surrendered.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
