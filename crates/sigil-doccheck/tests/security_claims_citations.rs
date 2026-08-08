//! The gate: docs/security-claims.md may not cite a test that is not there.
//!
//! This is the one mechanism in the program that catches a security claim going
//! false without anyone touching the claim. A test gets renamed, the row that
//! cites it keeps reading as proven, and the next reviewer cites the row instead
//! of reading the code. It has already happened at a rate of hours.

use sigil_doccheck::{check, fatal, repo_root, report, stale_allowlist_entries, Tree, KNOWN_STALE};

fn findings() -> Vec<sigil_doccheck::Finding> {
    let root = repo_root();
    let doc = std::fs::read_to_string(root.join("docs/security-claims.md"))
        .expect("docs/security-claims.md is part of the repo");
    let tree = Tree::index(&root).expect("the working tree is readable");
    check(&doc, &tree)
}

#[test]
fn every_cited_test_exists_in_the_tree() {
    let findings = findings();
    let dead = fatal(&findings, KNOWN_STALE);
    assert!(
        dead.is_empty(),
        "\n{}\nRun `cargo run -p sigil-doccheck` for the whole picture.\n",
        report(&findings, KNOWN_STALE)
    );
}

#[test]
fn the_known_stale_list_only_shrinks() {
    let findings = findings();
    let surrendered = stale_allowlist_entries(&findings, KNOWN_STALE);
    assert!(
        surrendered.is_empty(),
        "\nThese KNOWN_STALE entries in crates/sigil-doccheck/src/lib.rs no longer describe a dead \
         citation, because the row was re-cited or removed. Delete them; the list is a ratchet and \
         this is it clicking:\n  {}\n",
        surrendered.join("\n  ")
    );
}
