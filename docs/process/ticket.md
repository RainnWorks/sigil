# Tickets for Sigil

The `ticket` skill in `~/.claude/skills/ticket` holds the rules and the flow. This file holds what
is specific to Sigil. Where the two differ, this file wins.

## Linear

- Project: **Sigil** (`P-RAI-6`), in the Rainnworks team.

## What to cite

- The constitution: `docs/design/sigil-design-brief.html`. Cite the section. When the code and the
  brief disagree, the ticket fixes one of them in the same change. The Build state table says what
  is not built.
- The security record: `docs/security-claims.md`. A ticket that changes what the product claims
  names the row it changes.
- The invariants: `CLAUDE.md`, and the full list in `.claude/agents/security-reviewer.md`.
- Design notes for one subsystem: `docs/design/*.md`.

## Rules of its own

- Invariant 4 is a known open gap, deliberately not reworded. A ticket may close it. None may
  soften it.
- Any change touching crypto, keys, the envelope, the shim, leases, pairing or the relay needs an
  independent security review. The ticket names it. The implementer never writes the verdict.
- A user-facing change, meaning a screen, CLI output, microcopy or a state, needs a design review.
  The ticket names it.
- Every Verify line runs the gate:
  `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
  Phone work adds `npx tsc --noEmit` and the selftests. Mac work adds the headless build.
- `cargo test` includes the citation gate: a row in `docs/security-claims.md` may not name a test
  that is not in the tree. `KNOWN_STALE` may only shrink.
- Some properties are only provable on hardware: the Secure Enclave, Face ID, the keychain class,
  a backup and restore. Those go in a Device check and stay unproven until Tom runs them. Never
  write an acceptance check that a headless build cannot see.

## Research

Why the flow looks the way it does: [ticket-research.md](ticket-research.md).
