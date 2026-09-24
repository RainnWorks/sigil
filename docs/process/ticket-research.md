# Ticket skill: research

Input for the talk about `.claude/skills/ticket/SKILL.md`. Read only. No Linear data was read or
changed: the `linear-server` MCP is not connected in this project yet, so every statement below
about Linear comes from the Attention work, not from Sigil's own workspace.

## What Linear holds now

Checked with the Linear tools, read only apart from the labels Tom asked for.

| Fact | Effect on the skill |
|---|---|
| One team, `Rainnworks` (key `RAI`). Teams cannot be added, so work is split by project. | The skill names the team `RAI` and the project `Sigil`. |
| Project `Sigil` is `P-RAI-6`. `Attention` is `P-RAI-5`. | Two products, one team, one board each. |
| Triage is on. | Rule 3 has somewhere to send a raw idea. |
| The `Kind` group was a team label on a team that was later deleted, which deleted the labels with it. | Recreated at workspace level, on Tom's yes. A team deletion cannot take them again, and Attention shares them. |
| `Kind` holds `build`, `fix`, `spec`, `design`, `research`, one per issue. | The only labels a ticket uses. |
| The team also carries `area/*`, `role/*`, `Feature`, `Bug`, `Improvement`, `tonight` from the OSRS work. | The skill says to ignore them, so a ticket cannot pick from two sets. |

## What Sigil adds over the Attention version

Attention's rules carry over unchanged. These are the parts that are specific to this repo.

| Sigil fact | Effect on a ticket |
|---|---|
| The brief is the constitution. Code and brief may not drift. | A ticket that changes behaviour updates the brief in the same change. |
| `docs/security-claims.md` holds claims and independent verdicts. | A ticket that changes a claim names the row. Implementers never write verdicts. |
| `cargo test` includes a citation gate. | A claim may not name a test that is not in the tree. The gate fails the build. |
| Crypto, keys, envelope, shim, leases, pairing and relay need an independent review. | The ticket names the review. It is not optional and not self-certified. |
| Some properties are only provable on hardware. | Those go in Device check and stay unproven until Tom runs them. A headless test that claims them is worse than none. |
| Invariant 4 is a known open gap, deliberately not reworded. | A ticket may close it. No ticket may soften it. |

## Where the work is named

- Build state, in `docs/design/sigil-design-brief.html`: what is built, in progress, planned, later.
- `docs/security-claims.md`: open findings and residuals, each with a severity.
- `CLAUDE.md`: the six invariants, and which one is an open gap.

## Sources

The Linear and shaping research is in the Attention repo, on `process/ticket-skill`, at
`docs/process/ticket-research.md`. It is not copied here; it is the same material and it has not
changed.
