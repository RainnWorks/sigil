# Ticket skill: research

Input for the talk about `.claude/skills/ticket/SKILL.md`. Read only. No Linear data was read or
changed: the `linear-server` MCP is not connected in this project yet, so every statement below
about Linear comes from the Attention work, not from Sigil's own workspace.

## What still has to be checked in Linear

| To check | Why it matters |
|---|---|
| The Sigil team exists, with Triage on | Rule 3 sends raw ideas to Triage. Without it they have nowhere to go. |
| The team key | The skill says `SIG`. If Tom picks another, the skill changes. |
| A `Sigil` project exists | Tickets are filed into it. |
| The workspace `Kind` labels are visible to the team | The skill uses `build`, `fix`, `spec`, `design`, `research` and creates nothing. |

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
