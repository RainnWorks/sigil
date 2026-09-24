---
name: ticket
description: Drafts, splits and files Linear tickets for Sigil with Tom, one at a time. Use when Tom asks for a ticket, a task, an issue, or to put work on the Linear board, to break work down, or to plan what comes next. Never create or change a Linear issue without following it.
---

# Ticket

Sigil is driven from Linear. A ticket is a product decision, not a to-do. Each one is worked out
with Tom before it exists. This skill stops the failure Tom named: agents "running away and
creating a million tasks", none of them thought through.

## Rules

1. Nothing is written to Linear until Tom has seen the final draft in chat and said yes. His yes
   covers that one ticket only.
2. At most five tickets not yet started in the Sigil project at any time. When there are five, say so
   and do not draft a sixth; ask Tom which to drop or finish first.
3. An idea that is not worked out goes to Triage as one line with where it came from. Only Tom
   accepts from Triage.
4. One ticket is one pull request Tom can review in one sitting. Bigger work is split with Tom
   (step 4), never by you alone.
5. Never delegate a ticket to a Linear agent or start a Linear coding session. Tom does not use
   them. Agents that do the work read Linear, report in the PR, and never change a ticket's status.
6. Never create labels, teams or projects. Use what exists; ask Tom if something is missing.
7. Write for Tom: short lines, plain words, no metaphors, no restating. Cite the brief or the
   claims document by section instead of paraphrasing it.
8. Agents never merge and never deploy. A ticket never asks one to.

## Where things live

- Linear: the **Rainnworks** team (key `RAI`), project **Sigil** (`P-RAI-6`). Work is split by
  project, not by team. Do not propose a new team or project unless Tom asks.
- Labels: one from the workspace **Kind** group: `build`, `fix`, `spec`, `design`, `research`.
  Ignore the `area/*`, `role/*`, `Feature`, `Bug`, `Improvement` and `tonight` labels; they belong
  to the OSRS work.
- The constitution: `docs/design/sigil-design-brief.html`. When the code and the brief disagree,
  the ticket fixes one of them in the same change. Its Build state table says what is not built.
- The security record: `docs/security-claims.md`. A ticket that changes what the product claims
  must name the row it changes.
- The invariants: `CLAUDE.md` and `.claude/agents/security-reviewer.md`. A ticket may not weaken
  one. Invariant 4 is a known open gap being closed; do not reword it.
- Design notes for a subsystem: `docs/design/*.md`.

## Sigil-specific rules

- Any change touching crypto, keys, the envelope, the shim, leases, pairing or the relay needs an
  independent security review. Name it in the ticket. The implementer never writes the verdict.
- A user-facing change (a screen, CLI output, microcopy, a state) needs a design review. Name it.
- A claim only counts when a test proves it. `cargo test` includes the citation gate: a row in
  `docs/security-claims.md` may not name a test that is not in the tree.
- Some things can only be proved on hardware: the Secure Enclave, Face ID, the keychain class, a
  backup and restore. Those go in the ticket's Device check, marked unproven until Tom runs them.
  Never write an acceptance check that a headless build cannot see.

## The flow

### 1. Intake

Before drafting, read the Sigil project's open tickets with the Linear tools, so you do not duplicate
one. Then write back, in two or three lines:

- the problem in Tom's words, quoted where you can
- who has it: Tom, a person approving on a phone, an agent using a gated command, or the daemon
- the brief section or claims row it serves

If nothing in the brief fits, say so. The ticket may need a brief change first, and that is its own
ticket.

### 2. Draft

Fill in [template.md](template.md). Read the code and the docs you cite; do not guess what exists.
Every acceptance check is something Tom can observe: a command and its output, a screen and what it
shows, a log line. "Works correctly" is not a check. Propose a size; Tom sets it.

### 3. Check with Tom

Show the draft in chat. Ask only the open decisions, each with your recommendation. Change it until
Tom says yes. If he says "not now", it goes to Triage as one line.

### 4. Split, when the size is L

- Split into thin slices that each do something visible end to end, not into layers.
- Each slice has its own acceptance and verify lines.
- The first slice is the smallest one that proves the idea.
- Write the order and what each slice unblocks.

Tom picks the split. Only the first slice is drafted now. The rest are one line each in chat, and
go to Triage if Tom wants them kept.

### 5. File

Only after Tom's yes on the final text:

- create the issue in the Rainnworks team, project Sigil, status Backlog, with one Kind label
- set the size as the estimate
- link blockers with Linear relations, not in prose
- post the issue link in chat, and nothing else

While a decision in the ticket is open, it stays in Backlog. It moves to Todo only when Tom moves it.
