# Ticket template

Title: the task in plain words, as a command. "Require a fresh proof on every approve", not
"Approve proof work".

```markdown
## Why
One or two lines: the problem, and for whom. Quote Tom where you can.
Brief: <section>. Claims row: <row, if any>. Invariant: <number, if any>.

## Before and after
Before: <what happens today>
After: <what happens instead>

## Acceptance
- [ ] <observable check>
- [ ] <observable check>

## Verify
The exact command, test or screenshot the PR must show as evidence.
The gate, when code changes:
  cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
Phone: npx tsc --noEmit and the selftests. Mac: the headless build.

## Device check
Only what a headless build cannot prove: Secure Enclave, Face ID, keychain class,
backup and restore. Stays unproven until Tom runs it. Delete if empty.

## Review
Security review: <yes, and why> | <no>
Design review: <yes, for which surface> | <no>

## Context
Files it touches. The existing pattern to copy. Related tickets and PRs.

## Out of scope
- <what this ticket does not do>

## Rabbit holes
- <where the work could wander, and what to do instead>

## Decisions for Tom
- <question> Recommendation: <pick>, because <one line>.
(Delete this section when it is empty.)

Size: S (hours) | M (a day or two) | L (split it)
```
