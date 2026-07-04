# latch

Personal remote-approval instrument for 1Password secrets. Single user (Tom),
never a team product. The design brief at `docs/design/latch-design-brief.html`
is the constitution; when code and brief disagree, either fix the code or
update the brief in the same change, never let them drift.

## Agent team

Specialized profiles live in `.claude/agents/`. Route work accordingly:

- **rust-core**: anything under `crates/` (daemon, proto, shim, ssh-agent, CLI)
- **mac-app**: `apps/mac` (SwiftUI configurator, menubar, Touch ID/SE)
- **phone-app**: `apps/phone` (Expo approver, keystore crypto, push)
- **relay**: `relay/` (blind mailbox Worker + Bun variant)
- **security-reviewer**: run on EVERY change touching crypto, keys, envelope,
  shim, leases, pairing, or relay. Adversarial; owns the hostile-relay suite.
- **design-reviewer**: run on every user-facing change (screens, CLI output,
  microcopy, states).

Vendored skills in `.agents/skills/` are house style: rust-best-practices,
rust-async-patterns, swiftui-expert-skill, swiftui-pro, building-native-ui,
expo-deployment, workers-best-practices.

## Non-negotiable invariants (see .claude/agents/security-reviewer.md for the full list)

1. Daemon at rest is inert: tokens are ciphertext; the DEK arrives per-approval
   from the phone (or a live lease) and is zeroized after use.
2. Secret bytes never enter daemon memory: op child stdout splices to the
   client fd.
3. The relay is powerless and anonymous: opaque envelopes, key-hash mailboxes,
   no accounts, no key-distribution role.
4. Approve requires hardware-gated biometrics; deny requires nothing.
5. Everything fails closed.
6. Zero em-dashes and zero emoji in any user-facing string.

## Commands

```sh
cargo test && cargo clippy -- -D warnings && cargo fmt --check   # gate for crates/
```

`reference/op-remote/` is read-only prior art (wyattjoh's repo, own .git);
never modify it.
