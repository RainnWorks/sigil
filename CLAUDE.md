# Sigil

Personal remote-approval instrument for 1Password secrets. Single user (Tom),
never a team product. The design brief at `docs/design/sigil-design-brief.html`
is the constitution; when code and brief disagree, either fix the code or
update the brief in the same change, never let them drift.

## Agent team

Specialized profiles live in `.claude/agents/`. Route work accordingly:

- **rust-core**: anything under `crates/` (daemon, proto, shim, ssh-agent, CLI)
- **mac-app**: `apps/mac` (SwiftUI configurator, menubar, Touch ID/SE)
- **phone-app**: `apps/phone` (Expo approver, keystore crypto, push)
- **relay**: `crates/sigil-relay` (native Rust blind mailbox; serves `relay/landing.html`), deployed per `deploy/gcp/`
- **security-reviewer**: run on EVERY change touching crypto, keys, envelope,
  shim, leases, pairing, or relay. Adversarial; owns the hostile-relay suite.
- **design-reviewer**: run on every user-facing change (screens, CLI output,
  microcopy, states).

Vendored skills in `.agents/skills/` are house style: rust-best-practices,
rust-async-patterns, swiftui-expert-skill, swiftui-pro, building-native-ui,
expo-deployment, workers-best-practices.

**Review integrity rule:** an implementer NEVER writes a "reviewed and found
sound" verdict about its own code in docs/security-claims.md. Implementers
document behavior and residuals; only an independent security-reviewer (one that
did not write the code) writes review verdicts. Crypto especially gets an
independent adversarial pass, never self-certification.

## Non-negotiable invariants (see .claude/agents/security-reviewer.md for the full list)

1. Daemon at rest is inert: secrets are threshold-sealed ciphertext. Opening one
   needs the phone's per-approval partial combined with the Mac share (or a live
   lease); both are zeroized after use. There is no DEK; that was the retired v1
   model.
2. Secret bytes never enter daemon memory: op child stdout splices to the
   client fd.
3. The relay is powerless and anonymous: opaque envelopes, key-hash mailboxes,
   no accounts, no key-distribution role.
4. Approve requires hardware-gated biometrics; deny and revoke require nothing.
   A biometric binds to a DEVICE, not a human, so anything that lets the
   approving identity leave the device defeats this entirely. No gate may accept
   a device passcode. KNOWN OPEN GAP, being closed, do not reword this invariant
   to match it: a plain-gate approve is today authorized by a biometric check
   alone with no enclave key use, and every `op` rule is a plain gate. Treat a
   plain-gate approve path that unlocks nothing cryptographic as the gap this
   invariant exists to close, not as compliant.
5. Everything fails closed.
6. Zero em-dashes and zero emoji in any user-facing string.

## Commands

```sh
cargo test && cargo clippy -- -D warnings && cargo fmt --check   # gate for crates/
cargo run -p sigil-doccheck    # docs/security-claims.md citation report
```

`cargo test` includes the citation gate: a claim row in docs/security-claims.md
may not name a proving test that is not in the tree. The already-dead citations
are recorded in `KNOWN_STALE` (crates/sigil-doccheck/src/lib.rs), a list that
must only shrink.

`reference/op-remote/` is read-only prior art (wyattjoh's repo, own .git);
never modify it.
