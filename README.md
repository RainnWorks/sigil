# latch

A personal instrument for approving 1Password secret access from your phone.

One daemon on the Mac, one app in your pocket. Every secret release and SSH
signature waits for your thumb, wherever you are. Built for one user; the
team never knows it exists.

The full design brief lives at [`docs/design/latch-design-brief.html`](docs/design/latch-design-brief.html).

## Layout

| Path | What |
| --- | --- |
| `crates/proto` | The protocol core: sealed/signed envelopes, pairing, fingerprints, and the hostile-relay proof suite |
| `crates/latch` | The multicall binary: `latch` CLI + daemon; a symlink named `op` is the shim |
| `apps/mac` | SwiftUI configurator + menubar (Liquid Glass) |
| `apps/phone` | Expo approver app (SwiftUI on iOS, Compose on Android) |
| `relay` | The blind relay: a tiny Cloudflare Worker and a protocol-identical Bun server |
| `reference/op-remote` | wyattjoh/op-remote, the prior art this design started from (own git history) |
| `.claude/agents` | The agent team: rust-core, mac-app, phone-app, relay, security-reviewer, design-reviewer |
| `.agents/skills` | Vendored community skills the agents follow |

## The one-sentence trust model

The daemon at rest cannot produce a single secret: service-account tokens are
ciphertext under a key that lives on the phone, delivered fresh inside each
biometric-gated approval, and every network hop carries only sealed, signed
envelopes between keys pinned at an in-person pairing.

## Build

```sh
cargo build            # daemon + CLI + shim (one binary)
cargo test             # includes the hostile-relay suite
```
