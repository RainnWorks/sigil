# Sigil

**Two-factor approval for your command-line secrets.** Sigil puts a tap on your
phone in front of secret access: when a script, an agent, or you reach for a
1Password token, an SSH key, or an environment variable, the secret is released
only after you approve it on your phone with Face ID.

The point is agents. When you hand a coding agent the keys to your vault, Sigil
turns "it can read every secret, always" into "it can ask, and you decide, per
use, on your phone."

> Status: early. The cryptography has had an independent review (see
> `docs/security-claims.md`), but this is pre-release and moving quickly. Read
> the code before you trust it with anything that matters.

## How it works

- **The daemon at rest is inert.** Stored tokens are ciphertext. The key that
  decrypts them is never sitting on disk in the clear; it is reconstructed per
  approval from two shares, one held by your Mac's Secure Enclave and one by
  your phone's Secure Enclave (a threshold split). Approving is the act of
  contributing the phone's share, behind a hardware biometric.
- **Secret bytes never enter the daemon's memory.** The provider's own process
  (for example `op`) writes the secret straight to the calling program's file
  descriptor. Sigil gates and injects; it does not read.
- **The relay is blind.** Your Mac and phone meet on a relay that moves sealed
  envelopes it cannot open, addressed by key-hashes it cannot reverse. It has no
  accounts, stores nothing at rest, and cannot read a secret, forge an approval,
  or learn an outcome. That is why it is safe to run wide open, and why you can
  use the shared one or self-host in one command.
- **Everything fails closed.** No phone, no approval, no biometric: no secret.

## Parts

| Part | What it is |
| --- | --- |
| CLI (`latch`, `latch-config`) | Gates a command, injects its secret, runs it. `latch op read ...` asks your phone first. |
| iOS app | The approver. A zero-knowledge approve/deny surface: it sees a request, never the outcome. |
| Mac app | A menubar configurator: pair a phone, add accounts, manage rules. |
| Relay | A stateless blind mailbox (a Cloudflare Worker, or a self-hosted Docker image). |

The command-line tool is named `latch` for historical reasons; the product is
Sigil.

## Quickstart

```sh
# Gate a command on your phone. An unmatched command is refused until you
# configure a rule for it.
latch op read "op://Private/GitHub/token"

# Configure what gets gated.
latch-config add op --provider 1password

# Pair your phone (shows a QR; compare the six words on both screens).
latch pair --relay https://relay.rainn.works
```

Approving requires a hardware biometric on your phone. Denying requires nothing.

## Self-host the relay

The relay is one stateless worker. Use the shared instance at
`relay.rainn.works`, or run your own:

```sh
docker run -p 8787:8787 ghcr.io/rainnworks/sigil-relay:latest
```

There is no password and no account, because there is nothing there to protect.
See `relay/DEPLOY.md` for the Cloudflare Worker path and `relay/README.md` for
the Docker path.

## Repository layout

| Path | What |
| --- | --- |
| `crates/proto` | Protocol core: sealed and signed envelopes, pairing, threshold crypto, the shared cross-language test vectors, and the hostile-relay suite |
| `crates/latch` | The daemon and CLI (multicall binary); `crates/relay-client` is the transport |
| `apps/phone` | The Expo iOS approver app |
| `apps/mac` | The SwiftUI menubar configurator |
| `relay` | The blind relay: a Cloudflare Worker and a protocol-identical Bun server |
| `docs/design` | The design brief (the constitution) |
| `docs/security-claims.md` | Independent security-review verdicts and open residuals |

## Build

```sh
cargo test && cargo clippy -- -D warnings && cargo fmt --check   # the crates gate
```

## Security

The design and its threat model live in
[`docs/design/latch-design-brief.html`](docs/design/latch-design-brief.html).
Independent review verdicts, and the residuals still open, live in
[`docs/security-claims.md`](docs/security-claims.md). If you find a problem,
please report it privately first.

## Credits

Sigil started from the design of [wyattjoh/op-remote](https://github.com/wyattjoh/op-remote),
whose prior art shaped this instrument.

## License

[Apache-2.0](LICENSE). Copyright 2026 Rainnworks.
