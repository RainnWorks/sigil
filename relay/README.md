# Sigil blind relay

The relay is now the native Rust crate at **`crates/sigil-relay`**. This
directory keeps only `landing.html`, the static page the relay serves at `GET
/`, because the crate embeds it at build time:

```rust
const LANDING_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"), "/../../relay/landing.html"));
```

Deleting `landing.html` breaks `cargo build -p sigil-relay`. Leave it here.

## Where the relay lives now

- **Source, protocol, push doorbell, tests:** `crates/sigil-relay/` (a tiny
  hand-rolled hyper server; one in-memory mailbox per pairing, opaque
  deposit/drain, long-poll, and the publisher-side APNs doorbell). Its own
  `README`-level design notes are in `docs/design/rust-relay.md`.
- **Container image:** `crates/sigil-relay/Dockerfile` (a static musl binary in
  a `scratch` image). Build from the repo root so `relay/landing.html` is in
  context.
- **Deploy:** `deploy/gcp/` self-hosts the binary on a GCP e2-micro behind
  Caddy and Cloudflare. See `deploy/gcp/README.md` for the runbook.

## History: the retired TypeScript relay

This directory used to hold two byte-identical TypeScript implementations of the
relay protocol: a Cloudflare Worker + Durable Object (`src/`) and a Bun server
(`bun/`), sharing `shared/protocol.ts` and `shared/push.ts`. Both were retired
once `crates/sigil-relay` became the relay; the Rust crate is a faithful port of
that same wire protocol and doorbell behavior, checked by the same test cases.
Their design rationale (why HTTP + ephemeral buffer rather than held sockets,
and the APNs trust-model note) is preserved in `docs/design/rust-relay.md`.

The live Cloudflare Worker may still be serving during cutover; retiring the TS
source here does not un-deploy it. Decommissioning the Worker and its
`CLOUDFLARE_*` secrets is a separate operational step.
