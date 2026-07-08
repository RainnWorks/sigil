# The native Rust blind relay (`crates/sigil-relay`)

A second, native implementation of the Sigil blind relay: a single static binary
with the smallest runtime footprint we can manage, so it is "basically free to
run" (idle RSS a couple of MB, near-zero idle CPU, fast cold start,
scale-to-zero friendly). It is **wire-compatible** with the existing TypeScript
relay (`relay/`, the Cloudflare Worker + Bun variants) and preserves every
protocol semantic and hardening property of it. No client change is needed to
point a daemon or phone at it.

This document is the design, the footprint numbers, the dependency
justification, the Cloudflare-vs-native tradeoff, and the deploy notes. The
adversarial hostile-relay stance and the trust relaxations live in
`relay/README.md` and are unchanged by this port; a security-reviewer owns the
verdict, as always.

## Why a native relay at all

The managed default stays the Cloudflare Worker: it is what `relay.rainn.works`
runs, it scales to zero on Cloudflare's own edge, and it needs no host. The
native binary exists for the other half of the deployment model in
`.claude/agents/relay.md`: **self-hosting**. A stranger who wants to run their
own message relay (Fly.io, a $4 VPS, a Nitro box, a Raspberry Pi) should not
have to stand up `workerd`, a Durable Object account, or a Bun runtime. A single
~1.7 MB static binary with no dependencies, no database, and no config beyond a
port is the leanest possible thing to hand them. It is also the natural home for
the **upstream knock** mode (below), which lets a self-hosted message relay keep
the background push doorbell for official-app users without holding Apple's cert.

## Footprint (measured)

Built with the workspace release profile (`strip = true`, `lto = true`,
`codegen-units = 1`, `opt-level = "z"`, `panic = "abort"`), on
`aarch64-apple-darwin`:

| Metric | Value |
|--------|-------|
| Release binary size | **1.7 MB** (stripped) |
| Idle RSS | **~2.4 MB** |
| RSS holding 50 concurrent long-polls | **~3.9 MB** |
| Idle CPU | ~0 (one event loop, all waiters parked) |
| Cold start | dominated by `TcpListener::bind`; no warmup, no DB, no migration |

The idle number is the point: a long-poll waiter is a suspended future plus one
`tokio::sync::oneshot` and a small closure, not a thread and not a held
connection thread. Thousands of idle waiters are thousands of parked futures on
a **single-threaded** tokio runtime (`new_current_thread`), so they cost RAM in
the low kilobytes each and no CPU until woken. The reqwest client used for the
APNs/knock POST is built **lazily** (a `OnceCell`), so a relay that never fires a
doorbell never even constructs the TLS stack.

## Architecture

Three small modules under `crates/sigil-relay/src`:

- **`protocol.rs`** — the pure, runtime-agnostic port of
  `relay/shared/protocol.ts`. Constants, the `Mailbox` state, `enqueue` /
  `drain` / `wake` / `rate_ok` / `push_ok` / `evict_expired`, and the typed
  response bodies. No I/O. This is where every wire decision is made, exactly as
  in the TS module, so the two stay byte-identical by construction. It has no
  dependency on any other Sigil crate.
- **`push.rs`** — the doorbell port of `relay/shared/push.ts`, plus the knock
  modes. ES256 JWT minting (P-256, RustCrypto `p256`, raw `r||s` as JWS wants),
  the fixed content-free APNs body, JWT caching/refresh, and upstream-knock
  forwarding. Fail-open throughout.
- **`server.rs`** — the tiny hand-rolled hyper router, the mailbox map, the async
  long-poll, and the sweep. No web framework.

`lib.rs` wires config from the environment and serves; `main.rs` is a thin
current-thread-runtime wrapper. The landing page is `include_str!`'d directly
from the one source file `relay/landing.html`, so there is a single source of
truth and no HTML drift between the native and TS relays.

### State and concurrency

State is `Mutex<HashMap<mailbox_id, Arc<Mutex<Mailbox>>>>`: one map lock, and a
per-mailbox lock so a held long-poll on one mailbox never blocks another. Every
critical section is synchronous and short; **no lock is ever held across an
`.await`** (the long-poll registers its waiter under the lock, drops the guard,
then awaits). Nothing is written to disk, ever: on restart every mailbox is
simply gone, exactly as if its short TTL had elapsed, and the depositing side
still holds its own copy to redeposit. A periodic sweep (every `TTL_MS`) evicts
expired items and drops mailboxes that are both empty and unwatched, keeping the
map bounded — the analog of the Bun variant's `setInterval` sweep. (The Worker
does not need one: a Durable Object is per-mailbox and the runtime reclaims it.)

### The long-poll and the offer-then-drain wake

The v5.2 semantics are preserved exactly. A `GET` on an empty slot registers a
`Waiter` and holds up to `LONG_POLL_MS` (25s). A deposit **offers** the
still-queued blobs to the **newest** waiter and only drains the buffer once that
waiter reports it **accepted** the offer; a settled/dead waiter rejects and the
items stay queued with their original `exp` (no TTL reset, no reorder) for the
next `GET`. `MAX_WAITERS` (8) bounds coexisting waiters, dropping the **oldest**
(stalest, likeliest orphaned) at the cap. Newest-wins delivers a
disconnect-then-reconnect correctly.

The mapping onto Rust async is clean and, in one respect, **stronger** than the
Worker:

- A `Waiter` is a closure over a `oneshot::Sender`. `wake` calls it: if
  `send()` returns `Ok`, the receiver is live — that is the accept, and only
  then does `wake` drain the buffer. If `send()` returns `Err`, the receiver was
  dropped (the client's future is gone) — that is the reject, and the item stays
  queued. So `oneshot`'s own liveness is the delivery ack; offer-then-drain is
  not bolted on, it is how the primitive already behaves.
- When a client disconnects, hyper drops the handler future, which drops the
  `oneshot::Receiver`. Unlike the Cloudflare Durable Object case (where an
  incoming request's `AbortSignal` was confirmed **not** to fire reliably across
  the DO's internal request-forwarding boundary — the documented #53 residual),
  there is no forwarding hop here: the connection and the future are on the same
  task, so a dropped connection is an observable dead waiter. A `WaiterGuard`
  drop-guard also reaps the waiter from the slot on any future-drop.

The residual that remains is the same class, but narrower: a deposit whose
`wake` `send()` succeeds in the exact instant before the receiver is dropped is
handed off and then lost (the buffer was drained on the `Ok`). This requires the
future to drop in the window after `send` returns `Ok` but before the value is
received — far narrower than the DO signal-loss gap. It is bounded, fail-closed
(a lost `to-phone` deposit denies the gated command via the daemon's own
timeout; a lost `to-daemon` reply likewise), and covered by the sender's poll
backstop and the item TTL, exactly as documented for the TS relay.

## Wire compatibility (how it was verified)

The native relay was checked against the **real client contracts**, not a
re-derived spec:

- **The Rust daemon/phone/rendezvous clients** in `crates/relay-client`
  (`http.rs`, `daemon_http.rs`, `phone_http.rs`, `rendezvous.rs`). They
  `POST {"env":...,"pushToken"?,"platform"?}` to `/mailbox/{id}/{to-phone|to-daemon}`,
  `GET` the same paths expecting `{"envelopes":[...]}`, treat any non-2xx as
  fail-closed, and cap the drain body. The native relay's routes, methods,
  status codes, and JSON bodies match these exactly.
- **The phone's TypeScript client** `apps/phone/src/transport/relay-http.ts`:
  same two endpoints, same long-poll-then-reissue loop, same `{ env }` POST body
  and `{ envelopes }` GET body.
- **The TS relay's own suites** — `relay/test/worker.test.ts`,
  `relay/bun/server.test.ts`, `relay/shared/protocol.test.ts`,
  `relay/longpoll-adversarial.test.ts`, `relay/shared/push.test.ts` — were
  ported to Rust (see "Test parity" below) and pass against the native relay.

Response bodies are emitted from typed `#[derive(Serialize)]` structs in field
declaration order (`{"ok":true,"service":"sigil-relay"}`, `{"ok":true}`,
`{"envelopes":[...]}`, `{"ok":false,"error":"..."}`), so the bytes match the TS
`RESP.*` helpers and do not get alphabetized the way a `serde_json::Value` map
would. Status codes: `200` ok, `400` bad mailbox id or a body missing `env`,
`413` oversized, `429` rate limited, `507` queue full, `404` unknown verb.

Preserved constants (identical to `relay/shared/protocol.ts` at v5.2):
`TTL_MS = 180_000`, `MAX_QUEUE = 32`, `MAX_ENVELOPE_BYTES = 16_384`,
`MAX_BODY_BYTES = 20_480`, `LONG_POLL_MS = 25_000`, `MAX_WAITERS = 8`,
`RATE_MAX = 60 / 60_000ms`, `PUSH_MAX = 5 / 60_000ms`. The APNs identity is
pinned identically: topic `works.rainn.sigil`, team `53W966FBFP`, key id
`5PCK76SDBA`, `POST https://api.push.apple.com/3/device/{token}`, headers
`apns-push-type: alert` / `apns-priority: 10`, and the byte-identical fixed
doorbell body.

## The doorbell, and the pluggable knock modes

The doorbell is a relay feature with three modes (env `KNOCK_MODE`), so a
self-hosted relay can ring official-app users without necessarily holding
Apple's key:

- **`direct`** — the relay holds the APNs auth key (`APNS_KEY_P8` /
  `APNS_KEY_P8_PATH`) and signs + sends the content-free wake itself. This is
  what the Rainnworks-hosted relay runs. Identical behaviour to the TS relay.
- **`upstream`** — the relay holds **no** Apple key. On a deposit carrying a
  push token it forwards a content-free knock `{opaque_token, mailbox_hash,
  platform}` to a configured upstream relay's `/knock` (env `KNOCK_UPSTREAM`,
  e.g. `https://relay.rainn.works`), which does the actual APNs send. This is
  how a self-hosted **message** relay keeps the background doorbell for
  official-app users without the Apple cert.
- **`off`** — no doorbell; clients fall back to the foreground poll. Still
  correct (fail-closed): the poll backstop is what correctness depends on.

If `KNOCK_MODE` is unset it is inferred: `direct` if an APNs key is configured,
else `upstream` if `KNOCK_UPSTREAM` is set, else `off`.

The relay also **exposes** a knock endpoint, `POST /knock`, which is what an
`upstream`-mode relay calls on a `direct` upstream. It accepts
`{opaque_token, mailbox_hash}` (plus an optional `platform`), and:

- is **rate-limited** on the same tight per-mailbox push budget (`PUSH_MAX`,
  5/min), keyed by `mailbox_hash`, so a leaked token cannot amplify;
- **never accepts or forwards message content** — only the opaque token and a
  wake;
- **stores nothing**, learns no identity, and reads the token once to ring, then
  forgets it.

### Trust note for the upstream knock (behaviour, not a verdict)

An upstream knock relay learns exactly two things: the **opaque APNs push
token** it is asked to ring, and that **some** mailbox (a `mailbox_hash`, itself
a hash of two pinned keys, carrying no identity) has traffic. It never sees the
envelope, the secret, the command, the account, or who anyone is; the knock body
carries no content, and the APNs push it sends is the same fixed generic
"Approval requested". This is the same relaxation already documented in
`relay/README.md` for the direct doorbell (the relay is no longer literally
"powerless" once it can ring a token), extended one hop: in `upstream` mode the
Apple key lives only on the upstream, and the message relay holds no Apple secret
at all. As with everything push-shaped, the independent security-reviewer owns
the verdict; this section documents what the code can and cannot see.

## Cloudflare Worker vs native: the tradeoff

Both are kept; neither is deleted. They differ in exactly one architectural
axis — **where the mailbox state lives** — and that drives everything else.

| | Cloudflare Worker + Durable Object (`relay/src`) | Native Rust (`crates/sigil-relay`) |
|---|---|---|
| State | One DO **per mailbox**, in that DO's isolate memory; the platform shards and reclaims them across the edge | One process, all mailboxes in one `HashMap`; sweep-reclaimed |
| Scaling | Distributed, effectively unbounded mailboxes, scale-to-zero built in | Single instance; vertical, bounded by one host's RAM (each mailbox is tiny, so this is generous) |
| Disconnect signal | `AbortSignal` **unreliable** across the DO forwarding hop (#53 residual) | Reliable: connection and future share a task; the narrower same-tick residual only |
| Ops | Cloudflare account, `wrangler deploy`, zero host | One binary; any host, container, or scale-to-zero PaaS |
| Multi-region | Native to the edge | Run N instances behind anycast/DNS, but a mailbox is **not** shared across instances — both paired parties must reach the **same** instance |
| Push key custody | Cloudflare secret | env var or 0600 file, or `upstream` mode holding no key |

The load-bearing caveat for the native relay: because a mailbox is in-process
in-memory, **both paired parties must hit the same instance** for the duration of
one exchange. That is trivial for a single self-hosted instance (the common
case), and for a horizontally-scaled deployment it means pinning a mailbox id to
an instance (consistent-hash / sticky routing on the URL's mailbox id) rather
than round-robin. The Worker/DO variant gets this for free because the DO *is*
the shard. So:

- **When the native relay supersedes the Worker:** for self-hosting, for a
  single-region managed instance where one box's RAM is plenty (millions of
  tiny ephemeral mailboxes fit in a few hundred MB), and anywhere the operator
  wants one auditable static binary over a platform runtime.
- **When the Worker stays ahead:** for the free, global, many-user default at
  `relay.rainn.works`, where per-mailbox DO sharding and edge scale-to-zero are
  exactly the right cost curve and there is no host to run. The Worker remains
  the managed default; the native binary is the self-host and single-region
  option.

## Dependencies (every one justified)

Runtime deps only (dev-deps below cost nothing at runtime):

| Crate | Why |
|-------|-----|
| `tokio` (current-thread: `rt`, `net`, `time`, `sync`, `macros`, `io-util`, `signal`) | The async runtime. Current-thread flavour is the minimal footprint; parked long-polls are its whole job. |
| `hyper` (`http1`, `server`) | HTTP/1 server. The router is hand-rolled (~1 file), no web framework, so the surface is small and auditable. |
| `hyper-util` (`tokio`) | `TokioIo`, the glue between tokio streams and hyper 1.x. |
| `http-body-util` | `collect` + a `Limited` guard to cap request-body reads. |
| `bytes` | The `Bytes` body type hyper returns/accepts. |
| `serde` + `serde_json` | Parse the deposit body's `env`/`pushToken` and emit byte-exact response JSON. Already a workspace dep. |
| `base64` | Decode the APNs `.p8` PEM; base64url the JWT parts. Already a workspace dep. |
| `p256` (`ecdsa`, `pkcs8`) | ES256 JWT signing and PKCS#8 parsing of the `.p8`. RustCrypto, pure Rust, **no OpenSSL** — keeps the static musl build clean. |
| `reqwest` (`http2`, `rustls-tls-webpki-roots`) | The only networking client. APNs **mandates HTTP/2 over TLS**, and forwarding an upstream knock is an HTTPS POST. `rustls` (not OpenSSL) keeps the static musl link clean; `webpki-roots` bundles the trust store so a `scratch` container needs no system CA. Its client is built **lazily**, so it costs nothing at idle. |

No web framework, no ORM, no logging framework, no config crate. The whole thing
is a router, a map, and a doorbell.

Dev-only (kept out of the release binary by resolver v2): `reqwest` (+`json`) and
a `tokio` multi-thread runtime for the integration tests, and `p256`'s `pem`
feature for key **export** in the JWT test (runtime `p256` stays parse+sign
only).

## Test parity with the TS suite

All ported and passing (`cargo test -p sigil-relay`: 12 unit + 18 integration +
5 push = 35 tests):

- **`protocol.rs` unit tests** ← `relay/shared/protocol.test.ts` +
  `relay/longpoll-adversarial.test.ts`: `enqueue` bounds (413/507), `drain`
  drain-on-read and expiry, the rate + push limiters, and the adversarial `wake`
  cases with hand-crafted waiters — the undetectable-orphan residual (deposit
  lost to a silently-dead newest), the offer-then-drain save (settled-dead
  newest rejects, live older gets it), the lone-settled-dead preservation, and
  newest-wins to the live reconnect. Plus a byte-exact response-body assertion.
- **`tests/integration.rs`** ← `relay/test/worker.test.ts` +
  `relay/bun/server.test.ts`: the real server on a loopback port driven over
  HTTP. Health, landing, `/version`, malformed-id `400`, deposit/drain both
  directions, long-poll resolves-on-deposit and holds-the-full-window, two
  concurrent GETs (newest gets it, other holds), disconnect-then-reconnect
  delivery, disconnected-GET-does-not-leak, independent queues, push-token
  deposit still `200`s with no key, `400`/`413`/`507`/`429` bounds, opacity
  round-trip of adversarial non-JSON bytes.
- **`tests/push.rs`** ← `relay/shared/push.test.ts`: a real ES256 JWT minted
  against a throwaway P-256 key and **verified** (pinned `alg`/`kid`/`iss`,
  signature checks out), the fixed doorbell headers + body, Apple-rejection
  swallowed, `fcm` and no-key make **zero** network calls, undefined platform
  defaults to APNs.

## Deploy

### Build (static musl binary)

The workspace release profile already produces a stripped, LTO'd, size-optimized
binary. For a fully static Linux binary (no libc dependency, runs on `scratch`):

```sh
# one-time: add the musl target (requires rustup)
rustup target add x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl

# build
cargo build --release --locked -p sigil-relay --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/sigil-relay  (single static file)
```

`--locked` builds against the committed `Cargo.lock`. The musl target enables
`crt-static` by default, so the output links no shared libc. `p256`/`rustls` are
pure-Rust + `ring` (which builds fine under musl with `musl-dev`/`build-base`),
so there is no OpenSSL to cross-compile.

> Note: this environment has Homebrew Rust (no `rustup`, no musl std), so the
> musl artifact was **not** produced here; the measured 1.7 MB / 2.4 MB numbers
> are the native `aarch64-apple-darwin` release build. A musl build is expected
> to land in the same ballpark. Run the two commands above on a rustup host (or
> use the Docker build below, which does it for you) to produce the static
> Linux binary.

### Container (`crates/sigil-relay/Dockerfile`)

A two-stage build: compile the static musl binary, then copy it into `scratch`
(nothing else in the image — no shell, no libc, no package manager). Build from
the **repo root** so the whole workspace and `relay/landing.html` are in context:

```sh
docker build -f crates/sigil-relay/Dockerfile -t sigil-relay .
docker run --rm -p 8787:8787 sigil-relay          # knock mode: off
```

Direct-mode doorbell, mounting the key read-only (never bake it into the image):

```sh
docker run --rm -p 8787:8787 \
  -v /path/to/AuthKey.p8:/run/secrets/apns.p8:ro \
  -e APNS_KEY_P8_PATH=/run/secrets/apns.p8 \
  sigil-relay
```

Upstream-knock mode (self-hosted message relay, no Apple key):

```sh
docker run --rm -p 8787:8787 \
  -e KNOCK_MODE=upstream -e KNOCK_UPSTREAM=https://relay.rainn.works \
  sigil-relay
```

Docker bind-mounts `/etc/resolv.conf` into every container, so DNS works even on
`scratch`; TLS roots are bundled via `webpki-roots`, so no CA bundle is needed.
For a non-root image instead of `scratch`, swap the final stage to
`gcr.io/distroless/static:nonroot` (still tiny, adds a non-root user and
`/etc/passwd`).

### Configuration (all env, all optional)

| Var | Meaning | Default |
|-----|---------|---------|
| `PORT` | Listen port | `8787` |
| `KNOCK_MODE` | `direct` / `upstream` / `off` | inferred (see above) |
| `KNOCK_UPSTREAM` | Upstream relay base URL for `upstream` mode | — |
| `APNS_KEY_P8` | The `.p8` PEM text directly (shows in `docker inspect`; avoid on shared hosts) | — |
| `APNS_KEY_P8_PATH` | Path to the `.p8` file (a read-only mount; preferred) | — |
| `LONG_POLL_MS` | Long-poll hold window (tests shrink it; leave unset in prod) | `25000` |

**TLS:** the relay serves plain HTTP only, deliberately, to keep it tiny and keep
certificate management out of its trust surface. Put a reverse proxy (Caddy,
nginx, Cloudflare Tunnel) in front if it is internet-reachable; never expose the
plain-HTTP port directly.

### Endpoints

`GET /` landing, `GET /health` → `{"ok":true,"service":"sigil-relay"}`,
`GET /version` → `{"version","git_commit"}` (ops convenience; the `git_commit` is
baked at build time by `build.rs`). Plus the mailbox routes and `POST /knock`
described above. Nothing is persisted or logged beyond stderr diagnostics that
carry no envelope content.

## Residuals for the security-reviewer

- **APNs JWT signing** (`push.rs`): ES256 via `p256` (RFC6979-deterministic
  `Signer`), raw 64-byte `r||s` as JWS ES256 requires, verified in
  `tests/push.rs` against a throwaway key. The key is read from env/secret,
  cached with its minted-at, never logged, never part of a mailbox's data.
  Confirm the JWT refresh window and that a poisoned cache mutex fails safe
  (it re-signs).
- **Offer-then-drain wake** (`protocol.rs::wake` + `server.rs::poll`): the
  `oneshot`-liveness-as-ack mapping and the narrower same-tick loss window
  described above. Confirm the `WaiterGuard` reaps on every disconnect and that
  no lock is held across an await.
- **Rate limiting under a hostile relay peer**: `rate_ok` (60/min) gates all
  mailbox ops and `push_ok` (5/min) gates both the deposit doorbell and the
  `/knock` endpoint, keyed per mailbox; the two directions are disjoint waiter
  lists (a flood on one slot is self-DoS, cannot evict the other party's
  delivery waiter). Confirm the `/knock` rate bucket cannot be used to amplify a
  leaked token, and that an `upstream`-mode relay forwarding to a hostile
  upstream leaks only the opaque token + mailbox hash.
- **Powerlessness preserved**: the relay still never parses an envelope, holds no
  key material beyond the APNs signing key (direct mode only), and stores
  nothing. The upstream-knock hop moves the Apple key custody, it does not widen
  what any relay can read.
