# Latch blind relay

A deliberately tiny store-and-forward mailbox for sealed envelopes. It carries
opaque bytes between a paired Mac daemon and phone when neither LAN nor an owned
endpoint is reachable (rung 3 of the transport ladder). It is built to be run by
an adversary without harming anyone: it is given no role that requires trust.

Two byte-identical implementations of one protocol:

- `src/index.ts` — Cloudflare Worker + one Durable Object per mailbox. Deploy
  with `wrangler deploy`, zero config beyond the name in `wrangler.jsonc`.
- `bun/server.ts` — a single-process Bun server speaking the same routes over the
  same http + ws. Self-host with `bun run bun/server.ts`.

Both drive every wire decision through `shared/protocol.ts`, so the routes,
status codes, JSON bodies, and WebSocket frames are identical to the byte.

## What the relay can and cannot see

| Sees | Never sees |
|------|------------|
| The **mailbox id** in the URL (proto `mailbox_id` = a hash of the two pinned keys; carries no identity) | Any plaintext: the request, the secret name, the DEK |
| **Timing** of deliveries and pulls | Names, emails, Apple identifiers, APNs device tokens |
| **Size** of each opaque blob | The pinned public keys themselves (it holds only their hash) |
| **Queue depth** per mailbox | Anything derived from ciphertext: it never parses an envelope |

Its complete possible behaviour is enumerable and every entry is neutralised in
client code: **deliver** (the happy path), **drop / delay** (a denial of service,
which fails closed for the client and forces a fallback to Touch-ID-at-the-Mac or
timeout), **duplicate** (rejected by the client's single-use request id and
monotonic counter), and **observe** sizes and timing (the residue you accept, or
remove entirely by self-hosting). It cannot read, forge, mint, or replay an
approval; the libsodium seal, pinned Ed25519 signatures, and replay guard in
`crates/proto` hold regardless of who carries the bytes. The hostile-relay suite
in `crates/proto` is the proof; this component is the honest counterpart.

The relay treats every envelope as an opaque UTF-8 string. It is never parsed,
hashed, or inspected: it flows in one channel and out the other unchanged. The
opacity tests (`test/worker.test.ts`, `bun/server.test.ts`) push adversarial
non-JSON bytes through and assert a byte-identical round trip.

## The message contract

Addressing: a **mailbox id** is the lowercase hex of the 32-byte proto
`mailbox_id(daemon_pub, phone_pub)`. Both devices derive the same id from their
pinned keys; the relay only checks it matches `^[0-9a-f]{64}$` and routes by it.

An **envelope** on the wire is the client's serialized `proto::Envelope` (the
JSON `serde_json` produces). The relay carries it as an opaque string; senders
and receivers are the only parties that (de)serialize it.

### Phone side (HTTPS)

| Route | Purpose | Response |
|-------|---------|----------|
| `GET /health` | Liveness. No mailbox needed. | `{"ok":true,"service":"latch-relay"}` |
| `GET /mailbox/{id}/pending` | Pull and drain all envelopes waiting for the phone (daemon to phone). | `{"envelopes":["<opaque>",…],"depth":0}` |
| `POST /mailbox/{id}/submit` | Submit one response envelope (phone to daemon). Body is the raw opaque envelope. | `{"ok":true,"queued":true,"attached":<bool>}` |
| `GET /mailbox/{id}/depth` | Peek both queue sizes without draining. `pending` is the "N waiting" count. | `{"pending":N,"inbound":M}` |

`pending` is drain-on-read: a delivered envelope is removed. If the phone loses
it before processing, the daemon's request simply times out and the user retries
— fail closed. `attached` tells the phone whether a daemon was connected to take
the submission live.

### Daemon side (WebSocket, outbound)

`GET /mailbox/{id}/attach` with `Upgrade: websocket`. The daemon dials out, so no
inbound port is needed on the Mac. The connection multiplexes both directions,
so every frame is a small JSON control object; the opaque envelope rides in `env`
as a string the relay never parses.

Relay to daemon:
- `{"t":"deliver","env":"<opaque envelope>"}` — a phone-to-daemon envelope to
  process. On attach, everything queued is flushed as `deliver` frames.
- `{"t":"ack","depth":N}` — the daemon's last `send` was accepted; `depth` is the
  phone queue size.
- `{"t":"err","code":413|429|507}` — the last `send` was rejected (too large /
  rate limited / queue full). A rejection, never a silent drop.

Daemon to relay:
- `{"t":"send","env":"<opaque envelope>"}` — enqueue this envelope for the phone.
- Anything unrecognised (e.g. a keepalive) is ignored.

### Limits (in `shared/protocol.ts`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `TTL_MS` | 600 000 | Envelope lifetime, matching request expiry. Expired items are never delivered. |
| `MAX_QUEUE` | 32 | Bounded FIFO per direction. Overflow is rejected (`507`), never evicts a pending item. |
| `MAX_ENVELOPE_BYTES` | 16 384 | Size cap. Larger is rejected (`413`) before the body is buffered. |
| `RATE_MAX` / `RATE_WINDOW_MS` | 120 / 60 000 | Per-mailbox fixed-window limiter. Over is `429`. |

Status codes: `400` bad mailbox id, `413` too large, `426` attach without an
upgrade, `429` rate limited, `507` queue full, `404` unknown route.

## Deploy

Cloudflare (a stranger, zero config beyond the name):

```sh
cd relay
npm install
npx wrangler deploy        # NEEDS VERIFICATION: requires a Cloudflare account
```

Self-host with Bun (no Cloudflare, no account):

```sh
cd relay
PORT=8787 bun run bun/server.ts
```

Observability is deliberately **off** in `wrangler.jsonc`: request logs would
record mailbox ids and timing, which is exactly the metadata this relay promises
not to retain. The only counter kept is a coarse per-mailbox lifetime relay
count, held in memory / DO storage and never exported.

## Testing

Run the Worker suite in workerd (via Miniflare; no account needed):

```sh
npm test            # vitest-pool-workers, test/worker.test.ts
npm run test:bun    # bun test, bun/server.test.ts
```

Covered and passing locally:

- **Queue bounds** — 32 accepted, the 33rd is `507` over http and an `err` frame
  over ws (rejected, not dropped).
- **TTL eviction** — unit-level in the pure logic; expired items never drain.
- **Rate limits** — a flood trips `429`.
- **Size cap** — an oversized submit is `413`.
- **WebSocket attach / reconnect** — items queued while the daemon is away flush
  in order on the next attach; live submissions are delivered immediately.
- **Opacity** — adversarial non-JSON bytes round-trip byte-identically, and the
  only observable outputs are the payload itself and integer counts.
- **Byte-identical protocol** — the Bun suite mirrors the Worker suite against
  the same `shared/protocol.ts` contract; both green.

**NEEDS VERIFICATION** (needs a live Cloudflare account or on-device clients):

- `wrangler deploy` against a real account, and a real daemon holding a
  hibernated WebSocket across a Durable Object eviction (the design brief's open
  question on DO hibernation limits for the long-lived daemon connection).
- End-to-end against the real daemon and phone once those land: that a
  `serde_json` `Envelope` survives the string round trip unchanged, and clock
  skew against the 600s TTL in the field.

## One divergence from the invariant wording — please confirm

Invariant #2 (and design brief §"Anonymous by construction") says the relay
"holds those two pseudonymous keys only to drop unsigned garbage" and "verifies
outer signatures ONLY as anti-abuse." This build does **not** hold the keys or
verify signatures, on purpose:

- The relay cannot verify an Ed25519 signature without the signer's public key,
  and it only ever holds the *hash* of the two keys (the mailbox id). Making it
  verify would require a key-registration step **and** parsing each envelope to
  reconstruct the signed bytes — which breaks the "stores opaque envelopes only,
  never parses" invariant and adds real attack surface.
- The signature check is explicitly non-load-bearing: its absence fails nothing,
  because every client verifies every signature itself. Per the prime directive
  ("never add a relay feature whose absence would fail open; keep it tiny"), the
  correct move is to omit it.
- Anti-abuse is instead: mailbox-id shape check, size cap, bounded queue, and
  per-mailbox rate limit — all non-load-bearing. The cost is that a mailbox is
  not cryptographically squat-proof: anyone who observes a mailbox id could post
  garbage to it, bounded by the queue cap and rate limit, and discarded by the
  client on signature failure (a bounded DoS the design already tolerates).

This is strictly *more* powerless and anonymous than the brief's wording. If that
is acceptable, the brief's "holds those two pseudonymous keys / verifies outer
signatures" line should be softened to match. If cryptographic squat-proofing is
required, it is a bounded addition (register both keys at attach, verify the
mailbox-id hash) that still need not parse ciphertext — say the word.
