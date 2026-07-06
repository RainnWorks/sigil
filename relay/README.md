# Latch / Sigil blind relay

A deliberately tiny HTTP mailbox for sealed envelopes, plus the publisher-side
APNs push doorbell. It carries opaque bytes between a paired Mac daemon and
phone when neither LAN nor an owned endpoint is reachable (rung 3 of the
transport ladder), and it rings a content-free push to wake the phone when a
request is waiting.

Two byte-identical implementations of one protocol:

- `src/index.ts` — Cloudflare Worker + one Durable Object per mailbox. Deploy
  with `wrangler deploy`, zero config beyond the name in `wrangler.jsonc` and
  the `APNS_KEY_P8` secret.
- `bun/server.ts` — a single-process Bun server speaking the same routes over
  plain HTTP. Self-host with `bun run bun/server.ts`.

Both drive every wire decision through `shared/protocol.ts`, and the push
doorbell through `shared/push.ts`, so the two are identical to the byte.

## Why the model is HTTP + ephemeral buffer (v4), not held sockets (v3)

This relay has gone through two designs in the same effort; both are worth
recording so nobody re-litigates them from scratch.

**v3 (superseded)** made the relay a stateless *live socket bridge*: the
daemon and phone each held open a WebSocket to `/attach/{mailbox_id}`, and the
relay forwarded `send` frames between whichever sockets were live. That
followed from "the daemon rings its own APNs push directly, so the relay never
needs to bridge an offline gap." It was built and tested, then dropped before
being deployed.

**v4 (this build)** reverses that, because of who runs this relay: Sigil is a
free, many-user product served by **one relay Rainnworks operates**, not a
personal instance per user. Holding a socket open per idle user is the wrong
cost curve at that scale. So the relay went back to being a plain HTTP mailbox
much like its original design, minus the parts that don't hold up: no
10-minute TTL, no held sockets, no `ctx.storage` writes. A deposit lands in a
small in-memory buffer (a Durable Object's own instance memory, or a Bun Map)
with a short TTL, and the other side picks it up on its next poll or push
wake-up.

That wake-up push is also why the relay grew a new job. A per-user daemon
push would need a per-user Apple developer certificate, which a free,
many-user product can't ask users for. So **the relay itself signs and sends
the APNs doorbell**, using one Rainnworks-held key shared by every mailbox
(`shared/push.ts`, ported from what used to be the daemon's
`crates/latch/src/apns.rs`). The daemon carries zero Apple secret.

## Trust-model note (relaxation, not a verdict)

This is a real change to what the relay is trusted with, and it is recorded
here as behavior, not signed off as reviewed: **an independent
security-reviewer owns the verdict**, not the implementer.

Invariant #3 in the project's non-negotiables says the relay is "powerless and
anonymous." As of v4 that is no longer literally true: the relay holds a
publisher APNs signing key (a real secret, shared across every mailbox) and it
briefly sees a phone's push token on any deposit that carries one, in order to
ring the doorbell. That token is read once and never stored, logged, or
persisted; the key lives only as a platform secret (`wrangler secret put
APNS_KEY_P8` / an env var or a 0600 file for Bun), never in a mailbox's data.
What is unchanged: the relay still cannot read a secret, forge an approval, or
learn an outcome — every envelope stays opaque, sealed end to end by
`crates/proto`, and the push body is fixed and generic (`"Approval
requested"`, no caller, command, account, or reason). The residual is a
real one: compromise of the relay's process (not just its traffic) now also
exposes one shared APNs signing key and momentary access to whichever push
tokens are in flight at that instant, which a purely opaque store-and-forward
relay would not have exposed. This trade only exists because the alternative
(every user supplying their own Apple developer credentials) isn't viable for
a free, many-user release.

## What the relay can and cannot see

| Sees | Never sees |
|------|------------|
| The **mailbox id** in the URL (proto `mailbox_id` = a hash of the two pinned keys; carries no identity) | Any plaintext: the request, the secret name, the DEK |
| **Timing** of deposits and drains | Names, emails, Apple identifiers |
| **Size** of each opaque blob | The pinned public keys themselves (it holds only their hash) |
| A push token, for the instant it takes to ring one doorbell, then never again | Anything derived from ciphertext: it never parses an envelope |
| The APNs signing key, as a platform secret | Any per-request detail in a push: the doorbell body is fixed and generic |

The relay treats every envelope as an opaque UTF-8 string. It is never parsed,
hashed, or inspected: it flows in one deposit and out the other unchanged. The
opacity tests (`test/worker.test.ts`, `bun/server.test.ts`) push adversarial
non-JSON bytes through and assert a byte-identical round trip.

## The message contract

Addressing: a **mailbox id** is the lowercase hex of the 32-byte proto
`mailbox_id(daemon_pub, phone_pub)`. Both devices derive the same id from their
pinned keys; the relay only checks it matches `^[0-9a-f]{64}$` and routes by
it.

An **envelope** (`env`) on the wire is the client's serialized
`proto::Envelope` (the JSON `serde_json` produces). The relay carries it as an
opaque string; senders and receivers are the only parties that (de)serialize
it. `to-daemon` carries both an `ApprovalResponse` and a `PushRegister` this
way — the relay can't tell which, and doesn't need to.

### Routes

| Route | Purpose | Body / response |
|-------|---------|------------------|
| `GET /health` | Liveness. No mailbox needed. | `{"ok":true,"service":"latch-relay"}` |
| `POST /mailbox/{id}/to-phone` | Daemon deposits an envelope for the phone. | Body `{"env":"<opaque>","pushToken":"<hex>","platform":"apns"}`. `pushToken`/`platform` are optional; if `pushToken` is present the relay rings the doorbell for it and forgets it immediately. Response `{"ok":true}`. |
| `GET /mailbox/{id}/to-phone` | Phone drains what's waiting for it. Drain-on-read. | `{"envelopes":["<opaque>",...]}` |
| `POST /mailbox/{id}/to-daemon` | Phone deposits an envelope for the daemon. | Body `{"env":"<opaque>"}`. Response `{"ok":true}`. |
| `GET /mailbox/{id}/to-daemon` | Daemon drains what's waiting for it. Drain-on-read. | `{"envelopes":["<opaque>",...]}` |

Status codes: `400` bad mailbox id or a body missing `env`, `413` envelope too
large, `429` rate limited, `507` queue full, `404` unknown route.

### Limits (in `shared/protocol.ts`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `TTL_MS` | 120 000 (2 min) | Envelope lifetime. Short on purpose: this only has to outlive the gap to the other side's next poll or push wake-up, not a real offline window. |
| `MAX_QUEUE` | 32 | Bounded FIFO depth per direction. Overflow is rejected (`507`), never silently dropped. |
| `MAX_ENVELOPE_BYTES` | 16 384 | Size cap on `env` itself. Larger is rejected (`413`). |
| `MAX_BODY_BYTES` | `MAX_ENVELOPE_BYTES` + 4096 | Coarse pre-read guard on the whole request body (generous slack for the JSON wrapper); the authoritative per-envelope cap is `MAX_ENVELOPE_BYTES` on `env`. |
| `RATE_MAX` / `RATE_WINDOW_MS` | 120 / 60 000 | Per-mailbox fixed-window limiter over ordinary deposits/drains. Held only in the mailbox's in-memory record; never persisted. Over is `429`. |
| `PUSH_MAX` / `PUSH_WINDOW_MS` | 5 / 60 000 | A separate, tighter per-mailbox cap on push dispatches, so a leaked push token can't turn a mailbox into a doorbell-spam amplifier. **Residual**: this is per-mailbox, not per-token, so the same leaked token deposited against different mailbox ids is rate-limited independently for each; a push over this cap is silently skipped (the deposit still succeeds and 200s). |

All of it — the mailbox's two queues, its rate counters, its push counter —
lives only in the mailbox's in-memory record (a Durable Object's own instance
field, or a value in the Bun process's `Map`). Nothing is ever written to
`ctx.storage`, a database, or disk. If the process restarts or a Durable
Object's isolate is evicted, every mailbox it held is simply gone, exactly the
same as if a deposit had expired: the depositing side still has its own copy
and can redeposit.

### The push doorbell (`shared/push.ts`)

A `POST .../to-phone` carrying `pushToken` triggers a best-effort, fail-open
APNs push: ES256 JWT (`kid` `5PCK76SDBA`, `iss` `53W966FBFP`), topic
`works.rainn.sigil`, POSTed to `https://api.push.apple.com/3/device/{token}`
with a fixed, generic body (`"Approval requested"`, no caller/command/secret).
The JWT is cached and refreshed roughly every 50 minutes, matching Apple's
~60-minute cap. A push failure (bad token, Apple downtime, no key configured)
is logged and swallowed; the deposit has already succeeded and 200'd, and the
phone's own poll backstop covers it. `platform: "fcm"` is a stub for later:
logged and skipped, no network call. The signing key comes from
`APNS_KEY_P8` — a Cloudflare secret (`wrangler secret put APNS_KEY_P8`, the
`.p8` PEM text) or, for Bun, the `APNS_KEY_P8` env var or a path in
`APNS_KEY_P8_PATH` (meant to be a 0600 file). Absent, the doorbell is disabled
and every deposit still succeeds.

## Deploy

Two independent ways to run this relay, kept behaviorally identical by
`shared/protocol.ts` and `shared/push.ts`: the publisher's shared Cloudflare
instance, or self-hosting it yourself with Docker (or plain Bun). Pick either;
nothing about the wire or the trust model differs between them.

### Cloudflare (the publisher's shared instance)

Full runbook, including the exact command sequence, custom-domain setup, and
how to verify a real deploy, is in **`DEPLOY.md`**. Short version:

```sh
cd relay
npm install
npx wrangler secret put APNS_KEY_P8   # paste the .p8 PEM text
npx wrangler deploy
```

### Self-host with Docker (the Bun variant)

```sh
cd relay
docker compose up --build
curl http://localhost:8787/health
```

or without compose:

```sh
cd relay
docker build -t latch-relay .
docker run --rm -p 8787:8787 latch-relay
```

**Environment variables** (all optional; the relay runs with none of them set,
just without the push doorbell):

| Variable | Meaning |
|----------|---------|
| `PORT` | Listen port. Defaults to `8787`. |
| `APNS_KEY_P8` | The APNs `.p8` PEM text directly. Simplest, but the value then shows up in `docker inspect` and the container's process environment; avoid on a shared or multi-tenant host. |
| `APNS_KEY_P8_PATH` | A path to the `.p8` file instead, meant to be a read-only mount (see below). Preferred over `APNS_KEY_P8` for anything beyond a quick local test. |

**Mounting the key.** Never bake the `.p8` into the image; it must always be
injected at container start, and it is never part of the built image's
layers. With `docker-compose.yml`, put the file next to it (keep it out of
git: it is not part of this repo) and uncomment the `APNS_KEY_P8_PATH`
environment line and the matching `volumes:` bind mount. With plain
`docker run`:

```sh
docker run --rm -p 8787:8787 \
  -v /path/to/AuthKey.p8:/run/secrets/apns_key.p8:ro \
  -e APNS_KEY_P8_PATH=/run/secrets/apns_key.p8 \
  latch-relay
```

**TLS.** The container serves plain HTTP only; it does not terminate TLS
itself, deliberately, to keep it tiny and to keep certificate management out
of the relay's trust surface. If it is reachable from the internet, put a
reverse proxy in front that terminates HTTPS, e.g. Caddy (automatic
certificates via Let's Encrypt, one line of config: `relay.example.com {
reverse_proxy localhost:8787 }`), nginx, or Cloudflare Tunnel. Never expose
port 8787 directly to the internet over plain HTTP.

Without Docker, the same image's contents run directly:

```sh
cd relay
APNS_KEY_P8_PATH=/path/to/AuthKey.p8 PORT=8787 bun run bun/server.ts
```

Observability is deliberately **off** in `wrangler.jsonc`: request logs would
record mailbox ids and timing, which is exactly the metadata this relay
promises not to retain beyond its own short-lived buffer.

## Testing

```sh
npm test            # vitest-pool-workers, test/worker.test.ts
npm run test:bun     # bun test, bun/server.test.ts + shared/push.test.ts
```

Covered and passing locally:

- **Deposit and drain**, both directions, drain-on-read, independent queues.
- **Opacity** — adversarial non-JSON bytes round-trip byte-identically inside
  `env`.
- **Bounds** — an oversized envelope is `413`; the 33rd deposit past
  `MAX_QUEUE` is `507`; a flood trips `429`; a body missing `env` is `400`.
- **Push fail-open** — a deposit carrying a `pushToken` still 200s with no
  `APNS_KEY_P8` configured (both the Worker suite, which has no secret bound,
  and the Bun suite, which starts with the env var cleared).
- **Push proxy itself** (`shared/push.test.ts`, Bun-only since the module has
  no Workers-specific imports): a real ES256 JWT is minted against a
  throwaway P-256 test key and verified against the pinned `kid`/`iss`/topic;
  the fixed doorbell body is identical across calls regardless of input;
  Apple rejecting a push never throws; `platform: "fcm"` and a missing key
  both make zero network calls.

**NEEDS VERIFICATION** (needs a live Cloudflare account, a real APNs key,
on-device clients, or a working local Docker engine):

- `wrangler deploy` against a real account with a real `APNS_KEY_P8` secret,
  and a real push landing on a real device. See `DEPLOY.md`.
- End-to-end against the real daemon and phone once those land on this wire:
  that a `serde_json` `Envelope` survives the string round trip unchanged,
  that `PushRegister` correctly lands the daemon's copy of the phone's token,
  and that the phone's poll backstop covers a push that never arrives.
- `docker build` / `docker compose up` actually producing a working
  container: the Dockerfile and compose file were written and reviewed by
  hand, and the server code they wrap is the same code the Bun test suite
  above already exercises directly, but the container build itself was not
  run in this environment (the local Docker engine was unresponsive; see the
  session notes). Run `docker compose up --build` and `curl
  http://localhost:8787/health` once Docker is available to close this out.

## One divergence from the invariant wording — please confirm

Invariant #2 (and design brief §"Anonymous by construction") says the relay
"holds those two pseudonymous keys only to drop unsigned garbage" and
"verifies outer signatures ONLY as anti-abuse." This build does **not** hold
the keys or verify signatures, on purpose:

- The relay cannot verify an Ed25519 signature without the signer's public
  key, and it only ever holds the *hash* of the two keys (the mailbox id).
  Making it verify would require a key-registration step **and** parsing each
  envelope to reconstruct the signed bytes — which breaks the "carries opaque
  envelopes only, never parses" invariant and adds real attack surface.
- The signature check is explicitly non-load-bearing: its absence fails
  nothing, because every client verifies every signature itself. Per the
  prime directive ("never add a relay feature whose absence would fail open;
  keep it tiny"), the correct move is to omit it.
- Anti-abuse is instead: mailbox-id shape check, size cap, per-mailbox rate
  limit, bounded queue, and the separate push cap — all non-load-bearing. The
  cost is that a mailbox is not cryptographically squat-proof: anyone who
  observes a mailbox id could deposit garbage into it, bounded by the queue
  cap and rate limit, and discarded by the client on signature failure (a
  bounded DoS the design already tolerates).

This is strictly *more* powerless and anonymous than the brief's wording on
this one point (independent of the APNs trust relaxation noted above, which
cuts the other way and is the brief owner's to reconcile). If the
signature-verification omission is acceptable, the brief's "holds those two
pseudonymous keys / verifies outer signatures" line should be softened to
match. If cryptographic squat-proofing is required, it is a bounded addition
(register both keys at first deposit, verify the mailbox-id hash) that still
need not parse ciphertext — say the word.
