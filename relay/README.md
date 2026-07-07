# Sigil blind relay

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
`crates/sigil/src/apns.rs`). The daemon carries zero Apple secret.

**v5 (this build)** replaces v4's instant-return GET with long-poll: an empty
slot holds the request open instead of returning `{"envelopes":[]}` right
away, so a caller finds out about a new deposit the moment it happens instead
of on its next poll tick. This is not a return to v3's mistake: nothing is
held for an *idle* party. A long-poll is held only by whichever side is
actively waiting on a live operation (a pending approval, a pairing in
progress), for at most `LONG_POLL_MS` (~25s). A lone poll holds the full
window and is never resolved early; the **v5.1** revision (see "Long-poll"
below) fixed a concurrent-GET rule that used to manufacture fast empties, and
records the real, bounded disconnect residual that remains only partly closed.

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
`crates/sigil-proto`, and the push body is fixed and generic (`"Approval
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
| A **live in-memory count** of messages passed since the instance woke, forgotten on restart (see "The number the landing page shows") | Which mailbox, when, or by whom any counted message moved: the count is a bare number attributed to nothing, and it is stored nowhere |

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
| `GET /health` | Liveness. No mailbox needed. | `{"ok":true,"service":"sigil-relay","count":<n>}` where `count` is the live, in-memory relayed-message count for the serving instance (see "The number the landing page shows" below). |
| `GET /` | The landing page (HTML). Templates two figures in at serve time: the deploy date and the live relayed-message `count`. | `text/html` |
| `POST /mailbox/{id}/to-phone` | Daemon deposits an envelope for the phone. | Body `{"env":"<opaque>","pushToken":"<hex>","platform":"apns"}`. `pushToken`/`platform` are optional; if `pushToken` is present the relay rings the doorbell for it and forgets it immediately. Response `{"ok":true}`. |
| `GET /mailbox/{id}/to-phone` | Phone waits for the next envelope. Long-poll, drain-on-read. | `{"envelopes":["<opaque>",...]}` — immediately if something's already queued, otherwise held until a matching deposit or ~`LONG_POLL_MS` elapses (then `[]`). |
| `POST /mailbox/{id}/to-daemon` | Phone deposits an envelope for the daemon. | Body `{"env":"<opaque>"}`. Response `{"ok":true}`. |
| `GET /mailbox/{id}/to-daemon` | Daemon waits for the next envelope. Long-poll, drain-on-read. | Same long-poll shape as `to-phone`. |

Status codes: `400` bad mailbox id or a body missing `env`, `413` envelope too
large, `429` rate limited, `507` queue full, `404` unknown route.

### Long-poll

A GET with nothing queued holds the request open (see `longPoll`/`wake` in
`shared/protocol.ts`) instead of returning empty immediately. A matching
`POST` wakes it right away; failing that, it resolves to `{"envelopes":[]}`
after `LONG_POLL_MS`. A lone poll on an empty slot **holds for the full
window** — it is never resolved early.

**v5.1 changed how a second concurrent GET on the same slot is handled.** The
previous build resolved (empty) any waiter already registered there the instant
a new GET arrived. That early-empty was the root cause of an *instant-return →
instant-refire* hammer: superseding a live waiter turned one quiet held request
into a burst of fast empties a client re-fired on at network speed, and two such
GETs could ping-pong empties off each other. A caller pinned at the rate limit
during pairing was exactly this. Now waiters **coexist**: a newcomer never
resolves an existing waiter early, each waiter holds for its full duration, and
`wake` hands a deposit to the **newest** waiter. The coexisting count is bounded
by `MAX_WAITERS` (8); only crossing that bound drops a waiter — the oldest, the
stalest and likeliest-orphaned — and only then, never in the normal case.

Delivering to the newest is what preserves the correctness the old eviction was
protecting. The gap it guarded against is real and confirmed against a real
local Workers runtime (`wrangler dev`, not just the simulated test pool): an
incoming request's `AbortSignal` does **not** reliably fire when a long-poll GET
is forwarded through a Durable Object, so a client whose connection drops
mid-poll can leave an orphaned waiter behind with nobody left to hear from it.
The only reason two GETs legitimately overlap on one slot is a single client
whose earlier poll disconnected that way and then reconnected — so the newest
waiter is the live reconnect, and handing the deposit to it (rather than to the
orphan, and without flushing the orphan empty first) delivers to the connection
that can still receive it. This closes the disconnect-then-reconnect ordering
that eviction used to close, plus the fast-empty hammer eviction itself created.

**It does not close every case.** If a deposit lands in the narrow window after
a disconnect but *before* any reconnecting long-poll re-attaches at all, that
deposit is still handed to the (already-abandoned) orphan — the only, hence
newest, waiter — and is genuinely lost for that one delivery, not merely
delayed. A second, narrower residual arrives with coexisting waiters: if a
client holds two overlapping polls and the *newer* connection dies while the
older stays live, `wake` serves the dead-newer one and that deposit is lost.
Both require a real disconnect on top of unlucky timing (see the module comment
above `longPoll` in `shared/protocol.ts` for the exact mechanism).

#### KNOWN ISSUE: Worker/DO disconnect-orphan race (bounded, fail-closed, needs real-edge verification)

- **What v5.1 closed**: the fast-empty hammer (a normal single poll now holds
  the full window; a second concurrent GET can no longer flush an existing
  waiter empty, so two GETs cannot ping-pong), and the disconnect-*then*-
  reconnect delivery (the reconnect, being the newest waiter, receives the
  deposit rather than the orphan). This is the part of #53 now addressed.
- **What remains (the residual below)**: an incoming request's `AbortSignal`
  does not reliably fire when a long-poll GET is forwarded through a Durable
  Object. A disconnect landing in the gap before *any* reconnect re-attaches
  loses that one delivery to the orphaned waiter; and, more narrowly, if a
  client holds two overlapping polls and the newer connection dies while the
  older lives, `wake` (newest-first) serves the dead one and loses the deposit.
- **Blast radius, why this is an acceptable documented interim rather than a
  blocker**: the daemon and phone each deposit/respond once per exchange,
  with no higher-level resend today, so a lost delivery here is genuinely
  lost for that message — but every path is **fail-closed**. A lost
  `to-phone` deposit means the phone never sees the approval request, the
  daemon's own round-trip times out, and the gated command is **denied**. A
  lost `to-daemon` response means the daemon times out waiting and the
  command is **denied**. Worst case is one extra user-visible retry of the
  whole operation; there is no path from this residual to a wrong approval
  or a leaked secret.
- **Scope: Worker only.** The Bun variant almost certainly does not share
  this: there is no Durable Object forwarding a request signal through an
  internal hop, so `req.signal` there is the same object the whole way from
  Bun's own HTTP server to the handler. This has not been separately proven
  the way the Worker case has, but the mechanism that causes the Worker gap
  (signal loss across a DO's internal request-forwarding boundary) simply
  does not exist in the Bun path.
- **Still open**: whether local `wrangler dev` differs from Cloudflare's real
  edge network here has not been verified — no live account was available
  from this environment. This is tasked for the actual Cloudflare deploy
  step: deploy, then drive a real disconnect (e.g. kill wifi mid-long-poll)
  and check whether the abort fires against the real edge. That either
  closes this residual entirely or confirms it holds in production too.
- **Candidate mitigation, if it reproduces on real edge**: have the daemon
  re-deposit its `to-phone` request idempotently until it sees a response
  (rather than depositing once and only waiting), since the phone's replay
  guard already dedupes a duplicate by request id — this would paper over
  exactly the gap this section describes without changing the relay itself.
  Deliberately not built speculatively against what may be a local-only
  simulation artifact; revisit only if real-edge testing confirms the gap.

### Limits (in `shared/protocol.ts`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `TTL_MS` | 120 000 (2 min) | Envelope lifetime. Short on purpose: this only has to outlive the gap to the other side's next poll or push wake-up, not a real offline window. |
| `MAX_QUEUE` | 32 | Bounded FIFO depth per direction. Overflow is rejected (`507`), never silently dropped. |
| `MAX_ENVELOPE_BYTES` | 16 384 | Size cap on `env` itself. Larger is rejected (`413`). |
| `MAX_BODY_BYTES` | `MAX_ENVELOPE_BYTES` + 4096 | Coarse pre-read guard on the whole request body (generous slack for the JSON wrapper); the authoritative per-envelope cap is `MAX_ENVELOPE_BYTES` on `env`. |
| `LONG_POLL_MS` | 25 000 | How long a GET holds an empty slot open before resolving to `[]`. See "Long-poll" above. |
| `RATE_MAX` / `RATE_WINDOW_MS` | 60 / 60 000 | Per-mailbox fixed-window limiter over ordinary deposits/drains. Held only in the mailbox's in-memory record; never persisted. Sized for long-poll: each side holds at most one outstanding GET per slot and re-issues only after it resolves, so a two-sided active exchange is a couple of requests a minute per direction, with real headroom over that. Over is `429`. |
| `PUSH_MAX` / `PUSH_WINDOW_MS` | 5 / 60 000 | A separate, tighter per-mailbox cap on push dispatches, so a leaked push token can't turn a mailbox into a doorbell-spam amplifier. **Residual**: this is per-mailbox, not per-token, so the same leaked token deposited against different mailbox ids is rate-limited independently for each; a push over this cap is silently skipped (the deposit still succeeds and 200s). |

All of it — the mailbox's two queues, its rate counters, its push counter, and
the relayed-message count the landing page shows — lives only in memory (a
Durable Object's own instance field, a Bun process `Map`, or a Worker isolate's
module scope). Nothing is ever written to `ctx.storage`, a database, or disk. If
the process restarts or a Durable Object's isolate is evicted, every mailbox it
held is simply gone, exactly the same as if a deposit had expired: the
depositing side still has its own copy and can redeposit. The relay keeps
literally nothing at rest.

### The number the landing page shows (and forgets)

The landing page shows a live count of "N messages passed since it woke", next to
a plain deploy date it reports as "up since". That count is **ephemeral and
stored nowhere**, and the page makes a joke of exactly that (a hand-drawn arrow
at the number reading "even this number isn't stored"). It is behavior worth
recording plainly:

- **Definition.** Incremented **once per successful deposit** — one bump each
  time an envelope is accepted into a mailbox queue (a `POST` `.../to-phone` or
  `.../to-daemon` that `enqueue`s successfully), in either direction. A GET
  (drain or long-poll) and a rejected deposit (bad body `400`, oversized `413`,
  full queue `507`, rate-limited `429`) are not relayed messages and do not
  count. Both variants use this one definition.
- **Where it lives: memory only.** On the Worker it is a module-scope `let` in
  the isolate that serves the request (bumped in the top-level `fetch` when the
  mailbox DO returns `200` for a deposit); there is no stats Durable Object and
  no `ctx.storage` write anywhere. On Bun it is a plain in-process variable. It
  records nothing but its own value: no mailbox id, no timestamp, no per-message
  row, nothing linkable to a user, a pairing, or a message.
- **It resets, on purpose.** When the isolate is recycled or the process
  restarts, the count is forgotten and starts again from zero. It is therefore
  not an all-time total and cannot be one, because the relay persists nothing.
  On the Worker it is also per-isolate: each isolate counts only what it
  personally passed while awake. That impermanence is the point, not a bug.

Because the count is stored nowhere, the "stores nothing at rest" promise stays
literally true, and the landing page says so plainly.

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
docker build -t sigil-relay .
docker run --rm -p 8787:8787 sigil-relay
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
  sigil-relay
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
npm run test:bun     # bun test: bun/server.test.ts, shared/push.test.ts, shared/protocol.test.ts
```

Both integration suites run against a `LONG_POLL_MS` shrunk to 150ms (a spawn
env var for Bun, a `miniflare.bindings` override in `vitest.config.ts` for the
Worker suite), so a held GET that legitimately times out still resolves in
well under a second instead of the real ~25s.

Covered and passing locally:

- **Deposit and drain**, both directions, drain-on-read, independent queues.
- **Long-poll** — a GET on an empty slot holds and resolves the moment a
  matching deposit lands, well before its timeout; with nothing deposited, it
  times out to `[]`. A lone poll is measured to **hold ~the full window**, not
  return a fast empty (both suites).
- **Concurrent GET / anti-ping-pong** (both suites) — two overlapping GETs on
  one slot both hold; the newcomer does **not** flush the first empty; a single
  deposit goes to the newest and the other keeps holding (measured to time out
  near the full window, not instantly). A **disconnect/reconnect** then lands a
  deposit on the live reconnect, never the orphan.
- **Disconnect cleanup** — an aborted GET's waiter is removed immediately
  (both suites); a later deposit against the same mailbox still lands
  normally afterward, proving the mailbox isn't corrupted by an abandoned
  long-poll.
- **Long-poll unit tests** (`shared/protocol.test.ts`, pure logic, no server):
  immediate/wake/timeout paths, `wake()` on an empty waiter list is a no-op, a
  lone poll holds (does not resolve early), a second concurrent poll does **not**
  resolve the first empty (both coexist; a deposit goes to the newest), a
  disconnect/reconnect delivers the deposit to the live reconnect not the
  orphan, and the coexisting-waiter count is bounded by `MAX_WAITERS` (past the
  cap the oldest is dropped).
- **Opacity** — adversarial non-JSON bytes round-trip byte-identically inside
  `env`.
- **Bounds** — an oversized envelope is `413`; the 33rd deposit past
  `MAX_QUEUE` is `507`; a flood trips `429`; a body missing `env` is `400`.
- **Relayed-message counter** (both suites) — it increments **exactly once per
  successful deposit** in either direction, and does **not** move for a rejected
  deposit (`400`/`507`) or a GET (drain/long-poll); `GET /` renders the copy and
  both figures with no placeholder left unfilled (the ELI5 rewrite, the "even
  this number isn't stored" gag, and the repo link included) and `GET /health`
  carries the live `count`. Ephemerality (the whole point): the Worker suite
  reaches into the mailbox `Durable Object` after a full deposit-then-drain and
  asserts its `ctx.storage` is **completely empty** (nothing persisted, no
  counter, no queue), proving an evicted isolate would lose the count; the Bun
  suite deposits a known number into a fresh process, **hard-restarts** it, and
  confirms the count is back to **zero**, because nothing was written anywhere.
- **Push fail-open** — a deposit carrying a `pushToken` still 200s with no
  `APNS_KEY_P8` configured (both the Worker suite, which has no secret bound,
  and the Bun suite, which starts with the env var cleared).
- **Push proxy itself** (`shared/push.test.ts`, Bun-only since the module has
  no Workers-specific imports): a real ES256 JWT is minted against a
  throwaway P-256 test key and verified against the pinned `kid`/`iss`/topic;
  the fixed doorbell body is identical across calls regardless of input;
  Apple rejecting a push never throws; `platform: "fcm"` and a missing key
  both make zero network calls.

Verified by hand against a real local Workers runtime (`wrangler dev`, not
just the simulated test pool), because this is exactly where the disconnect
residual above was found: a held GET, killed client-side with a real
`AbortController` over a real HTTP connection, followed by a deposit and then
a fresh reconnect, delivers correctly (confirmed woken in ~500ms, not the
full 25s) — and the same sequence with the deposit landing *before* the
reconnect reproduces the known residual (confirmed still pending after 5s of
a 25s window). Both outcomes match what the `longPoll`/`wake` newest-waiter
logic predicts; see the comment above it in `shared/protocol.ts`. (This
hand-check predates the v5.1 revision, which removed the early-empty eviction
in favour of coexisting waiters with newest-first delivery; the
disconnect-then-reconnect outcome it confirmed is unchanged, and re-running it
on a real Cloudflare deploy is still the open verification step.)

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
