# Direct transport: ladder rungs 1 (LAN/Bonjour) and 2 (owned endpoint / DDNS)

Status: partial implementation + design (2026-07-07, task #51). Implementer
notes and residuals for an independent security review; the review verdict lives
in `docs/security-claims.md`, written by the reviewer, not here.

Today every daemon<->phone approval rides the blind relay (rung 3). When the two
can reach each other directly -- same LAN via Bonjour/mDNS (rung 1), or a
user-owned endpoint / dynamic-DNS host (rung 2) -- we want to carry the **same**
sealed envelopes over a direct connection and skip the relay, keeping the relay
as the always-available fallback. This document records what landed, the
security argument for it, and the design for the parts deliberately deferred.

## The one rule everything else follows

**A direct transport is a pipe, never a trust boundary.** The security layer is,
and remains, the envelope: crypto_box-sealed to the pinned recipient,
Ed25519-signed by the pinned sender, single-use uuidv7 request id, per-pairing
monotonic counter, 150s timestamp window (`sigil_proto`). A direct transport
changes only *which bytes carry the envelope*; it introduces no plaintext and no
new trust in the network.

Consequences that the whole design leans on:

- The envelope layer already authenticates the peer. A rogue host on the LAN can
  open a TCP connection and inject frames, but every frame is still gated by
  `Envelope::open` against the pinned peer key with the shared replay guard, at
  the exact same `RemoteApprover`/phone call site that gates a relay-delivered
  envelope. An imposter cannot produce an envelope that opens, so over a direct
  link it can at worst send bytes that get dropped. It cannot forge a request,
  forge or replay a response, or read anything.
- The mDNS record is therefore **untrusted input**. Discovery may only decide
  *which address to dial*; *who is on the other end* is decided by the envelope,
  never by the advertisement.
- The relay's powerless/anonymous property is untouched. This work is about
  **not using** the relay when a direct path exists, never about weakening it.

## What landed (tested, in `crates/sigil-direct`)

A new, isolated crate behind the existing `sigil_proto::Transport` trait, with
zero changes to the reviewed daemon owner loop, approval concurrency core, relay
client, or envelope crypto. It is not yet wired into the daemon or the phone app
(see "Deferred", below), so the shipping approval path is byte-for-byte
unchanged.

- **`DirectLink`** -- a `Transport` over one duplex TCP connection. Framing is
  `[dir: u8][len: u32 big-endian][payload]`, where `payload` is the *exact*
  opaque envelope wire the relay carries (`serde_json` of `Envelope`), so the
  daemon's approver and the phone are byte-indifferent to which rung answered. A
  background reader thread demuxes frames into per-`Direction` FIFOs and parks
  `recv` on a condvar, exactly like `LocalRelay`. Hardening:
  - A frame payload is capped at `MAX_FRAME_BYTES` (64 KiB, generous over the
    relay's 16 KiB envelope cap); an over-cap declared length closes the link
    rather than allocating. This denies a hostile peer an unbounded-allocation
    lever, the same discipline as the relay client's drain cap.
  - Fail-closed: a dropped connection, truncated frame, unknown direction byte,
    or over-cap length latches the link closed, and every subsequent `recv`/
    `send` returns `TransportError` so the selector reverts to the relay. Close
    forces `shutdown(Both)` so the peer also observes EOF and both ends fail over
    together (a `try_clone`'d read half would otherwise keep the fd open).
  - A frame that is valid-length but not a decodable envelope is dropped without
    tearing the link (framing stays synchronised), matching the relay client's
    tolerance.
- **`DirectListener`** -- the rung-2 daemon side: bind an owned `host:port`,
  `accept()` the phone's dial, hand back an **unverified** `DirectLink`.
- **`FallbackTransport`** -- the selector, and where downgrade-safety is
  enforced. It wraps the always-present relay `Transport` and an *optional*
  verified direct primary:
  - **No primary installed == the relay, byte-identical.** The default, and the
    state after any direct failure. This is the guarantee that "the relay path
    stays byte-identical when direct is off/unavailable."
  - **Prefer-direct deposit** (`DepositPolicy::PreferDirect`, default): a request
    goes out the direct primary only, actually skipping the relay; on a direct
    error the primary is retired and the deposit completes on the relay.
  - **Mirror deposit** (`DepositPolicy::Mirror`): also deposit to the relay, so a
    black-holed direct link cannot even delay the request; the redundant copy
    expires unread if the phone answers direct. Offered for the conservative
    posture; it does not skip the relay.
  - `recv`: when a primary is present, park on it; on a mid-flight link failure,
    retire it and spend the remaining budget on the relay so an in-flight
    approval completes rather than being lost with the connection.
  - Primary install/retire is pointer-checked (`Arc::ptr_eq`) so a stale
    failure never clobbers a freshly installed link.
- **`discovery`** -- the rung-1 seam and the promotion gate:
  - `ServiceRecord { host, port, hint }` and `SERVICE_TYPE = "_sigil._tcp"`. The
    `hint` is a **non-secret** discriminator the phone recomputes to pick the
    right host among several on the LAN; it grants nothing and is never trusted.
    It is deliberately NOT the mailbox id (broadcasting that would advertise the
    pairing's routing address on the LAN).
  - `Discovery` trait (`advertise`/`browse`) + an in-memory test double. The
    concrete Bonjour backend is deferred (below).
  - **`verify_link`** -- the promotion gate. It reads exactly one envelope off a
    freshly dialled/accepted link and hands it to a caller-supplied predicate
    wired to the SAME `Envelope::open` (pinned peer key + daemon agreement key +
    replay guard) the relay path uses. A host that dialled in but does not hold
    the phone's key cannot produce an envelope that opens, so it fails here and
    is never installed as a primary. Fail-closed on timeout or link error.

The crate has 18 Rust unit tests (loopback TCP round-trips, direction
independence, close/EOF detection, buffered-frame-survives-close, selector
prefer/fallback/retire, and the verify-link accept/reject/timeout gate).

Phone side (`apps/phone/src/transport`), tested and typecheck-clean:

- **`LadderTransport`** -- the phone-side mirror of `FallbackTransport`: composes
  the relay `PhoneRelay` with an optional direct rung, prefers direct when
  connected, falls back on a throwing direct `send`, fans inbound requests in
  from BOTH rungs (the controller's replay guard dedupes a request that arrives
  on both), and is relay-identical when no direct rung is set. It works against
  any `Transport` and is exercised with in-memory doubles
  (`ladder-transport.selftest.ts`, 10 checks). The concrete native-TCP direct
  rung it plugs into is deferred (below).

## Downgrade-safety argument

The threat: an attacker on the LAN must not be able to **force, delay, or
silently break** approvals by spoofing or withholding discovery, and must never
be able to forge or read one.

1. **Cannot forge / read.** Unconditional: every rung carries the same sealed,
   signed envelope, opened against pinned keys with a replay guard. No transport
   is trusted. A rogue LAN responder's frames fail `open` and are dropped.

2. **Cannot silently break the relay path.** When no verified primary is
   installed -- the default, and the state after any failure -- `FallbackTransport`
   is the relay, unchanged. Spoofing or withholding an mDNS record cannot touch a
   daemon that is not even running discovery, and cannot alter the relay bytes of
   one that is.

3. **Cannot get promoted by pretending to be the phone.** A primary is only ever
   installed after `verify_link` reads an envelope that opens as the pinned peer.
   A host that merely completes a TCP handshake, or advertises a matching mDNS
   record, cannot pass this gate.

4. **The residual: an active MITM one-timeout denial.** The one thing an *active*
   LAN man-in-the-middle can still do is relay the phone's genuine verification
   envelope verbatim (it is opaque bytes it cannot decrypt but can forward), pass
   the promotion gate, then black-hole subsequent traffic. Under
   `PreferDirect`, the daemon would then deposit a request into the MITM, the
   phone would never see it, and the approval would **time out and fail closed**.
   This is a denial, never a forged approval or a leaked secret. It is fully
   closed by two independent mitigations, either sufficient:
   - **`Mirror` deposit** removes the delay entirely (the relay always carries
     the request), at the cost of still using the relay.
   - **Demote-on-silence** (design, not yet built; see below): a direct
     round-trip that returns no response within a short bound retires the primary
     and retries the request over the relay, so the damage is one short retry,
     not a full timeout, and repeated MITM attempts keep falling back to the
     relay (which the LAN attacker cannot block).
   Because demote-on-silence lives in the reviewed approval loop, the crate ships
   with direct transport **OFF by default**, and enabling it is a security-review
   decision.

## The relay <-> direct handoff (protocol invariant)

To keep `recv` coherent without racing two channels (which would risk
double-draining the relay), the daemon and phone follow one rule:

> **Answer on the rung the request arrived on; a rung failure is a connection
> drop that fails both parties over to the relay together.**

- The daemon deposits a request over the active rung and reads the response on
  the same rung's `recv`. A live direct link is authoritative while up; its drop
  is detected (EOF -> `TransportError`) and both `recv` and the next deposit fall
  to the relay.
- The phone, symmetrically, answers over the rung the request came in on
  (`LadderTransport.send` prefers the connected direct rung, falls back to the
  relay on failure).
- Because a direct link is a single duplex TCP connection, "the rung failed" is
  atomic for both ends: the same dropped connection surfaces as EOF on each side,
  so they revert to the relay in step rather than one waiting on a channel the
  other abandoned.

## Reconnection

A dropped direct link is not fatal: `FallbackTransport` retires the primary and
the daemon serves from the relay immediately. Re-establishing direct is a
background concern (a discovery re-browse on the phone, a re-accept on the
daemon's listener) that never blocks an approval, because the relay is always
available underneath. Backoff on reconnect attempts is the phone/daemon
integration's job; the crate imposes none.

## Deferred, with the design to implement it

These are deferred because they need either live networking / a native module
that cannot be exercised in the current environment, or a change inside the
reviewed daemon owner loop that must not be half-built.

### Daemon integration (acceptor + owner-loop handoff)

The clean seam exists: build the daemon's approver on a `FallbackTransport`
instead of a bare `DaemonRelay` (both are `Arc<dyn Transport>`; the owner loop is
unchanged). The care is in **promotion**, which needs the daemon's private
agreement key and the shared replay guard -- both owned by `RemoteApprover`, whose
owner loop is the *sole* reader of the `ToDaemon` channel. A naive acceptor that
reads one envelope to verify would become a second reader of that channel,
violating the single-reader invariant and desynchronising the replay counter.

Plan: give `RemoteApprover` a small, additive `verify_and_promote(link)` entry
that (a) performs the `verify_link` read using the approver's own key + guard, so
there is still exactly one guard and one reader, and (b) on success both installs
the link as the `FallbackTransport` primary and dispatches that first envelope
through the normal `dispatch` path (it is a real `PushRegister`/response). The
acceptor thread (rung 2: `DirectListener::bind(endpoint)`; rung 1: dial a
verified discovery hit) only hands raw links to that entry; it never reads the
channel itself. Demote-on-silence is a bounded retry added to `round_trip`:
after a direct deposit, if no response arrives within a short fraction of the
timeout, retire the primary and re-deposit over the relay once. This is the piece
that turns the residual in section 4 into a short retry; it touches the reviewed
loop and so is left for a reviewed change rather than bundled here.

Config (additive, default-off) to add when this lands: `direct_endpoint:
Option<String>` (rung 2 `host:port` the daemon binds) and `direct_lan: bool`
(rung 1 advertise/discover toggle) on `Settings` and `RemotePairingConfig`, both
defaulting to off so existing configs and the default relay path are unchanged.

### Rung 1 concrete mDNS/Bonjour backend

A thin adapter implementing `discovery::Discovery` over `mdns-sd` (pure-Rust, no
Avahi/Bonjour daemon dependency), advertising `_sigil._tcp` with the daemon's
`DirectListener` port and a `hint` TXT record. The hint is a salted, truncated
hash of the daemon's public identity (e.g. first 8 bytes of
`BLAKE2b(domain-sep || daemon_pub)`), which the phone -- which pins that key --
recomputes to filter candidates before dialling. Deferred because it cannot be
exercised without a live multicast network; it is a small, well-understood
adapter over the landed, tested seam, and it produces only *hints* (a wrong hint
merely fails `verify_link` and falls back to the relay), so its blast radius is
bounded by the verification gate.

### Rung 2 DDNS / owned endpoint

Rung 2 is `DirectListener::bind` on a configured port plus the user's own DDNS
name / static IP / forwarded port; the phone dials `ServiceRecord`-shaped
`host:port` and runs the same `verify_link`. The only additional piece is an
optional DDNS updater (out of scope here; the user may run any existing DDNS
client). Unauthenticated bytes hitting the port drop at `verify_link`, so an
exposed port is not a new trust surface, only a new (envelope-gated) attack
surface the reviewer should weigh; hence default-off.

### Phone native TCP direct rung

`LadderTransport` already composes any `Transport`; the missing piece is a
concrete phone `Transport` speaking the `DirectLink` framing over a raw TCP
socket. React Native has no built-in TCP, so this needs a native socket module
(e.g. a small Expo native module or `react-native-tcp-socket`). Deferred because
it cannot be built/tested in this environment; the selector it plugs into is
landed and tested.

## Residuals for the security reviewer

- **Active LAN MITM one-timeout denial** under `PreferDirect` without
  demote-on-silence (section 4). Denial only, fail-closed; closed by `Mirror` or
  by the deferred demote-on-silence. Direct transport ships OFF by default for
  exactly this reason.
- **Rung-2 inbound port** is a new (envelope-gated) attack surface. Every byte is
  dropped unless it is an envelope that opens as the pinned peer, but a reviewer
  should confirm the daemon-at-rest inertness and fail-closed posture hold with a
  bound listener before rung 2 is enabled.
- **`verify_link` uses the caller's predicate.** The gate's soundness depends on
  the daemon wiring the predicate to the real `Envelope::open` with the shared
  guard (not a throwaway guard). The deferred `verify_and_promote` entry is where
  that wiring must be reviewed; the crate cannot enforce it because it holds no
  identity types by design.
- **Metadata.** A direct link reveals to a LAN observer that two hosts talk, and
  the mDNS advertisement reveals a Sigil daemon is present (via `_sigil._tcp` +
  a non-identifying hint). No pairing routing address or key is exposed. This is
  strictly less metadata than the relay sees for the same exchange.
- **No new envelope/message types** were introduced, so the hostile-relay suite's
  coverage is unchanged; the direct pipe carries the identical wire and is
  subject to the identical open/verify/replay checks.
