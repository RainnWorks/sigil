# Direct transport: ladder rungs 1 (LAN/Bonjour) and 2 (owned endpoint / DDNS)

Status: DEFERRED CORE landed + remaining design (2026-07-09, task #51).
Implementer notes and residuals for an independent security review; the review
verdict lives in `docs/security-claims.md`, written by the reviewer, not here.

What changed on 2026-07-09 (this pass): the daemon-side deferred pieces landed,
integrated with the reviewed #36 multi-device owner model, still OFF by default:

- `RemoteApprover::verify_and_promote(link)` -- the per-device promotion gate.
- Demote-on-silence in the approval wait (`deposit_and_wait` and its ring-all
  cancellable twin), turning the section-4 MITM residual into a short relay retry.
- `RemoteApprover::run_direct_acceptor(listener, shutdown)` -- the rung-2 acceptor
  loop, plus `DirectListener::set_nonblocking` / `accept_nonblocking`.
- Daemon wiring: a per-device `direct_endpoint` (`RemotePairingConfig` +
  `pairing.json`), the `FallbackTransport` build in `build_gate`, and one acceptor
  thread per direct-enabled device in `serve`. All additive and default-off.
- `remote::direct_service_hint(daemon_pub)` -- the non-secret mDNS hint helper.

Still deferred (needs live networking / a native module that cannot be exercised
here): the concrete `mdns-sd` Bonjour backend and the phone native-TCP rung. See
"Deferred" below; the design is unchanged and now sits behind a landed, tested
daemon seam.

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
   Demote-on-silence is now **built** (2026-07-09), in the reviewed approval loop:
   see "Daemon integration (landed)" below. Direct transport still ships **OFF by
   default** (`direct_endpoint` unset on every device), so enabling it remains a
   security-review decision.

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

## Daemon integration (landed)

The clean seam that was designed here is now built, integrated with the reviewed
#36 multi-device owner model, and OFF by default. The care was all in
**promotion**, which needs the daemon's private agreement key and the shared
replay guard -- both owned by `RemoteApprover`, whose owner loop is the *sole*
reader of that device's `ToDaemon` channel. A naive acceptor that read one
envelope to verify would become a second reader of that channel, violating the
single-reader invariant and desynchronising the replay counter.

How it preserves the per-device owner model:

- **`RemoteApprover::verify_and_promote(link)`** reads exactly one envelope off the
  **raw** `link` (never the owner's transport), through the approver's OWN pinned
  key + agreement key + the SAME shared `ReplayGuard` (via `classify`). So there
  is still exactly one guard, honoring the phone's single monotonic outbound
  counter across BOTH the relay and the link. On success it installs the link as
  the `FallbackTransport` primary FIRST (so the owner's next `recv` reads the
  link), THEN routes that one verifying envelope via a new `route` helper WITHOUT
  a second open (a second open would be correctly rejected as a counter replay).
  The verify read is a one-shot handoff sequenced strictly before install, so the
  owner never races it: before install the owner reads the relay; after install
  the owner is the sole reader of the link. Fail-closed on `NotPinnedPeer`,
  timeout, or link error -- a rogue LAN dialer is dropped, never installed.
- **The acceptor never reads the channel.** `run_direct_acceptor` only polls the
  rung-2 `DirectListener` (`accept_nonblocking`, honoring the shutdown flag) and
  hands each raw link to `verify_and_promote`. It is a no-op when direct is
  disabled, so it is safe to spawn per device.
- **Per-device isolation is untouched.** Each device's approver has its own
  `direct` selector, its own `ReplayGuard`, its own pinned phone, its own owner
  loop, and (if enabled) its own bound listener + acceptor thread. Nothing is
  shared across devices; a `RingApprover` still composes N unchanged approvers.
- **Demote-on-silence** is a bounded retry in `deposit_and_wait` (and its
  ring-all cancellable twin `deposit_and_wait_cancellable`): after a deposit that
  actually went out a live direct primary, if no response arrives within a short
  window (`DIRECT_DEMOTE_AFTER`, 8s), `demote_and_redeposit` retires the primary
  (`clear_primary`, so the owner reverts to the relay on its next poll) and
  re-seals the request under a FRESH counter and re-deposits over the relay
  (which a LAN attacker cannot block). The re-seal is what lets the phone's replay
  guard accept the relay copy even if it already saw the black-holed direct copy.
  The remaining timeout budget is then spent waiting for the relay-delivered
  response, so the section-4 MITM residual becomes a short retry that COMPLETES
  over the relay, not a full-timeout denial. **Byte-identical when direct is off:**
  `deposit_and_wait` takes the reviewed single `recv_timeout(self.timeout)` path
  whenever no direct primary is carrying the request (`self.direct` is `None`, or
  enabled-but-relay-serving), and the ring loop's demote branch is gated on the
  same, so N==1 and N>=2 relay-only behavior is unchanged.

**N==1 revert timing.** After `clear_primary`, an owner already parked in the old
primary's `recv` reverts to the relay only on its next poll (bounded by the direct
link's poll return, or immediately if the link dropped). With the 8s demote window
and the 120s approval timeout this is comfortably fail-closed and still completes
via the relay; a crisper revert (closing the demoted link to unblock the owner at
once) is a possible future refinement, not required for correctness.

Config (additive, default-off), landed: `direct_endpoint: Option<String>` (the
rung-2 `host:port` the daemon binds) on `RemotePairingConfig` and the
`pairing.json` device row (`#[serde(default, skip_serializing_if)]`, so existing
pairings round-trip unchanged and load with direct OFF). A future `direct_lan:
bool` toggle gates rung-1 advertise/discover once the Bonjour backend lands; the
acceptor/promotion machinery it will feed is already in place. No `NewPairing` /
`save` / `add_device` signature changed: a user opts a device in by setting
`direct_endpoint` (hand-edit today, a config verb later), keeping the pairing flow
untouched.

Tested (all headless, over loopback TCP + in-memory relay): promotion for the
pinned peer, rejection of an imposter opener, no-op when direct is disabled, a
full approval riding a promoted direct link (relay depth stays 0), demote-on-
silence completing over the relay against a black-holed primary, and the acceptor
loop promoting a dialled phone end to end. See `crates/sigil/src/remote.rs` tests.

## Deferred, with the design to implement it

These remain deferred because they need live networking / a native module that
cannot be exercised in the current environment. Each now sits behind the landed,
tested daemon seam above, so a wrong or hostile input from either is bounded by
`verify_and_promote` (drop + relay fallback), not by trusting the network.

### Rung 2 status

Rung 2 (owned-endpoint / DDNS) is **landed**: `DirectListener::bind(direct_endpoint)`
+ `run_direct_acceptor` + `verify_and_promote`. The only out-of-scope piece is an
optional DDNS updater (the user may run any existing DDNS client). Unauthenticated
bytes hitting the bound port drop at `verify_link`; see the residuals.

### Rung 1 concrete mDNS/Bonjour backend

A thin adapter implementing `discovery::Discovery` over `mdns-sd` (pure-Rust, no
Avahi/Bonjour daemon dependency), advertising `_sigil._tcp` with the daemon's
`DirectListener` port and a `hint` TXT record.

The hint is **already landed** as `remote::direct_service_hint(daemon_pub)`:
`hex(BLAKE2b-64("sigil.direct.hint.v1" || verifying || agreement))`, a salted,
truncated hash of the daemon's PUBLIC identity, which the phone -- which pins that
key -- recomputes to filter candidates before dialling. It lives in `sigil` (not
`sigil-direct`) because the discovery crate holds no identity/crypto types by
design; the daemon computes the hint and hands it to a `ServiceRecord`. It is not
the mailbox id (broadcasting that would advertise the pairing's routing address).

The `mdns-sd` **crate dependency is deliberately not added**: this environment is
offline and `mdns-sd` is not in the cargo cache, so adding it (even as an optional
dep) would break `cargo test --workspace` at dependency resolution. When wired on
a networked machine, add `mdns-sd` to `sigil-direct` behind an off-by-default
`mdns` feature and implement `Discovery::advertise` (register a `ServiceInfo` with
the port + hint TXT) and `browse` (a bounded `ServiceDaemon` browse draining the
receiver into `ServiceRecord`s). It cannot be exercised without a live multicast
network, and it produces only *hints* (a wrong hint merely fails `verify_link` and
falls back to the relay), so its blast radius is bounded by the verification gate.
The daemon side that consumes a discovered/verified rung-1 record reuses the same
`verify_and_promote` the rung-2 acceptor uses (dial the record's `endpoint()`,
`verify_link`, promote), so no new trust path is introduced.

### Phone native TCP direct rung

`LadderTransport` already composes any `Transport`; the missing piece is a
concrete phone `Transport` speaking the `DirectLink` framing over a raw TCP
socket. React Native has no built-in TCP, so this needs a native socket module
(e.g. a small Expo native module or `react-native-tcp-socket`). Deferred because
it cannot be built/tested in this environment; the selector it plugs into is
landed and tested.

## Residuals for the security reviewer

- **Active LAN MITM residual, now a short retry (section 4).** With
  demote-on-silence built, a promoted-then-black-holed direct link no longer
  causes a full-timeout denial: after `DIRECT_DEMOTE_AFTER` (8s) the primary is
  retired and the request is re-deposited over the relay, which the LAN attacker
  cannot block, and the approval completes there. The reviewer should confirm the
  demote path (`demote_and_redeposit`: `clear_primary` + fresh-counter re-seal +
  relay deposit; owner reverts on its next poll) and the "byte-identical when
  direct is off" claim in `deposit_and_wait` / `deposit_and_wait_cancellable`.
  Direct still ships OFF by default (`direct_endpoint` unset).
- **Rung-2 inbound port** is a new (envelope-gated) attack surface, now bindable
  when `direct_endpoint` is set. Every byte is dropped unless it is an envelope
  that opens as the pinned peer (`verify_and_promote` -> `verify_link` -> the real
  `classify`/`Envelope::open`); an unverified dialer gets a link that is read once
  and dropped, never installed. The reviewer should confirm daemon-at-rest
  inertness and the fail-closed posture with a bound listener before enabling it.
- **`verify_and_promote` wires the real open.** The `verify_link` predicate is
  wired to the approver's own `classify` (pinned peer key + daemon agreement key +
  the SHARED `ReplayGuard`), not a throwaway guard, and the opener is routed
  without a second open. This is the wiring the earlier draft flagged as needing
  review; it is in `crates/sigil/src/remote.rs::verify_and_promote`. The
  single-reader invariant is preserved because the verify read is on the raw link
  and sequenced strictly before the primary is installed (after which the owner is
  the sole reader). Confirm no second reader of any device's `ToDaemon` channel and
  no guard sharing across devices.
- **Metadata.** A direct link reveals to a LAN observer that two hosts talk, and
  the mDNS advertisement reveals a Sigil daemon is present (via `_sigil._tcp` +
  a non-identifying hint). No pairing routing address or key is exposed. This is
  strictly less metadata than the relay sees for the same exchange.
- **No new envelope/message types** were introduced, so the hostile-relay suite's
  coverage is unchanged; the direct pipe carries the identical wire and is
  subject to the identical open/verify/replay checks.
