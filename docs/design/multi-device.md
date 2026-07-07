# Multi-device pairing (#36)

Ring-all deposit, first-wins resolution, and a zero-knowledge resolution
broadcast, across N paired phones. Each device has its own identity, its own
key-hash mailbox, and its own threshold share; the relay stays powerless and
anonymous (a per-device key-hash mailbox is just another opaque mailbox).

This document is the implementer's record for #36: what landed in this change,
the precise design for the parts deliberately deferred, and the residuals an
independent security-reviewer should attack. It is written by the implementer;
per the review-integrity rule it contains behavior + design + residuals only,
never a "reviewed and found sound" verdict. The adversarial verdict is the
security-reviewer's to write in `docs/security-claims.md`.

## Why this was split

The single-device approval core in `crates/sigil/src/remote.rs` (the one
ToDaemon owner, register-before-deposit, the single shared `ReplayGuard`,
fail-closed-to-deny on timeout/owner-death) was JUST independently
security-reviewed and found correct. Extending it to N devices must preserve
every one of those guarantees. Rather than rewrite the reviewed concurrency core
in one pass, this change lands the additive, independently-testable half of the
feature and specifies the risky core precisely for a follow-up that gets its own
adversarial pass.

## What landed in this change (tested)

1. **Proto wire contract** (`crates/sigil-proto/src/request.rs`):
   - `ResolutionStatus { Settled, Expired, Withdrawn }` (serde snake_case).
   - `ResolutionBroadcast { request_id, status }`, tagged `type: "resolution"`,
     the daemon->phone sibling of `DeliveryReceipt`. Metadata only: it releases
     nothing and gates nothing. It carries neither which device resolved the
     request nor whether the resolution was an approve or a deny (zero-knowledge).
   - `ToPhoneMessage { Request(Box<ApprovalRequest>), Resolution(ResolutionBroadcast) }`
     with `from_value`, mirroring `ToDaemonMessage` on the return path: a `type`
     peek selects the tagged resolution; its absence is a (legacy, untagged)
     `ApprovalRequest`, so `ApprovalRequest`'s wire shape stays byte-identical and
     the pinned vectors / pairing transcript do not shift.
   - Unit tests for the wire contract and fail-closed classification, plus a
     hostile-relay proof
     (`crates/sigil-proto/tests/hostile_relay.rs::resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope`):
     a resolution is confidential to the relay, its signature covers every field
     (no forged dismissal), and it is single-use (no replayed dismissal). Even a
     (cryptographically impossible) forged-but-valid dismissal only ever *hides a
     prompt*, which withholds a release; it can never cause one.

2. **Daemon broadcast half** (`crates/sigil/src/remote.rs`):
   - `RemoteApprover::broadcast_resolution(request_id, status)` seals a
     `ResolutionBroadcast` to THIS device's pinned phone and deposits it ToPhone,
     forwarding the push hint so the device wakes to dismiss promptly. It shares
     the existing daemon->phone monotonic `counter` and seal path, registers no
     waiter, and touches no `ReplayGuard`, DEK, or `Z_F`. Best-effort: a seal or
     transport error is swallowed, because the phone's own request timeout still
     expires the sheet, so a lost broadcast degrades to today's single-device
     behavior, never to a release.
   - Test:
     `broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open`
     drives a software phone that opens, classifies, and replay-rejects it.
   - This method is additive; it does not alter the reviewed wait / first-wins /
     guard / owner-loop logic in any way.

3. **Phone dismissal** (`apps/phone`):
   - `ResolutionBroadcastMessage`, `ResolutionStatus`, `ToPhoneMessage`, and a
     pure `classifyToPhone(payload)` in `src/protocol/requests.ts`, mirroring the
     Rust classifier and failing closed on a malformed resolution.
   - `SigilSession.handleInbound` (`src/session/session.ts`) now opens each
     inbound envelope once to a raw payload (crypto verified regardless of shape),
     then demuxes: a resolution calls `store.dismissResolved`; a request keeps the
     existing `store.receive` + delivery-receipt path unchanged. A resolution is
     never acknowledged with a delivery receipt.
   - `Store.dismissResolved(requestId, status)` (`src/state/store.ts`) wires into
     the phone's existing terminal states: `expired` -> the expired path; `settled`
     / `withdrawn` -> transition to the already-modelled `superseded` state, record
     a neutral history entry, and drop it from the active queue. Zero-knowledge:
     the recorded outcome is deliberately neutral (`superseded`), never
     approved/denied, because the phone never learns which device resolved it or
     how. A no-op for an unknown or already-terminal request, so a duplicate, late,
     or never-seen broadcast changes nothing.
   - `HistoryEntry.decision` widened to include `"superseded"`; the history/home
     UI already renders any non-approved/denied outcome with the neutral glyph.

The result is the complete resolution-broadcast wire, end to end, minus the ring
coordinator that decides WHEN to call `broadcast_resolution`. That coordinator,
and the multi-pairing storage that feeds it, are specified below and deferred.

## Deferred, with design: the daemon ring-all / first-wins core

### Composition, not rewrite

The safe way to reach N devices while provably preserving the reviewed
single-device guarantees is **composition**: keep `RemoteApprover` exactly as
reviewed and run ONE per device, then coordinate them from a thin `RingApprover`.

```
RingApprover {
    devices: Vec<Arc<RemoteApprover>>,   // one per paired phone, each UNCHANGED
}
impl Approver for RingApprover { fn decide(&self, ctx) -> ApprovalOutcome { ... } }
```

Because each device is a full, untouched `RemoteApprover`:

- **Per-device replay is automatic.** Each `RemoteApprover` owns its own
  `ReplayGuard`, its own monotonic `counter`, and its own pinned phone key. No
  guard is shared across devices. This directly satisfies "PER-DEVICE
  ReplayGuard": device A's guard never sees device B's counters, so the two
  phones' independent monotonic sequences never collide or regress each other.
- **No wrong-device response can resolve.** A response is verified inside the
  `RemoteApprover` whose `phone` key sealed it. Device B's response fails
  signature verification in device A's approver and is dropped. Cross-device
  substitution is a `BadSignature`, exactly as in the hostile-relay suite.
- **One reader per device slot.** Each device keeps its single ToDaemon owner
  loop (the sole reader of that device's mailbox), so no response can be stolen.
  `serve()` spawns N owner threads instead of one (see wiring below).
- **Single device is byte-identical.** When N == 1, `build_gate` constructs a
  bare `RemoteApprover` exactly as today (NOT a `RingApprover`), so the reviewed
  path is unchanged for the common case. `RingApprover` is only built for N >= 2.

### Ring-all deposit + first-wins

`RingApprover::decide(ctx)`:

1. **Ring-all.** For each device, register a waiter under `ctx.id` and deposit
   the request sealed per-device (each device seals the SAME `ApprovalRequest`
   with ITS OWN counter and phone key to ITS OWN mailbox). Register-before-deposit
   is preserved per device, so no response can arrive before its waiter exists.
2. **First-wins.** Wait for the FIRST device to return a real decision. "Real"
   is the existing `round_trip` distinction: `Some(outcome)` is an
   approve-or-explicit-deny (it resolves the ring); `None` is a timeout / dead
   owner (it does NOT resolve, we keep waiting on the others). If EVERY device
   returns `None`, the ring denies (fail closed), identical to the single-device
   timeout.
3. **Resolution broadcast.** Once resolved, call `broadcast_resolution(ctx.id,
   Settled)` on every device EXCEPT the winner, so the other phones dismiss. On
   the all-timeout path, no broadcast is needed (each phone expires on its own);
   on a daemon-side withdraw (lockdown/restart), broadcast `Withdrawn` to all.
   `Expired` is available for the daemon expiring a request server-side before any
   phone answers, should the ring choose to prompt-dismiss rather than rely on the
   phones' own timeout.
4. Return the winner's `ApprovalOutcome` to the gate unchanged (DEK for v1, `Z_F`
   partial for v2), so the decrypt path downstream is exactly today's.

### The one delicate part: loser cancellation

The reviewed `round_trip` blocks on `rx.recv_timeout(self.timeout)` on the
per-device waiter channel. In a ring, once one device wins, the N-1 losers are
still blocked in their own `recv_timeout` for up to the full timeout (120s). Two
constraints make this more than cosmetic:

- **Lifetime.** `ctx: &ApprovalContext` cannot be borrowed by detached threads
  that outlive `decide`. So `decide` MUST join all device threads before it
  returns; it cannot leave losers running.
- **Prompt dismissal.** We want losers to stop promptly after a winner, not sit
  for 120s.

The recommended design is a **shared cancel signal** the coordinator can fire to
wake every device's wait:

- Give each device round-trip in the ring a `recv_timeout` loop with a SHORT tick
  (e.g. 200ms) that also checks a shared `Arc<AtomicBool> resolved` (or, better, a
  `std::sync::mpsc` / `Condvar` the coordinator notifies). On `resolved`, the
  device stops waiting and returns `None` (no decision), removing its waiter as
  `round_trip` already does on every exit.
- The coordinator sets `resolved` the instant a winner is seen, then joins all N
  threads (each returns within one tick), then broadcasts to the losers.
- A late loser response that lands after cancellation finds no waiter (already
  removed) and is dropped by that device's owner loop, exactly as a
  post-timeout response is dropped today.

This changes the wait *loop shape* inside a ring-only code path; it must NOT
change the single-device `round_trip`. Two clean options, both keeping the
reviewed path byte-identical for N == 1:

- **(A) Ring-specific method.** Add `RemoteApprover::round_trip_cancellable(ctx,
  cancel: &CancelToken) -> Option<ApprovalOutcome>` used only by `RingApprover`;
  leave `round_trip` (and thus `decide`, used for N == 1) untouched. Factor the
  shared seal/deposit/cleanup so the two share code without the single-device path
  gaining a cancel check.
- **(B) Internal cancel token, always-none for single device.** Thread an
  `Option<&CancelToken>` through the wait; `None` reproduces today's exact
  behavior. Slightly more invasive; (A) is preferred for a cleaner review diff.

Whichever is chosen, the cancellation path is the piece that needs the
independent adversarial pass: it is the only new concurrency in the approval
core, and a bug there is the only way the ring could regress fail-closed-to-deny.
Test matrix (all headless with `LocalRelay` + N software phones):

- N phones, one approves first -> that DEK/`Z_F` reaches the gate; the other N-1
  get a `Settled` broadcast; losers' late responses are dropped, not routed.
- N phones, one denies first -> deny wins (first-wins covers deny too); others
  get `Settled`.
- N phones, all time out -> deny (fail closed); no broadcast required.
- Winner + a concurrent second approval on a different `request_id` -> each ring
  resolves independently; no cross-`request_id` routing.
- Owner death on one device mid-ring -> that device contributes `None`; the ring
  still resolves on the others or denies. Never a release from the dead device.
- Distinct DEKs per phone -> the gate receives exactly the winner's, proving no
  cross-device key delivery.

### `serve()` wiring

`build_gate` returns `Vec<Arc<RemoteApprover>>` (today: `Option<Arc<...>>`);
`serve()` spawns one named ToDaemon owner thread per device and joins them all on
shutdown. The push store is shared or per-mailbox (each device registers its own
token under its own mailbox; `PushStore` is already keyed by mailbox, so N
devices coexist without change). The pending enumeration (`pending_json`)
concatenates every device's `pending_snapshot()`; a ring request appears once per
device it is outstanding on, or is de-duplicated by `request_id` for the Mac's
surface (recommended: de-dup by `request_id`, keeping the earliest `queued_at_ms`
and any `delivered_at_ms`).

## Deferred, with design: multi-pairing storage

`crates/sigil/src/pairing_store.rs` currently persists exactly one pairing: the
public parts in `~/.sigil/pairing.json` (0600) and the daemon's private identity
in the keystore under the fixed label `pairing.daemon-identity.v1`. It stays
inert at rest (no DEK persisted) and is gated on a live biometric at save time
(#48). Multi-device keeps all of that per device.

### On-disk format (v2 container)

Bump `pairing.json` to a versioned container, migrating v1 on read:

```json
{
  "version": 2,
  "devices": [
    {
      "deviceId": "uuidv7",          // stable id; names the keystore label + mailbox row
      "label": "Tom iPhone 15",      // human label for `sigil pair list` / removal
      "relayUrl": "https://...",
      "phone": { /* PeerIdentity */ },
      "pairedAt": 0,
      "sasWords": ["...", 6],
      "phoneShare": { /* PersistedPhoneShare, optional (v2 threshold) */ }
    }
  ]
}
```

- Each device's **private daemon identity** is sealed in the keystore under a
  per-device label `pairing.daemon-identity.v1.<deviceId>`, never in the plaintext
  file. Each pairing ceremony already mints its own fresh daemon identity, so a
  device is fully independent: own daemon identity, own phone pin, own mailbox
  (`mailbox_id(daemon_pub_i, phone_pub_i)`), own DEK delivery. The relay sees N
  unrelated 32-byte mailbox hashes and cannot link them (it never sees a
  `daemon_pub`).
- **v1 read migration.** A `version: 1` file (single `PersistedPairing` +
  identity under the legacy label) loads as a one-element `devices` list whose
  `deviceId` is a fixed sentinel and whose identity stays under the legacy label.
  First `add_device` rewrites the file as v2 and, if desired, re-keys the legacy
  identity label to the per-device scheme (or leaves the primary on the legacy
  label with a recorded exception). Migration must be crash-safe: write the new
  file, then only after it lands delete/rename keystore blobs.

### API

- `load(ks) -> Option<RemotePairingConfig>`: unchanged signature; returns the
  PRIMARY (devices[0]) so a single-device daemon behaves byte-identically. Used
  by today's `build_gate` for N == 1.
- `load_all(ks) -> Vec<RemotePairingConfig>`: every device, for `RingApprover`.
- `add_device(ks, NewPairing) -> deviceId`: appends WITHOUT dropping existing
  devices (additive pairing). Keeps the #48 biometric gate on each add: a real
  keystore runs `verify_presence` BEFORE anything is written, deny-closed, exactly
  as `save` does today.
- `list_devices() -> Vec<DeviceSummary>`: public parts only (no keystore), for
  `sigil pair list`.
- `remove_device(ks, deviceId) -> bool`: delete that device's row + its keystore
  identity blob; idempotent. Removing the last device returns to the unpaired
  state. `unpair` remains "remove all".
- `save`/`summary`/`remove` retained as thin wrappers over the primary for source
  compatibility during migration, or replaced call-by-call in `cli.rs`.

### CLI + Mac

- `sigil pair` becomes additive; its "a phone is already paired; re-pairing will
  replace it" microcopy changes to name the added device and show the running
  count (no em-dash, no emoji, per invariant #6).
- `sigil pair list` enumerates `deviceId`, label, SAS words, paired-at.
- `sigil pair remove <deviceId>` (or `sigil unpair <deviceId>`) removes one; bare
  `sigil unpair` removes all. Design-reviewer owns the final microcopy.

### v2 threshold under multi-device (open question)

The v1 (DEK) path is naturally N-device: every phone receives the same keystore
DEK at pairing, so any phone's approve returns a DEK that decrypts the token.

The v2 threshold path is NOT yet N-device: a `ThresholdRecord` pins one base
point `E` agreed against ONE phone's Secure-Enclave share `F`. With N phones each
holding a distinct `F_i`, a single record cannot be opened by an arbitrary phone.
Options for a later change (all deferred):

- **Per-device wraps.** Store one `E_i` (and matching Mac share `m_i`) per device
  in the record, so any device's partial `Z_{F_i}` opens the token. The ring picks
  the winner's device index and combines with that device's `m_i`.
- **k-of-n threshold.** A genuine threshold scheme over the N shares; heavier, and
  out of scope for #36's "first-wins" (which is 1-of-n by construction).

Until then, a v2 account is armed against the PRIMARY device only (ring-all still
rings all phones, but a non-primary phone's v2 approve cannot open a v2 token and
fails closed). This must be surfaced honestly in `sigil doctor` and is a residual
below.

## Residuals for the independent security-reviewer

1. **Cancellation correctness (highest priority when the ring core lands).** The
   loser-cancellation path is the only new concurrency in the approval core.
   Attack it: can a cancelled loser still route a stale response to the gate? Can
   a race between "winner seen" and "cancel fired" let two devices' outcomes both
   reach the gate (double-release)? The invariant: exactly one outcome reaches the
   gate per `decide`, and an all-timeout ring denies.
2. **Broadcast cannot cause a release.** Confirmed by construction and by the
   hostile-relay proof: `ResolutionBroadcast` carries no key material and gates
   nothing; forging one only hides a prompt (fail-closed). Re-verify when the ring
   coordinator is wired that the broadcast is sent AFTER the winner's outcome is
   committed, never before (a premature `Withdrawn` must not race a real approve).
3. **Per-device replay isolation.** Confirmed for the composition design (separate
   `ReplayGuard` per `RemoteApprover`). Re-verify no shared-guard shortcut sneaks
   into `RingApprover`.
4. **Storage inert-at-rest across N devices.** Each device's private identity in
   the keystore under a per-device label; no DEK persisted; per-device 0600 file
   rows. The #48 biometric gate must fire on EACH `add_device`. Attack the v1->v2
   migration for a window where an identity blob is orphaned or a device is armed
   without a pinned phone.
5. **v2 multi-device gap.** A non-primary phone cannot open a v2 token today; it
   fails closed. Confirm the failure is closed (no partial release) and surfaced,
   not silent.
6. **Push-doorbell metadata.** N devices register N tokens with the relay; the
   relay learns it can wake N devices for one mailbox-set. Same metadata posture
   as single-device, multiplied; no new secret exposure. Note it plainly.

## Invariant map (this change)

- **Inert at rest**: unchanged; no DEK added anywhere. Storage design keeps
  per-device identities in the keystore, DEK off disk.
- **Secrets bypass the daemon**: unchanged; the broadcast carries no secret and
  the decrypt/splice path is untouched.
- **Relay powerless/anonymous**: a per-device mailbox is another opaque key-hash
  mailbox; the `ResolutionBroadcast` is opaque and single-use to the relay
  (hostile-relay proof). No key-distribution role added.
- **Replay impossible**: the broadcast rides the sealed/signed/single-use
  envelope on the daemon->phone counter; per-device guards stay separate.
- **Biometric gating structural**: unchanged; approve still requires the phone's
  hardware-gated key use. Deny and dismiss require nothing. The broadcast is not
  an approve path.
- **Fail closed**: a lost/forged/dropped broadcast degrades to each phone's own
  timeout; the ring denies on all-timeout; a non-primary v2 approve fails closed.
- **No em-dash / no emoji**: honored in all new user-facing strings (phone
  history note "resolved on another device", CLI copy specified above).
