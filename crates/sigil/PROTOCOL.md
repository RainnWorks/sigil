# The Sigil daemon control protocol

This is the machine interface the Mac app (`apps/mac/Sigil/Model/DaemonClient.swift`)
speaks **directly** to the daemon over its unix control socket. The human `sigil`
CLI is a second renderer of the same protocol: for the read/report and
runtime-control verbs it is a thin socket client. There is one interface, two
renderers.

The Rust definition is `crates/sigil/src/local.rs` (`Frame` = request, `Reply` =
response); the JSON payload shapes are the DTOs in `crates/sigil/src/json.rs`
(field-for-field the Swift decoder in `DaemonClient.swift`).

## Least-privilege split (why some things are NOT here)

The always-running, relay-connected daemon may **read/report everything and
control the runtime**, but it must never be able to **mutate the
keystore/tokens/config or wipe**. Those are short-lived, user-invoked CLI
operations so a compromised daemon cannot perform them. Therefore:

- **Over this socket (daemon):** status, doctor, leases (list + revoke), pending
  (+ live subscription), history, approve/deny.
- **CLI-only mutations (the Mac app shells out to `sigil … --json`):** account
  add/rotate/remove, **command config** (`config add|list|remove`), settings
  get/set, wipe `--force`, mac-approvals `--enable|--phone-only`, shim
  install/add, and **pairing** (`sigil pair --relay <url> --json`, an NDJSON
  ceremony stream). These write the keystore / `~/.sigil` and so are deliberately
  not daemon capabilities. Their `--json` shapes are in `JSON.md`.

**Exception, added with the wrapped keystore (2026-08-04).** The daemon can now
perform exactly one mutation: `seal_threshold` writes a threshold-sealed record
into `threshold.db`. It exists because under a Secure-Enclave-wrapped keystore
the CLI cannot read the Mac share it would seal with, and the daemon holds the
opened material. Weigh it honestly: the daemon can now write sealed values a
caller hands it, where before only a short-lived CLI could. It still cannot read
any sealed value back (opening needs the phone's per-request partial), cannot
mutate the keystore itself (see below), and cannot mutate rules, settings, or
pairing. The keystore verbs are likewise not mutations of the keystore *by the
daemon*: they hand it material and drive de-adoption, and the file itself is only
ever written by the signed app.

Pairing note: the brief initially placed the pairing ceremony on the socket
(the daemon owns the relay connection). It is kept CLI-side because completing a
pairing **writes the daemon's private identity into the keystore and
`pairing.json`** — a keystore/config mutation, which the least-privilege
principle keeps out of the daemon. The daemon still *reads* the persisted pairing
at arm time and reports it via `status`. If the security review prefers the
daemon to drive pairing, the persist step is the only piece that must move.

## Framing

The control socket lives at `$SIGIL_SOCK` or `$TMPDIR/sigil/daemon.sock`, mode
**0600**, in a **0700** directory: only the owning user may connect. The daemon
reads the **kernel-verified peer pid** (`LOCAL_PEERPID` on macOS, `SO_PEERCRED`
on Linux) for its lease/provenance measurement; a client cannot spoof it.

Wire framing (unchanged from the existing shim protocol):

- **Request:** one JSON object (a `Frame`), newline-terminated, written by the
  client. `Op` requests additionally pass the caller's stdout/stderr file
  descriptors via `SCM_RIGHTS`; **no control frame passes descriptors.**
- **Reply:** one JSON object (a `Reply`) per line, written by the daemon.
  Request/reply verbs write exactly one reply then the daemon closes the
  connection. The subscription writes **many** `event` replies on one connection
  until the client hangs up.

A frame that is not valid JSON is rejected (`InvalidData`); the daemon never
guesses. An unknown/hung-up connection (a bare connect-then-close probe) is a
quiet no-op.

`Frame` is tagged by a `kind` field (snake_case). `Reply` is tagged by `kind`
too: `exit` | `control` | `json` | `event`.

## Requests and replies

### Read / report — reply `json` (a body string that parses to the DTO)

| Frame | Reply body (DTO) |
|-------|------------------|
| `{"kind":"status"}` | `StatusJson` |
| `{"kind":"doctor"}` | `[CheckJson]` |
| `{"kind":"lease_list"}` | `[LeaseJson]` |
| `{"kind":"pending"}` | `[PendingJson]` |
| `{"kind":"history"}` | `[HistoryJson]` |

The reply is `{"kind":"json","body":"<the JSON text>"}`; the client parses
`body`. The daemon is the source of truth: it computes the host facts (shim
drift, `op` discovery, pairing factor, relay reachability, counts) *and* holds
the runtime facts (live leases, the pending set, the audit log).

`StatusJson`:
```json
{ "daemon_up": bool, "socket": str,
  "shim": { "kind": "healthy|drift|not_installed|unknown", "path": str?, "issue": str? },
  "op": { "found": bool, "path": str? },
  "accounts": int,
  "factor": { "kind": "phone|biometric|fail_closed", "relay": str? },
  "relay_reachable": bool?, "relay_url": str?,
  "locked_down": bool (always false; retained for wire compatibility) }
```
`CheckJson`: `{ "label": str, "ok": bool, "hint": str }` — the last row
(`ssh-agent socket`) is informational (always `ok`).

`LeaseJson`: `{ "grant_hex": str, "caller": str, "account": str, "scope": str,
"covers": str, "granted_ms": int, "expires_ms": int }`. `scope` is the matched
RULE's name: the lease covers any command that rule matches for the caller chain
that opened it, not just the command line that did. `covers` is the daemon's
coverage label (below) naming exactly what that rule matches, so renderers can
state the breadth instead of gesturing at it; the CLI prints
`<rule> · <covers>`, falling back to `<rule> · any matching command` when the
daemon rendered no label.

`PendingJson`:
```json
{ "id": str, "kind": str, "command": [str],
  "secrets": [ { "provider": str, "segments": [str], "label": str } ],
  "ssh": { "key_label": str, "host": str, "fingerprint": str }?,
  "provenance": { "process_chain": [str], "cwd": str, "machine": str, "requested_ms": int },
  "leasable": bool, "max_lease_secs": int?, "lease_covers": str?, "reason": str?,
  "expires_ms": int, "timeout_ms": int, "coalesced": int }
```

### The lease coverage label (`covers`)

A leasable request must tell the human **how wide the window is** before they
open it. The daemon therefore renders one short string, the **coverage label**,
and every surface shows that same string: the phone's approval sheet, the Mac,
and `sigil lease list`. No renderer derives its own description of the breadth.

- **Provenance.** Rendered by the daemon (`Match::coverage` in
  `crates/sigil/src/config.rs`) from the **matched rule's own match conditions**
  (`command`, `subcommand`, `argv_contains`, `flag_present`, `flag_equals`,
  `arg_regex`) at resolve time. Those conditions are **user-authored config**, not
  provider semantics, so carrying them does not dent the approver's
  provider-blindness. It is never read from disk (a hand-edited `covers` in
  `config.json` is ignored and overwritten), never taken from a client, and never
  built from the argv that happened to trip the rule. A raw argv and a secret
  reference can therefore never appear in it.
- **Register.** `op read` (subcommand), `op with --account "rowmhq.1password.eu"`
  (flag equality), `op with --vault` (flag presence), `op containing "prod"`
  (substring), plain `op` when nothing beyond the command is constrained. The
  label never implies a rule is narrower than it is: a command-only rule renders
  the bare command.
- **Bound.** At most `sigil_proto::COVERS_MAX_CHARS` (72) characters, reduced by
  `LeasePolicy::with_covers` to an allowlist: printable ASCII, whitespace runs
  collapsed to one space, and `…`. Every other character (bidi controls,
  zero-width and other format characters, combining marks, and anything else that
  renders as nothing) becomes one `?` per run, so a label cannot reorder, hide
  inside, or stack on the caption it is rendered into. Renderers mirror this
  filter rather than trusting it.
  A rule with more than three conditions, or one whose list would exceed the
  bound, degrades to an honest count (`op read with 5 match conditions`) rather
  than a truncated list that would read as if the dropped conditions did not
  exist. A single over-long user token is elided with `…`.
- **Run-once carries none.** A run-once request opens no window, so it has
  nothing to describe: `lease_covers` is omitted (and the proto's `covers` is
  absent from the sealed policy).
- **Display only.** Renderers must treat it as text to show, never as something
  to parse, match on, or act on. The daemon remains the sole lease authority: the
  label describes the window, it does not define it. When it is absent or empty a
  renderer shows **no coverage clause** rather than inventing one.

**On the wire to the phone**, the same string rides *inside the sealed envelope*
as a field of the request's lease policy (proto `LeasePolicy::Leasable`):
`{"kind":"leasable","maxSecs":900,"covers":"op read"}`, omitted when empty. It
uses no new transport and is not visible to the relay.

`HistoryJson`: `{ "id": str, "kind": str, "label": str, "account": str,
"process": str, "cwd": str, "decision": "approved|denied|expired", "note": str?,
"at_ms": int, "via": "phone|biometric|lease|dev" }`.

### Runtime control — reply `control`

| Frame | Effect |
|-------|--------|
| `{"kind":"lease_revoke","prefix":str}` | revoke leases whose grant hex starts with `prefix` |
| `{"kind":"approve","id":str,"lease":bool}` | resolve a parked local request as approve (optionally lease) |
| `{"kind":"deny","id":str}` | resolve a parked local request as deny |

Reply: `{"kind":"control","ok":bool,"lines":[str]}`. `ok:false` with a reason
line when there was nothing to act on (e.g. approving an id that is not parked).

**Finding-1 posture:** `approve`/`deny` only *resolve an already-parked* local
request; they cannot manufacture an approval. Under the phone or no-factor
configurations nothing parks on the control socket (the phone is the gate, or
`NullApprover` denies), so a control client **cannot bypass the real approving
factor**. This is unchanged and covered by tests
(`control_approve_for_an_unknown_id_is_refused`,
`no_factor_daemon_fails_closed_on_a_gated_request`).

### Subscription — reply `event` stream

`{"kind":"subscribe_pending"}` → the daemon writes
`{"kind":"event","body":"<[PendingJson]>"}` **immediately** (the current set) and
again on **every change** to the pending set, in order, until the client
disconnects. It also re-emits as a periodic keepalive so a dead client is
detected. Drives the live menubar. The client parses each `event.body` as
`[PendingJson]` and replaces its view.

### The Secure-Enclave-wrapped keystore (v2)

When `keystore.json` is wrapped (`{"v":2,...}`), its bytes are ciphertext only
the signed Sigil app's enclave can open, and the daemon is handed the plaintext
at runtime. The delta this buys is **at-rest exfiltration only** (backups,
snapshots, a stolen disk); a live same-UID attacker is exactly as capable as
before, and the daemon is unsigned by design.

Four verbs, all of which the daemon refuses unless the **peer's code identity**
satisfies `anchor apple generic and certificate leaf[subject.OU] = "53W966FBFP"`
(checked live against the connecting pid via Security.framework, not asserted):

- `{"kind":"keystore_provision","len":N}` **followed immediately by N raw bytes**
  on the same stream. The daemon digests what it received
  (`BLAKE2b-256("sigil.keystore.v2" || len||se_pub || len||material)`) and
  compares it, constant time, against the value the file committed to, read once
  at startup. Reply is a bare `control` ok/fail that never echoes the expected
  digest. Accepted **once per daemon lifetime**; a refused attempt does not
  consume that slot (otherwise one bad frame would be a denial of service).
  Material never travels inside a JSON field: no `Frame` variant carries it.
- `{"kind":"subscribe_keystore"}` → an `event` stream of ceremony events,
  currently `{"kind":"unwrap","nonce":str}` only.
- `{"kind":"keystore_unwrap_done","nonce":str,"ok":bool,"reason":str}`: the app
  reports the outcome; on `ok` the daemon clears the adoption marker.
- `{"kind":"keystore_unwrap_request"}`, same-UID (it is `sigil keystore unwrap
  --confirm`), asks the daemon to raise an unwrap request and waits for the app.

**Deferred, deliberately:** the commit flow (`keystore_commit_fetch` /
`keystore_commit_done`) for daemon-side keystore mutations. It has no trigger
today: the daemon never writes the keystore (every write is CLI-side in
`pairing_store`), and those CLI paths refuse upfront against a sealed store. So
while wrapped, nothing mutates the keystore from either side, by construction
rather than by machinery. When daemon-side mutations exist, `subscribe_keystore`
is the stream they announce on.

One more verb exists because of wrapping, but is same-UID (not app-only):
`{"kind":"seal_threshold","id":str,"len":N}` + N raw bytes asks the daemon to
threshold-seal a value the caller supplies, because under a wrapped store the CLI
cannot read the Mac share to seal with. `len == 0` removes the record. The caller
is `sigil-config`, an unsigned CLI, so there is no code identity to demand; the
boundary is the 0600 socket, the same one every other CLI verb has.

## Phone lease control (sealed relay messages, NOT this socket)

Everything above rides the local unix control socket. This section is different:
it defines four messages that ride the **sealed envelope between the daemon and a
paired phone**, on the same `ToDaemon` / `ToPhone` channels as approvals. It lives
here because it is the second controller over the same lease store the
`lease_list` / `lease_revoke` frames above drive, and the two must be read
together. The Rust definitions are in `crates/sigil-proto/src/request.rs`; the
daemon side is `RemoteApprover::answer_lease_list` / `answer_lease_revoke` in
`crates/sigil/src/remote.rs`.

`sigil lease revoke <prefix>` is unchanged. This **adds** a controller; it does
not move the existing one.

### Why it exists

The brief cites phone-side visibility and revocation as the containment for a
rule-wide lease window. Until now the phone's lease list and revoke control were
demo state, which is worse than an absent control: a revoke button that silently
does nothing teaches the human that the window is closed when it is open.

### The four messages

All four are **tagged by a `type` field** and demultiplexed alongside the existing
traffic on their channel (`ToDaemonMessage` / `ToPhoneMessage`). An
`ApprovalResponse` and an `ApprovalRequest` remain the only untagged payloads, so
no lease message can ever be routed to a waiting approval.

**Phone → daemon** (`ToDaemon`, same counter and replay guard as an approval):

```jsonc
{ "type": "leaseList",   "queryId": "<id>" }
{ "type": "leaseRevoke", "queryId": "<id>",
  "grantHex": "<64 lowercase hex>", "instance": "<32 lowercase hex>" }
```

**Daemon → phone** (`ToPhone`, same counter and seal as a request):

```jsonc
{ "type": "leaseListReply", "queryId": "<echoed>",
  "leases": [ { "grantHex": str, "instance": str, "scope": str, "covers": str,
                "account": str, "remainingMs": int, "ageMs": int } ] }
{ "type": "leaseRevokeReply", "queryId": "<echoed>",
  "grantHex": "<echoed>", "revoked": bool }
```

Field semantics, exactly:

| Field | Meaning |
|-------|---------|
| `queryId` | Phone-generated correlation id. 1–64 printable-ASCII characters; the daemon validates and echoes it verbatim. The phone MUST drop a reply whose `queryId` it did not send, so a late answer cannot repaint a newer screen. |
| `grantHex` | The grant key, exactly 64 hex characters. **Deterministic**: the same caller chain and rule derive it again tomorrow. It names a lease *shape*, not a lease. |
| `instance` | This window's instance id, exactly 32 hex characters. 16 bytes of OS randomness minted when the window opens. Names ONE window. |
| `scope` | The matched rule's name. Display must state the breadth: the window covers anything that rule matches, not the one command that opened it. |
| `covers` | The daemon-rendered coverage label (`op read`). **Empty means none was rendered** — show no coverage clause rather than inventing one. |
| `account` | The source label the window injects from. Empty for a plain gate, which injects nothing. |
| `remainingMs` / `ageMs` | Milliseconds until the window lapses, and since it opened. |
| `revoked` | `true` only when a live window with that exact `(grantHex, instance)` was found and zeroized. |

`leases` is always present; empty is a complete answer meaning "no live windows".
`covers` and `account` are always present; empty is their "none" value. Every
input the phone accepts is case-normalised hex or an already-sanitised label; hex
is emitted lowercase.

### What is never on the wire

`scope`, `covers`, and `account` are the only human-readable fields, and all three
pass through `sanitize_label` at `LEASE_LABEL_MAX_CHARS` (72) — the same allowlist
that protects the approval sheet's coverage caption: printable ASCII, whitespace
runs collapsed, `…`, and one `U+FFFD` per run of anything else. So a rule name
carrying a bidi override or a pile of combining marks cannot reorder or hide the
lease list. **Renderers re-filter** rather than trusting this.

There is no argv, no secret reference, and no secret value in any of the four
messages. A revoke carries two identifiers; a list carries names and clocks.

### Replay binding: what was chosen, and what it does not cover

The problem is specific. A grant key is a hash of the daemon-verified caller
identity plus the rule, so **it recurs**: the same tool tree running the same rule
tomorrow derives the same `grantHex`. A `LeaseRevoke` that named only the key
would be aiming at every window that key will ever have, and a copy of it captured
off the wire would be a stored weapon against a future window the human just
opened.

**The envelope's own protection, stated honestly.** The per-pairing counter is
**not** a replay gate in this codebase — it was retired (`crates/sigil-proto/src/replay.rs`)
because an in-memory counter reset on either side and dropped genuine approvals as
false replays. It still rides the wire inside the signed bytes, but it gates
nothing, so it was not available as the freshness lever. What remains is two gates,
both of which a lease message passes through exactly like an approval:

1. **Ed25519 signature** over the canonical bytes. The relay holds neither signing
   key, so it can neither forge a revoke nor re-aim a genuine one.
2. **Freshness + single use**: the sender timestamp must be within
   `REPLAY_WINDOW_MS` (150s) of now, and the uuidv7 request id must not have been
   seen on that pairing.

Those two catch a replay in every case but one. The guard is in-memory, so a
**daemon restart inside the freshness window** starts with an empty seen-set: a
captured revoke re-delivered in that gap is authentic and fresh, and opens. It is
normally harmless (a restart clears every lease), but the sequence
`restart → human re-approves → relay replays the captured revoke` would kill a
window the human opened seconds earlier, with no visible cause. That is exactly
the "future window sharing the key" case.

**The choice: bind the window instance.** Every lease carries 16 bytes of OS
randomness minted when the window opens, and a `LeaseRevoke` must name both
`grantHex` and `instance`. `LeaseStore::revoke_instance` matches both exactly, so a
replayed revoke names a window that has already ended and is a clean no-op.

- **Random, not granted-at.** Two windows granted in the same millisecond would
  share a timestamp, and a clock moves. 16 CSPRNG bytes collide with nothing.
- **Preserved across a refresh.** A later approval under the same key extends the
  one window the human is looking at; a revoke aimed at it before the refresh must
  still land. A new instance is minted only when a window genuinely ended and a
  fresh approval opened another — the case a stale revoke must not reach.
- **Exact, not prefix.** A prefix is a convenience for a human at a terminal who
  can see what they are aiming at. A message that crossed a relay gets no latitude.

**What the instance binding does not cover** (residuals, for the reviewer):

1. **A censoring relay.** The relay cannot forge, alter, or replay a revoke, but it
   can **drop** one. A dropped revoke leaves the window alive until its TTL,
   `sigil lease revoke` on the Mac, or a daemon restart. Phone-side revocation is
   therefore best-effort by construction, and the containment story must say so:
   the TTL and the Mac are the backstops, not the phone.
2. **A lost reply looks like a failed revoke.** The daemon replies once,
   best-effort, with no retry. A revoke whose reply is lost may or may not have
   landed. The phone must treat a missing reply as *unknown* and re-list, never as
   success or as failure.
3. **Traffic analysis.** The relay sees an opaque envelope, but not a constant-size
   one: a list reply's length grows with the number of windows, and
   `"revoked":true` is one byte longer than `"revoked":false`. So a relay that is
   also watching timing can infer "a list was fetched and it was short" or "a
   revoke succeeded". It learns no identifier, label, or value. Padding would close
   it; it is not implemented, and it is a strictly smaller leak than the
   already-variable approval traffic on the same channel.
4. **It does not authenticate the human.** A compromised *phone* (holding the
   signing key) can revoke at will. Revocation only ever narrows what is
   authorized, so this is a denial-of-convenience, never a release.

### Rate limiting

A lease **list** is answered at most once per 250ms per device; a query inside that
floor is dropped with no reply. A list is idempotent, so the cost is a re-ask. A
**revoke is never rate-limited** — it is an action the human just took, and
silently dropping one would be the consent theatre this feature exists to end.

### Fail-closed rules the daemon holds to

- No lease store attached, a malformed `queryId`, or (for a revoke) a `grantHex` or
  `instance` that is not exactly-width hex: the message is dropped **whole, with no
  reply**. Peer-chosen bytes are never echoed back onto a screen.
- Anything that fails verify, replay, or decode is dropped, exactly as an approval
  response is.
- A revoke that matches nothing is a **successful no-op** reporting
  `revoked: false`, never an error. The four ways to reach `false` (already lapsed,
  already revoked, superseded instance, key never held) are indistinguishable, so
  the reply is not an oracle for what this daemon holds.
- Neither message can release a secret, approve a request, or widen anything. A
  list reads names and clocks; a revoke can only take a window away.

### The run path (not part of the control surface)

`{"kind":"run","argv":[str],"cwd":str}` with the caller's stdout/stderr passed as
`SCM_RIGHTS` is the secret path for the `sigil <cmd>` primitive (and its shim
alias / `sigil run -- <cmd>`). `argv[0]` is the command name; the daemon looks up
the command's config, gates it, injects the provider's environment, then splices
the child's stdout to the caller fd. An *unconfigured* command is refused (a
non-zero exit with a stderr pointer to `sigil config add`), never run ungated.
Reply `{"kind":"exit","code":int}`. Clients of the control protocol never send
this; it is the shim / primitive channel.

## What the Swift `DaemonClient` implements vs. shells out for

**Implements over the socket** (connect, write one `Frame` line, read `Reply`
line(s), parse `body`):
- `status()` → `status`; `doctor()` → `doctor`; `leases()` → `lease_list`;
  `pending()` → `pending`; `history()` → `history`.
- `revokeLease` → `lease_revoke`;
  `approve/deny` → `approve`/`deny` (read the `control` `{ok,lines}`).
- A long-lived `subscribe_pending` connection feeding the menubar; reconnect on
  drop.

**Shells out to `sigil … --json`** (short-lived process; keystore/config
mutations that must not be daemon capabilities):
- `addAccount`/`rotateAccount`/`removeAccount` → `account add|rotate|remove … --json`
- `settings`/`saveSettings` → `settings get|set --json`
- `wipe` → `wipe --force --json`
- `setMacApprovals` → `mac-approvals --enable|--phone-only --json`
- `installShim` → `shim install --json`
- `unpair` → `unpair --json`
- pairing → `pair --relay <url> --json` (read the NDJSON `qr`/`sas`/`paired`/
  `failed` events line by line); `pairedDevice` → `pair list --json`.

See `JSON.md` for those mutation output shapes.

## Known gaps vs. the DTO fields (honest constants, not fabricated)

- `account.health`/`detail`/`last_used_ms`: no token-expiry model → `healthy`/null.
- `account.id`: equals the label (the store keys by unique label).
- `lease.caller`: empty — a lease retains the grant key, not the provenance.
- `pending.leasable`/`max_lease_secs`/`lease_covers`: carried through from the
  matched rule's lease policy (`leasable=false` + omitted cap and label for a
  run-once rule). A local approver must not offer "approve for N minutes" when
  `leasable` is false, and clamps any window to `max_lease_secs`; the daemon
  re-checks regardless. See "The lease coverage label" above for `lease_covers`.
- `lease.covers`: empty for a grant whose rule the daemon rendered no label for;
  a renderer then falls back to naming the rule and its breadth generically,
  never to a guess at what the rule matches.
- `pending.reason`/`coalesced`: null/0 — the local control-socket path sets no
  reason line and the registry does not count coalesced waiters.
- `pair.name`: fixed `"iPhone"` — the ceremony captures no device name.
- `history.decision == "expired"`: reserved; a timed-out local approval currently
  records `denied`.
