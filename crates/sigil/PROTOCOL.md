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
- **Bound.** At most `sigil_proto::COVERS_MAX_CHARS` (72) characters, control
  characters stripped and whitespace collapsed by `LeasePolicy::with_covers`.
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
