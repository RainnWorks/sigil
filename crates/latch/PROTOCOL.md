# The Latch daemon control protocol

This is the machine interface the Mac app (`apps/mac/Latch/Model/DaemonClient.swift`)
speaks **directly** to the daemon over its unix control socket. The human `latch`
CLI is a second renderer of the same protocol: for the read/report and
runtime-control verbs it is a thin socket client. There is one interface, two
renderers.

The Rust definition is `crates/latch/src/local.rs` (`Frame` = request, `Reply` =
response); the JSON payload shapes are the DTOs in `crates/latch/src/json.rs`
(field-for-field the Swift decoder in `DaemonClient.swift`).

## Least-privilege split (why some things are NOT here)

The always-running, relay-connected daemon may **read/report everything and
control the runtime**, but it must never be able to **mutate the
keystore/tokens/config or wipe**. Those are short-lived, user-invoked CLI
operations so a compromised daemon cannot perform them. Therefore:

- **Over this socket (daemon):** status, doctor, leases (list + revoke), pending
  (+ live subscription), history, lockdown (engage/clear), approve/deny.
- **CLI-only mutations (the Mac app shells out to `latch … --json`):** account
  add/rotate/remove, **command config** (`config add|list|remove`), settings
  get/set, wipe `--force`, mac-approvals `--enable|--phone-only`, shim
  install/add, and **pairing** (`latch pair --relay <url> --json`, an NDJSON
  ceremony stream). These write the keystore / `~/.latch` and so are deliberately
  not daemon capabilities. Their `--json` shapes are in `JSON.md`.

Pairing note: the brief initially placed the pairing ceremony on the socket
(the daemon owns the relay connection). It is kept CLI-side because completing a
pairing **writes the daemon's private identity into the keystore and
`pairing.json`** — a keystore/config mutation, which the least-privilege
principle keeps out of the daemon. The daemon still *reads* the persisted pairing
at arm time and reports it via `status`. If the security review prefers the
daemon to drive pairing, the persist step is the only piece that must move.

## Framing

The control socket lives at `$LATCH_SOCK` or `$TMPDIR/latch/daemon.sock`, mode
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
the runtime facts (lockdown, live leases, the pending set, the audit log).

`StatusJson`:
```json
{ "daemon_up": bool, "socket": str,
  "shim": { "kind": "healthy|drift|not_installed|unknown", "path": str?, "issue": str? },
  "op": { "found": bool, "path": str? },
  "accounts": int,
  "factor": { "kind": "phone|biometric|fail_closed", "relay": str? },
  "relay_reachable": bool?, "relay_url": str?, "locked_down": bool }
```
`CheckJson`: `{ "label": str, "ok": bool, "hint": str }` — the last row
(`ssh-agent socket`) is informational (always `ok`).

`LeaseJson`: `{ "grant_hex": str, "caller": str, "account": str, "scope": str,
"granted_ms": int, "expires_ms": int }`.

`PendingJson`:
```json
{ "id": str, "kind": str, "command": [str],
  "secrets": [ { "provider": str, "segments": [str], "label": str } ],
  "ssh": { "key_label": str, "host": str, "fingerprint": str }?,
  "provenance": { "process_chain": [str], "cwd": str, "machine": str, "requested_ms": int },
  "risk": "routine|elevated|critical", "reason": str?,
  "expires_ms": int, "timeout_ms": int, "coalesced": int }
```

`HistoryJson`: `{ "id": str, "kind": str, "label": str, "account": str,
"process": str, "cwd": str, "decision": "approved|denied|expired", "note": str?,
"at_ms": int, "via": "phone|biometric|lease|dev" }`.

### Runtime control — reply `control`

| Frame | Effect |
|-------|--------|
| `{"kind":"lockdown","clear":false}` | seal: deny + refuse, zeroize leases |
| `{"kind":"lockdown","clear":true}` | unseal |
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

### The run path (not part of the control surface)

`{"kind":"run","argv":[str],"cwd":str}` with the caller's stdout/stderr passed as
`SCM_RIGHTS` is the secret path for the `latch <cmd>` primitive (and its shim
alias / `latch run -- <cmd>`). `argv[0]` is the command name; the daemon looks up
the command's config, gates it, injects the provider's environment, then splices
the child's stdout to the caller fd. An *unconfigured* command is refused (a
non-zero exit with a stderr pointer to `latch config add`), never run ungated.
Reply `{"kind":"exit","code":int}`. Clients of the control protocol never send
this; it is the shim / primitive channel.

## What the Swift `DaemonClient` implements vs. shells out for

**Implements over the socket** (connect, write one `Frame` line, read `Reply`
line(s), parse `body`):
- `status()` → `status`; `doctor()` → `doctor`; `leases()` → `lease_list`;
  `pending()` → `pending`; `history()` → `history`.
- `revokeLease` → `lease_revoke`; `lockdown(clear:)` → `lockdown`;
  `approve/deny` → `approve`/`deny` (read the `control` `{ok,lines}`).
- A long-lived `subscribe_pending` connection feeding the menubar; reconnect on
  drop.

**Shells out to `latch … --json`** (short-lived process; keystore/config
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
- `pending.risk`/`reason`/`coalesced`: `routine`/null/0 — the local
  control-socket path does no risk scoring and the registry does not count
  coalesced waiters.
- `pair.name`: fixed `"iPhone"` — the ceremony captures no device name.
- `history.decision == "expired"`: reserved; a timed-out local approval currently
  records `denied`.
