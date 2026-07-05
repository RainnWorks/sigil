# `latch … --json` — the CLI mutation output shapes

This file documents the `--json` output of the **CLI-only mutation commands**.
By the least-privilege split (see `PROTOCOL.md`), these operations write the
keystore / config / `~/.latch` and are therefore **not** daemon capabilities:
the Mac app shells out to `latch … --json` for them and decodes the shapes here.

Everything the daemon *reports or controls at runtime* (status, doctor, leases,
pending, history, lockdown, approve/deny, the live pending subscription) is the
**daemon control socket protocol**, specified in `PROTOCOL.md` — not `--json`.
The DTOs for both live in `crates/latch/src/json.rs`.

Each command below emits one JSON value on stdout (no ANSI). Enum-like fields
are explicit strings. Timestamps are integer unix milliseconds.

## Commands and shapes

### `latch account list --json`
```json
[ { "id": str, "label": str, "vaults": [str],
    "health": "healthy|rotate|expiring", "detail": str?, "last_used_ms": int? }, ... ]
```

### `latch account add --token-stdin --label <l> --json`
### `latch account rotate --id <id> --token-stdin --json`
Each echoes one account object (same shape as a `list` element).

### `latch account remove --id <id> --json`
### `latch shim install --json`
### `latch unpair --json`
### `latch wipe --force --json`
All return the control shape:
```json
{ "ok": bool, "lines": [str] }
```
`wipe` refuses (`ok:false`) without `--force`. `wipe --force` removes the
pairing, accounts, SSH keys, settings, dev keystore, and history.

### `latch mac-approvals --enable | --phone-only --json`
```json
{ "ok": bool }
```
`--phone-only` persists the hardened mode (phone strictly required) → `ok:true`.
`--enable` needs the Mac Secure Enclave DEK envelope: it succeeds on the dev
keystores, and on a real enclave exits non-zero with a "needs verification"
stderr line (minting defers to task #17) rather than faking success.

### `latch settings get --json`  /  `latch settings set --json`
```json
{ "approval_timeout_sec": int, "notifications": bool, "retention_days": int,
  "relay_url": str, "reduce_motion": bool, "mac_approvals": "enabled|phone_only" }
```
`set` accepts a positional `<key> <value>` or a JSON object patch on stdin (what
the Mac app pipes). A patch is **merged**: absent keys are untouched, so writing
the five GUI fields never drops `mac_approvals` (extra to the Swift `SettingsDTO`
and ignored by its decoder).

### `latch pair list --json`
```json
{ "paired": { "name": str, "sas_words": [str], "relay_url": str, "paired_ms": int } | null }
```

### `latch pair --relay <url> --json`  (NDJSON ceremony stream)
Pairing writes the daemon's private identity into the keystore + `pairing.json`,
so it is a CLI mutation, not a daemon op. It streams one JSON object **per line**
as the ceremony progresses:
```json
{ "event": "qr", "payload_b64": str }
{ "event": "sas", "words": [str] }
{ "event": "paired", "name": str, "sas_words": [str], "relay_url": str, "paired_ms": int }
{ "event": "failed", "reason": str }
```
The SAS is auto-confirmed once its event is emitted (the stream is one-way; the
human confirms on the phone, as the interactive `--yes` does).

## Known gaps vs. the DTO fields

Emitted with an honest constant/empty value, not fabricated (also noted inline in
`json.rs` and in `PROTOCOL.md`):

- `account.health` / `detail` / `last_used_ms` — no token-expiry model →
  `healthy` / null.
- `account.id` — equals the label (the store keys accounts by unique label), so
  `account rotate/remove --id <id>` takes the label.
- `pair.name` — fixed `"iPhone"`; the ceremony captures no device name.
