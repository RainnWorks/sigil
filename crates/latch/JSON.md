# `sigil … --json` — the CLI mutation output shapes

This file documents the `--json` output of the **CLI-only mutation commands**.
By the least-privilege split (see `PROTOCOL.md`), these operations write the
keystore / config / `~/.sigil` and are therefore **not** daemon capabilities:
the Mac app shells out to `sigil … --json` for them and decodes the shapes here.

Everything the daemon *reports or controls at runtime* (status, doctor, leases,
pending, history, lockdown, approve/deny, the live pending subscription) is the
**daemon control socket protocol**, specified in `PROTOCOL.md` — not `--json`.
The DTOs for both live in `crates/sigil/src/json.rs`.

Each command below emits one JSON value on stdout (no ANSI). Enum-like fields
are explicit strings. Timestamps are integer unix milliseconds.

## Commands and shapes

### `sigil account list --json`
```json
[ { "id": str, "label": str, "vaults": [str],
    "health": "healthy|rotate|expiring", "detail": str?, "last_used_ms": int? }, ... ]
```

### `sigil account add --token-stdin --label <l> --json`
### `sigil account rotate --id <id> --token-stdin --json`
Each echoes one account object (same shape as a `list` element).

### `sigil config list --json`
```json
[ { "command": str, "provider": str, "source": str?, "account": str?,
    "risk": "routine|elevated|critical" }, ... ]
```

### `sigil config add <cmd> --provider <id> [...] --json`
Echoes the one added command object (same shape as a `list` element). Validated
CLI-side: an unknown provider or risk, or an `env-file` provider without
`--source`, is rejected (exit 2) before the store is written.

### `sigil config remove <cmd> --json`
Returns the control shape `{ "ok": bool, "lines": [str] }` (`ok:false` when no
such command was configured).

### `sigil account remove --id <id> --json`
### `sigil shim install --json`
### `sigil shim add <cmd> --json`
### `sigil unpair --json`
### `sigil wipe --force --json`
All return the control shape:
```json
{ "ok": bool, "lines": [str] }
```
`wipe` refuses (`ok:false`) without `--force`. `wipe --force` removes the
pairing, accounts, SSH keys, command config, settings, dev keystore, and history.

### `sigil mac-approvals --enable | --phone-only --json`
```json
{ "ok": bool }
```
`--phone-only` persists the hardened mode (phone strictly required) → `ok:true`.
`--enable` needs the Mac Secure Enclave DEK envelope: it succeeds on the dev
keystores, and on a real enclave exits non-zero with a "needs verification"
stderr line (minting defers to task #17) rather than faking success.

### `sigil settings get --json`  /  `sigil settings set --json`
```json
{ "approval_timeout_sec": int, "notifications": bool, "retention_days": int,
  "relay_url": str, "reduce_motion": bool, "mac_approvals": "enabled|phone_only" }
```
`set` accepts a positional `<key> <value>` or a JSON object patch on stdin (what
the Mac app pipes). A patch is **merged**: absent keys are untouched, so writing
the five GUI fields never drops `mac_approvals` (extra to the Swift `SettingsDTO`
and ignored by its decoder).

### `sigil pair list --json`
```json
{ "paired": { "name": str, "sas_words": [str], "relay_url": str, "paired_ms": int } | null }
```

### `sigil pair --relay <url> --json`  (NDJSON ceremony stream)
Pairing writes the daemon's private identity into the keystore + `pairing.json`,
so it is a CLI mutation, not a daemon op. It streams one JSON object **per line**
as the ceremony progresses:
```json
{ "event": "qr", "payload_b64": str }
{ "event": "sas", "words": [str] }
{ "event": "paired", "name": str, "sas_words": [str], "relay_url": str, "paired_ms": int }
{ "event": "failed", "reason": str }
```
After the `sas` event, the process **blocks on one line of stdin**: it reads
until newline and proceeds (seals + sends the DEK) only if that line is
`confirm` (case-insensitive). Anything else, or stdin closing (EOF), fails the
ceremony closed and emits `{"event":"failed",...}` without ever sending the
DEK. The GUI writes `confirm\n` to the child's stdin after the human taps
"match" having compared the six words on both screens — this is the real MITM
backstop, so it must gate on an actual tap, never be sent automatically.

## Known gaps vs. the DTO fields

Emitted with an honest constant/empty value, not fabricated (also noted inline in
`json.rs` and in `PROTOCOL.md`):

- `account.health` / `detail` / `last_used_ms` — no token-expiry model →
  `healthy` / null.
- `account.id` — equals the label (the store keys accounts by unique label), so
  `account rotate/remove --id <id>` takes the label.
- `pair.name` — fixed `"iPhone"`; the ceremony captures no device name.
