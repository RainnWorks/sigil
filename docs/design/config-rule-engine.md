# Config rule engine: generic if-this-then-that gating

Status: design + first implementation increment (rust-core, 2026-07-06).
Supersedes the per-command `CommandStore` (`commands.json`) with a
rule/source model. Constitution: `docs/design/latch-design-brief.html` and the
ANY-CLI PIVOT / INVOCATION MODEL notes in the project memory.

## Why

Latch is "gated env-var injection + phone approval for ANY CLI", not an `op`
tool. The core must have **zero** concept of 1Password. Until now two things
baked `op` into the core gating path:

1. `CommandConfig::default_op()` / `CommandStore::resolve("op")` returned a
   built-in 1Password config, so the core *knew* about `op`.
2. `fulfill` sniffed `--vault` out of the argv (`parse_vault`) to route a
   1Password account — argv semantics only `op` has.

Both are removed. `op`-ness now lives entirely in **user-authored rules** plus
the `op` provider plugin (`provider::OpProvider`). The core evaluates generic
rules against an invocation and, on a match, gates then injects from a named
source. Nothing in the rule vocabulary or the engine names `op`.

## Package & binary layout (landed)

One workspace package (`crates/latch`). Its `[lib]` is the shared core
`latch_core` — the rule engine, providers, gating/daemon, keystore, transport,
and the proxy module all live here, so both binaries call one implementation
with zero duplication. Two thin `[[bin]]` targets in `src/bin/`:

- **`latch`** — the lean hot-path + runtime binary agents and launchd invoke:
  the `latch <cmd>` gating primitive, the transparent shim multicall, `latch
  proxy …` (the auto-aliasing proxy), `latch run`, and the runtime verbs
  (daemon, status, pair, lease, ssh, …). Reserved verbs in this binary: the
  runtime set + `run` + `proxy` + `config` (hint-only, points at `latch-config`);
  everything else is the `latch <cmd>` primitive.
- **`latch-config`** — the configuration-management CLI the desktop shells out
  to under the hood: `source`/`rule`/`list`/`export`/`import`, plus the
  config-ish mutations (`account`, `settings`, `mac-approvals`, `wipe`).

The split moves the desktop's invocation from `latch config …`/`latch account …`
to `latch-config …` (source/rule/list/export/import + account/settings/
mac-approvals/wipe are now `latch-config` verbs, no `config` prefix). That is an
outward-facing contract the Mac app (`apps/mac`) depends on; updating it is a
separate task. Because `config`/`account`/`settings`/`wipe` are no longer
reserved in the lean `latch` binary, a program literally named any of those is
now gateable as `latch <that-name> …`; the escape hatch for a residual reserved
runtime verb is `latch run -- <cmd>`.

## Two CLIs, one binary

The multicall `latch` binary keeps its two faces; this change sharpens the split:

- **Gating CLI** — `latch <cmd> [args]`, the transparent shim alias, and
  `latch run -- <cmd>`. On an invocation the daemon evaluates the configured
  rules; the first matching rule gates the command on the phone, injects its
  source's env, and execs+streams. No rule matches -> refuse and point at
  `latch config` (never run ungated: a silent pass-through is false security).
- **Configuration CLI** — `latch config …`. A provider-agnostic config layer
  that authors rules and sources. It is the owned primitive; the **desktop app
  is a client** that shells out to it (or, later, speaks the same JSON). JSON
  in/out mirrors the daemon-control-protocol philosophy: one machine interface,
  no redundant flags.

## Data model

Persisted at `~/.latch/config.json` (plaintext by design — it holds routing,
never a secret; it must be readable while the daemon is inert). Two collections:

```jsonc
{
  "version": 1,
  "sources": [
    { "name": "rowm-op", "provider": "1password", "account": "Rowm" },
    { "name": "gcloud-env", "provider": "env-file", "path": "/home/tom/.gcloud.env" }
  ],
  "rules": [
    {
      "name": "op-read",
      "match": { "command": "op", "argv_contains": ["read"] },
      "action": { "source": "rowm-op", "risk": "routine" }
    }
  ]
}
```

### Source

A named, pluggable `SecretProvider` configuration referenced by rules. `op` /
1Password is one provider type among peers; `env-file` is the reference peer.

| field      | meaning                                                             |
|------------|--------------------------------------------------------------------|
| `name`     | unique id a rule's action references                               |
| `provider` | provider id in the registry (`1password`, `env-file`, …)           |
| `account`  | optional: the 1Password account label to route (op provider)       |
| `path`     | optional: the env-file path whose KEY=VALUEs are injected          |

`account`/`path` are the provider-specific knobs. New provider types add their
own optional fields; the engine never interprets them, it hands the whole source
to the provider. Nothing here is op-only in the *engine's* eyes.

### Rule = Match -> Action

Rules are an **ordered list; first match wins**. Ordering is authorship order
(edit via export/import). A rule:

| field    | meaning                                             |
|----------|-----------------------------------------------------|
| `name`   | unique human label / id                             |
| `match`  | the conditions (below)                              |
| `action` | what to do on a match                               |

**Match** — composable conditions on the invoked command + argv. All present
conditions must hold (AND). A match with **no** conditions never matches (fails
closed rather than gating everything).

| condition       | matches when …                                                   |
|-----------------|------------------------------------------------------------------|
| `command`       | argv[0] equals this string                                       |
| `subcommand`    | argv[1] equals this string                                       |
| `argv_contains` | every listed needle is a substring of some argv token            |
| `flag_present`  | every listed `--flag` appears (as `--flag` or `--flag=…`)        |
| `flag_equals`   | every `{flag,value}` appears (`--flag=value` or `--flag value`)  |
| `arg_regex`     | (deferred, see below) a regex matches the joined args            |

**Action** — require phone approval, then inject the named source's env, then
exec:

| field         | meaning                                                          |
|---------------|------------------------------------------------------------------|
| `source`      | the `Source.name` to inject from                                 |
| `risk`        | `routine` \| `elevated` \| `critical`; scales approve friction   |
| `timeout_sec` | optional per-rule approval timeout; falls back to settings       |

### The op use case, with zero op in the core

> "if the command is `op` and argv contains `read` then gate + inject the SA
> token from source `rowm-op`"

```jsonc
{ "name": "op-read",
  "match": { "command": "op", "argv_contains": ["read"] },
  "action": { "source": "rowm-op", "risk": "routine" } }
```

The engine matches strings; the `1password` provider (named only by
`sources[].provider`) knows what a token is and how `op` resolves `op://` refs.
The core never parses `op://`, never reads `--vault`, never special-cases `op`.

## Gating path (daemon `fulfill`)

1. `Config::resolve(argv)` -> the first rule whose match holds, resolved against
   its source into a `ResolvedAction { provider, source_path, account, risk,
   timeout_sec }`. `None` -> refuse with `latch config` guidance.
2. Look up the provider by id in the `ProviderRegistry`.
3. If the provider `needs_account()` (op), route the account by the **source's
   `account` label** (not by sniffing argv). `AccountStore::route` now matches an
   account by label OR vault, single-account fallback unchanged. v2 threshold
   routing matches by label too.
4. Gate on the phone (or lease short-circuit for account-backed providers).
5. On approval, decrypt the token / read the env-file, run the provider on the
   caller's fds. Invariants #1/#2/#7 unchanged: token ciphertext at rest, op
   child stdout splices to the client fd, every failure fails closed.

`parse_vault` is deleted from the core. Account selection is configuration, not
argv archaeology — which is exactly the generalization.

## Configuration CLI surface

All verbs take `--json` for the machine path (the desktop shells out for these):

```
latch config source add <name> --provider <id> [--account <label>] [--path <file>]
latch config source list
latch config source remove <name>

latch config rule add <name> --source <src>
      [--command <c>] [--subcommand <s>]
      [--argv-contains <needle> ...] [--flag <f> ...] [--flag-eq <f>=<v> ...]
      [--risk routine|elevated|critical] [--timeout <sec>]
latch config rule list
latch config rule remove <name>

latch config export          # whole config as JSON on stdout
latch config import          # replace whole config from JSON on stdin
latch config list            # human summary of sources + rules

# Convenience desugar (keeps the old one-liner + the docs/tests that use it):
latch config add <cmd> --provider <id> [--source <path>] [--account <label>] [--risk r]
      == source add <cmd> + rule add <cmd> matching command==<cmd>
```

The daemon only **reads** the config (loaded at arm time); a compromised
always-on daemon must not be able to rewrite which commands are gated. Re-run
`latch restart` to apply a change. This is unchanged from the old store.

## Persistence & migration

- New store: `~/.latch/config.json`.
- On load, if `config.json` is absent but the legacy `commands.json` exists, it
  is migrated in memory (and can be written on first mutation): each legacy
  `CommandConfig{command,provider,source,account,risk}` becomes a `Source`
  (named after the command) + a `Rule` matching `command == <cmd>`. To preserve
  the historical implicit behavior, if no legacy entry named `op` exists, a
  default `op` rule + `1password` source (no account) is synthesized — so Tom's
  existing zero-config `op` keeps working after upgrade. The legacy file is left
  in place (non-destructive); `latch wipe` removes both.

## Migration: verb moves (lean `latch` vs `latch-config`)

The split is a HARD CUT — no back-compat aliases in the lean binary (aliases
would re-reserve the very verbs we moved off it, defeating gateability). The
exact moves, so retargeting the Mac app (#42) is mechanical:

| old invocation                    | new invocation                         |
|-----------------------------------|----------------------------------------|
| `latch config <verb>`             | `latch-config <verb>` (no `config` word)|
| `latch config source …`           | `latch-config source …`                |
| `latch config rule …`             | `latch-config rule …`                  |
| `latch config list` / `export` / `import` | `latch-config list` / `export` / `import` |
| `latch config add <cmd> …`        | `latch-config add <cmd> …`             |
| `latch account <verb>`            | `latch-config account <verb>`          |
| `latch settings <verb>`           | `latch-config settings <verb>`         |
| `latch mac-approvals …`           | `latch-config mac-approvals …`         |
| `latch wipe [--force]`            | `latch-config wipe [--force]`          |
| `latch <anything-else>`           | unchanged (lean `latch`)               |

Everything else (`status`, `daemon`, `doctor`, `pair`, `unpair`, `qr`,
`start`/`stop`/`restart`, `lease`, `lockdown`, `approve`, `deny`, `history`,
`pending`, `ssh`, `sshagent`, `setup`, `shim`, `run`) stays on the lean `latch`
binary. Proxy management (`proxy add|remove|list|status|doctor|env`) lives on
`latch-config`, NOT reserved in the lean binary, so a program named `proxy` is
gateable as `latch proxy …`.

## Security notes (for the security-reviewer, not self-certified)

- **Matched-but-broken rule fails closed (sec-review Note B):** if the first rule
  whose match holds names a source that no longer exists, `resolve` returns
  `None` (refuse) — it does NOT fall through to a later, broader rule. Falling
  through would be a fail-open downgrade of a hand-edited config to an unintended
  broader route. Invariant #5 over convenience.
- **Label/vault routing collision (sec-review Note A):** account routing matches
  an account by its **label OR one of its vault names** (`.find`, first hit
  wins). If one account's label equals another account's vault name, a routing
  hint that string is order-dependent (the account earlier in the store wins).
  This is a Tom-authored-config misconfiguration, not an exploit (both accounts
  are the operator's own, and the approval is still gated), but it is surprising.
  `latch-config account add` warns when a new account's label collides with an
  existing account's vault (or vice versa) so the ambiguity is visible at
  authoring time. Prefer account labels that are not also vault names.

- Inert-at-rest (#1), secrets-bypass-daemon (#2), fail-closed (#7) are untouched:
  the config only chooses *which* provider/source/risk; the token and env
  handling are the same code paths as before.
- **Routing change to review:** account selection moved from argv `--vault`
  sniffing to the source's `account` label, and `route`/`route_exact` now match
  by label OR vault. This touches the v2 threshold routing (`route_exact`), which
  is security-sensitive. It is additive (a superset of the old vault match) and
  covered by tests, but wants an independent adversarial pass before it is called
  sound.
- **`arg_regex` is deferred:** implementing it needs the `regex` crate, a
  non-trivial dependency for a "copy a binary" install (opt-level=z, five
  cross-compiled targets). The field is modeled and round-trips, but a config
  that sets it is rejected at `rule add` time until the dependency is approved.
  Decision needed from Tom: add `regex`, or ship the four deterministic
  conditions (which already cover the op use case) only.
- An all-empty match never matches (fail closed), so a malformed/partial rule
  cannot silently gate every command.
