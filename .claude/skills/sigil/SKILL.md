---
name: sigil
description: >
  Operate Sigil, the phone-gated command interceptor, on the human's behalf.
  Use this skill when: (1) the human asks anything about Sigil, gating a CLI,
  or phone approvals, (2) a command fails with a Sigil/approval/gate error,
  (3) setting up or repairing the Sigil daemon, (4) sealing environment
  secrets for a gated command, (5) serving or routing SSH keys through the
  Sigil agent, (6) diagnosing why an approval never reached the phone.
---

# Operating Sigil

Sigil is a phone-gated command interceptor: it intercepts matched commands,
requires an approval on the human's phone, then runs them, optionally
injecting Sigil-stored secrets as environment variables. You are the
OPERATOR: you keep the daemon healthy, author gates and rules, wire SSH, and
explain state. The human does exactly two things you must never try to do for
them: approve on the phone, and type secret values.

## The one rule that outranks everything

**You must never see, receive, echo, or log a secret value in plaintext.**

- Never ask the human to paste a secret into the chat. If they paste one
  anyway, tell them to rotate it; do not use it.
- Sealing a value is always a pipe THE HUMAN runs in their own terminal. You
  write the command with a placeholder; they substitute the value:

  ```sh
  printf '%s' "$THE_SECRET" | sigil-config source env set <source> --key <KEY>
  # or several at once, KEY=VALUE lines on stdin:
  sigil-config source env set <source> --stdin
  ```

- Values are write-once and sealed immediately (threshold cryptography; the
  daemon cannot open them without a phone approval). There is no read-back.
  Verify by structure, never by value: `sigil-config list` shows key NAMES
  only, and that is all you ever need.
- Do not run gated commands whose purpose is to print a secret to your own
  transcript (e.g. `op read` to stdout). Gated commands may resolve secrets
  INTO a child process; that is the product. The transcript is not a child
  process.

## The model (so you explain it correctly)

- **Gate, do not broker.** Sigil gates commands and can inject its OWN sealed
  secrets. It never holds other tools' credentials on their behalf; `op` (or
  any provider CLI) is just a gated command that does its own auth.
- **Inert at rest.** Sealed values on the Mac are ciphertext. Each approval
  makes the phone return a per-request partial; the daemon combines it with
  its local share, uses the key once, and zeroizes it.
- **Approve needs the phone's hardware biometrics; deny needs nothing.**
- **Everything fails closed.** A timeout, a missing rule, a dead relay: the
  command is refused, never silently allowed.
- **The phone is provider-blind.** Never describe it as a "1Password
  approver"; it approves opaque requests for any CLI.

## Habit zero: `sigil up`

Start EVERY Sigil task by running `sigil up`. It is the idempotent,
self-healing keystone: installs the binary to `~/.sigil/bin/sigil`, writes
and loads the launchd agent, heals a dead OR wedged daemon (a wedged daemon
looks alive to launchd but answers nothing; `up` detects it with a real
round trip and kickstarts), wires the `op` shim onto PATH, and reports
pairing. Exit 0 means healthy (things it fixed are still exit 0); exit 1
means something needs the human, and the report says what.

```sh
sigil up          # safe to run any time, repeatedly
sigil status      # the instrument panel
sigil doctor      # deeper diagnosis: shim drift, factor, relay, socket
```

Never manage the daemon by hand (`launchctl`, killing pids, deleting
sockets). If `up` cannot heal it, read the log and say what you found:
`~/.sigil/logs/daemon.err.log`.

## CLI surface map

Two binaries, one contract: `sigil` is the runtime (gating, daemon, ssh),
`sigil-config` is configuration (rules, sources, settings). Anything not a
reserved verb is the gating primitive: `sigil <cmd> [args]` runs `<cmd>`
gated.

```sh
# runtime
sigil up | status | doctor | history | pending
sigil pair --relay <url>       # pairing ceremony (HUMAN scans QR + compares words)
sigil lease list | lease revoke <prefix>
sigil lockdown [--clear]       # panic switch: deny and refuse everything
sigil ssh ... | sigil sshagent # SSH (below)

# configuration
sigil-config list                             # rules + sources (key names only)
sigil-config add <cmd> --provider env         # gate <cmd> with an inline env source
sigil-config rule add <name> ...              # fine-grained rule authoring
sigil-config source env set <name> --stdin    # HUMAN-run seal (see the rule above)
sigil-config source env unset <name> --key K  # drop one sealed key
sigil-config remove <name>
```

## Recipes

### Gate a CLI (no secrets involved)

A plain gate: the command runs only after a phone approval. The `env`
provider with no sealed values IS the plain gate (an inline env source with
nothing sealed injects nothing and just gates).

```sh
sigil-config add mytool --provider env   # source + rule: gate `mytool`
sigil mytool --do-something              # runs gated; phone shows caller/command
```

Note: `rule add ... --allow` is a PASSTHROUGH (no approval at all). Never
reach for it to reduce friction; it exists for deliberate allowlisting by
the human.

If the tool is called by other software that cannot be changed, install a
transparent alias so the bare name routes through Sigil:
`sigil shim add mytool` (the `op` alias is installed by `up` already).

### Gate a CLI and inject a secret

1. You create the structure:

   ```sh
   sigil-config add deploytool --provider env    # creates source + rule
   ```

2. The HUMAN seals the value in their terminal (you provide the command,
   with the placeholder, and never see the value):

   ```sh
   printf '%s' "$DEPLOY_TOKEN" | sigil-config source env set deploytool --key DEPLOY_TOKEN
   ```

3. Verify by structure: `sigil-config list` shows the rule and the key name.
4. From then on `deploytool ...` (or `sigil deploytool ...`) runs with
   `DEPLOY_TOKEN` injected, one phone approval per run (or a lease window if
   the rule is leasable).

An env source with declared keys but no sealed value degrades to a plain
gate (still phone-gated, injects nothing). That is dead config: either have
the human seal the value or remove the keys; never build around "unsealed".

### 1Password (or any provider CLI)

Do NOT store provider tokens in Sigil for injection; that is brokering.
`op` is a plain gated command: the human signs into `op` however they
normally do, and Sigil gates each invocation. `SECRET=$(op read "op://...")`
inside the human's own script is their business; you still never run it to
print into your transcript.

### SSH keys through the phone gate

The Sigil ssh-agent serves keys and gates EVERY signature on the phone (no
lease shortcut). Point clients at it:

```sh
sigil sshagent        # prints the socket; export SSH_AUTH_SOCK=<that path>
```

Key sources:

```sh
# a key file already on disk (private key stays on disk, read per signature)
sigil ssh add-file --path ~/.ssh/id_ed25519 --host github.com

# a threshold-STORED key: sealed at rest, opened per-signature with the phone.
# The private key is a secret value, so the HUMAN pipes it, never you:
cat ~/.ssh/id_ed25519_new | sigil ssh add-stored --host myserver.example

sigil ssh list
sigil ssh remove <path-or-id>
sigil ssh config --install     # routes the chosen hosts via ~/.ssh/config
```

Only unencrypted ed25519 keys are served (v1). After `sigil ssh config
--install`, `ssh myserver.example` transparently asks the phone.

### Diagnosis

- `sigil up` first, always. It heals the classic failures (dead daemon,
  wedged daemon, stale binary path, shim drift).
- A gated command hangs then fails: the approval timed out. Was the phone
  app open? Delivery is foreground-polling today; have the human open the
  app and retry.
- `ssh` signature requests: the daemon logs each one
  (`ssh-sign <label> · host <h> · data SHA256:... · pid <p>` in
  `~/.sigil/logs/daemon.err.log`). Log line present but no phone sheet means
  a delivery/phone problem, not a daemon problem.
- `sigil history` shows decided requests; `sigil pending` shows parked ones.
- Never weaken a gate to make automation smoother: no `--dev-insecure`, no
  auto-approve environment variables, no editing rules to bypass an
  approval. If a gate is in your way, that is the product working; ask the
  human.

## What only the human can do

- **Pairing**: `sigil pair` renders a QR and six words; the human scans and
  compares on the phone. You run the command and talk them through it; you
  cannot complete it.
- **Approvals**: on the phone, hardware biometrics. You wait.
- **Secret values**: typed or piped by the human, per the rule above.
