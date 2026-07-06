# Auto-aliasing proxy: transparent, anonymous CLI interception

Status: design (rust-core / proxy-shim, 2026-07-06). Implements task #40.
Constitution: `docs/design/latch-design-brief.html` and the INVOCATION MODEL /
ANY-CLI PIVOT notes. Companion: `docs/design/config-rule-engine.md` (config-cli
owns the rule engine this proxy gates through).

## Goal

Let a caller that cannot be modified (an AI agent, the rowm launcher's bare
`op item get`, `git` reaching the SSH agent) hit Latch **transparently**. The
caller runs `op`; it sees `op` behaving normally: it blocks until the phone
approves, streams the real output, and exits with the real exit code. On deny it
"fails" with a non-zero exit that the caller cannot attribute to Latch. The
caller never learns Latch exists. That anonymity is the property Tom wants.

The mechanism is a Latch-managed **proxy directory** placed first on `PATH`,
holding one thin alias per intercepted command. The alias re-enters the multicall
binary as `latch <cmd> "$@"`, which gates on the phone and then execs the *real*
`<cmd>`. Everything is managed by the CLI: `latch proxy add|remove|list|status|
doctor|env`.

## What already exists (build on, do not reinvent)

The current tree already has most of the primitive:

- **Multicall dispatch** (`main.rs`): `argv[0]` stem other than `latch` is a
  transparent alias that re-enters as `latch <stem> <args>` via
  `shim::dispatch`. `latch <cmd>` (non-reserved verb) and `latch run -- <cmd>`
  funnel to the same `dispatch`.
- **The alias is a symlink**, not a shell script: `setup::install_shim_for(cmd)`
  symlinks `~/.latch/bin/<cmd>` at the running binary. We keep symlinks on
  Unix; they are strictly better than a `#!/bin/sh exec latch <cmd> "$@"`
  wrapper (zero shell spawn, cold start near zero, `argv[0]` preserved). The
  POSIX-script form is the fallback for no-symlink filesystems and the model for
  the Windows `.cmd` shim.
- **Real-binary resolution** (`paths::find_real`): walks `PATH`, skipping any
  candidate that canonicalises to our own binary. Because every alias is a
  symlink to the multicall binary, this already excludes every alias in any
  directory. This is the primary recursion guard (see below).
- **Drift detection** (`paths::ShimStatus`, `path_order`): today hardwired to
  `op`; this design generalises it to an arbitrary command for `proxy doctor`.
- **PATH durability** (`setup::ensure_profile_path`): edits one shell profile
  (zsh `~/.zshrc` or bash `~/.bash_profile`) with an idempotent managed block.
  This design widens it to bash-login + `.profile` + fish and adds the agent
  story.
- **launchd PATH** (`service.rs`): the daemon plist pins `PATH` with
  `~/.latch/bin` first, so GUI-launched / launchd-descended tools resolve the
  alias ahead of the real binary without sourcing an rc file. This is the macOS
  half of the agent story.

So this task is mostly: (1) rename/reframe the `shim` surface as `proxy` with the
fuller CLI, (2) generalise drift detection beyond `op`, (3) add the recursion
env-guard backstop, (4) widen PATH durability + write the agent story, (5) design
Windows, (6) close the stdin/TTY transparency gap.

## Terminology

- **proxy directory**: `~/.latch/bin`, first on `PATH`. Latch-managed.
- **alias** (a.k.a. shim): one symlink in the proxy dir, named for the command
  it intercepts, pointing at the multicall binary. "shim" stays the internal
  word for the individual alias; **`proxy` is the user-facing verb**.
- **real binary**: the `<cmd>` a shell would resolve with the proxy dir removed
  from `PATH`. Never moved, never modified.

## The two paths

```
  caller (agent, launcher, git)
        |  runs `op read op://...`   (argv[0]=op)
        v
  ~/.latch/bin/op  --- symlink --->  latch multicall binary
        |  argv[0] stem = "op" != "latch"  => alias mode
        v
  latch op read op://...            (shim::dispatch)
        |
        +-- daemon UP:  forward argv+cwd+caller fds over the control socket;
        |               daemon evaluates config rules, gates on the phone,
        |               on approve spawns the REAL op (find_real, proxy dir
        |               excluded) with its stdout spliced to the caller fd,
        |               mirrors the child exit code back.  On deny: non-zero.
        |
        +-- daemon DOWN: exec the REAL op directly (find_real), inheriting all
                         fds and the TTY. Transparent; nothing to gate against.
```

Note the asymmetry: with the daemon **up**, a protocol fault fails **closed**
(exit 70), never a silent ungated run. Only a **down** daemon takes the
transparent-exec fallback, matching "behave exactly like the real tool when Latch
is off."

## Hard problem 1: recursion

`~/.latch/bin/op` -> `latch op` -> must find the *real* `op`, never the alias.
Two independent guards, defence in depth:

**(a) Resolution-time exclusion (primary, airtight).** `find_real(cmd)` resolves
the real binary from `PATH` while excluding the proxy. Two exclusion rules,
either sufficient:

1. Skip any candidate whose canonical path equals `current_exe()` (the running
   multicall binary). Every alias is a **symlink** to it, so `canonicalize`
   resolves the alias to our binary and excludes it in any directory. This is
   *upgrade-proof*: it compares against the binary actually running, so a
   rebuilt/moved Latch still excludes its own aliases. (`canonicalize` resolves
   symlinks, not hard links: a hard *copy* of the binary planted under a
   command's name is not caught here, only by rule 2 if it is inside the proxy
   dir, or by the depth fuse otherwise. That is an exotic case; the real aliases
   are always symlinks.)
2. Skip any candidate inside the proxy directory (`~/.latch/bin`) outright. This
   also catches a future non-symlink alias (a script, or a hard copy of the
   binary) that rule 1 would miss.

Re-resolving at **run time** (not trusting a path recorded at add time) means a
brew/asdf/mise upgrade that moves the real binary still works.

**(b) Env-guard depth fuse (backstop only).** A bug in (a) that returned an alias
would fork-bomb. To convert an infinite loop into a bounded, fail-closed error,
Latch carries an inherited counter `LATCH_PROXY_DEPTH`. The enforcement point is
the **alias's dispatch entry**: on entry Latch reads the counter and, past a
generous bound (proposed 40), aborts with exit 70 and a diagnostic; otherwise it
sets `LATCH_PROXY_DEPTH = n+1` on whatever it execs next.

Because every loop passes *through an exec* that inherits env, this one entry
check bounds both loops:

- **Daemon down:** the alias `exec`s the real tool (or, in the bug, another
  alias). The env var propagates by ordinary exec inheritance, so a re-entering
  alias sees `n+1` and eventually trips the fuse.
- **Daemon up:** the daemon spawns the real tool. For the up-path to be bounded
  the daemon must set `LATCH_PROXY_DEPTH = n+1` on the child it spawns (a small
  daemon-side addition, coordinated separately); if that child is erroneously an
  alias, its dispatch-entry check trips the fuse *before* it reconnects to the
  daemon. The socket frame does not need to carry the counter, because the loop
  always re-enters via a spawned child that inherits env.

Legitimate nesting (a gated `op` runs a script that runs a gated `gcloud` that
runs a gated `op`) is realistically < 5 deep; a resolution bug hits 40 in
milliseconds. The counter is deliberately *not* reset when execing the real tool,
because Latch cannot distinguish "the real tool" from "another alias" without
solving the very question the guard exists to backstop; a large bound absorbs
real nesting instead.

The env-guard is a fuse, not the mechanism. Guard (a) is the mechanism.

**Wrapper real binaries (brew/asdf/mise).** If the first non-Latch resolution is
itself a wrapper (a mise/asdf shim), Latch execs it and lets it do its own
indirection to the real tool. mise/asdf shims resolve the tool directly, never
back through `~/.latch/bin`, so no loop. Latch's contract is "exec the first
non-Latch resolution"; version-manager indirection past that point is theirs.

## Hard problem 2: the right binary among many PATH entries

Package managers scatter binaries: Homebrew (`/opt/homebrew/bin` on Apple
Silicon, `/usr/local/bin` on Intel), system dirs, asdf (`~/.asdf/shims`), mise
(`~/.local/share/mise/shims`), npm-global (`~/.npm-global/bin`), Scoop
(`~/scoop/shims`) + Chocolatey on Windows.

Strategy: **resolve what the shell would have run.** `find_real` walks the
caller's actual `PATH` minus the proxy dir and returns the first match. That is,
by construction, the binary the caller would have executed without Latch. No
heuristic ranking, no guessing.

- **Resolve-and-record at add time.** `latch proxy add <cmd>` runs `find_real`
  and shows the resolved path. It records it (for `list`/`doctor` display and
  for change-detection), but run time re-resolves so upgrades survive.
- **Never guess silently.** `add`, `list`, and `doctor` all print exactly which
  real binary each proxy targets. If nothing resolves, `add` warns loudly (the
  alias would exit 127 whenever the daemon is down).
- **Override.** `latch proxy add <cmd> --real <path>` pins an explicit real
  binary (recorded and used directly at run time, opting out of re-resolution).
  The tradeoff is documented: a pin defeats upgrade-survival but disambiguates
  when several `<cmd>` sit on `PATH`.

## Hard problem 3: never clobber the real binary

Latch only prepends a directory and changes resolution *order*. The real binary
is never moved, renamed, wrapped, or written. `find_real` opens it read-only to
resolve it and nothing else.

Detect and warn:

- `proxy doctor` flags **a real binary preceding the proxy on PATH** (the alias
  lost; requests would reach the real tool ungated). This is the security-
  relevant drift, already modelled by `ShimStatus::issue`.
- `proxy doctor` flags **an alias with no gating rule**. If `proxy add op` runs
  but no rule gates `op`, the alias refuses every call (fail-closed, correct) and
  the real `op` becomes uncallable through that shell. doctor surfaces this as
  "alias <cmd> has no gating rule; it will refuse all calls; add one with
  `latch config ...`, or `latch proxy remove <cmd>`."
- `proxy add` warns when the resolved real binary is in a surprising location, or
  when several candidates exist, and asks for confirmation (or `--force`).

## Hard problem 4: PATH durability and the agent story

Two audiences: interactive shells (source rc files) and **agents/daemons that
inherit env from a parent without sourcing any rc** (the real use case).

**Interactive shells: idempotent managed blocks.** One marker-bracketed block per
relevant startup file, written only if the proxy dir is not already present:

| shell | files edited | line |
|-------|--------------|------|
| zsh   | `~/.zshrc`   | `export PATH="$HOME/.latch/bin:$PATH"` |
| bash  | `~/.bashrc` and `~/.bash_profile` (or `~/.profile`) | same |
| fish  | `~/.config/fish/config.fish` | `fish_add_path --prepend $HOME/.latch/bin` |

Already-running shells need a re-source; `proxy add` says so and prints the env
line for the current session.

**Agents (no rc sourced): three delivery routes, in order of preference.**

1. **launchd (macOS), already wired.** The daemon plist pins `PATH` with the
   proxy dir first (`service.rs`). Anything launchd starts, or any GUI app whose
   env descends from launchd, inherits the shim-first PATH with no rc file. This
   is the native macOS answer for agents started by the daemon or by the GUI.
2. **The printable env line: `latch proxy env`.** Prints the prepend line for the
   current shell (`--shell zsh|bash|fish|nu`) so it can be dropped into whatever
   launches the agent: a launchd/systemd unit's environment, a Docker `ENV`, the
   agent runner's own PATH, a `.env`. This is the universal answer: *put the
   proxy dir first in the environment the agent inherits.* Per-launcher recipes:
   - launchd job: `EnvironmentVariables` -> `PATH` (as the daemon plist does).
   - systemd --user unit: `Environment=PATH=%h/.latch/bin:...` or a drop-in.
   - rowm launcher (Node/Bun): prepend the proxy dir to the env it spawns
     children with, or to the shell that launches it.
3. **Login-shell env.** A user who wants it everywhere for their own account can
   add the prepend to `~/.profile` (POSIX login) so any login-derived process
   inherits it. `launchctl config user path` (system-wide, persistent, sudo) is
   documented but not automated: too broad a blast radius for a personal tool.

`proxy status` reports both halves: is the proxy dir on `PATH` **in this shell**,
and is it present in the launchd/agent environment (best-effort: inspect the
daemon plist and, on request, a target pid's environment).

## Hard problem 5: cross-platform

- **macOS / Linux (first-class).** Symlink aliases in `~/.latch/bin`; rc-block +
  launchd/systemd PATH as above. Linux has no launchd: the systemd --user unit
  carries `Environment=PATH=`; document it beside the plist.
- **Windows (designed, flagged/stubbed).** A symlink-to-multicall is unreliable;
  use a per-command `<cmd>.cmd` shim (`@echo off` + `latch %~n0 %*`) or a hard
  copy of the exe named `<cmd>.exe`. PATH persists via the user environment
  (`HKCU\Environment` / `setx`), not an rc file. Package-manager awareness: Scoop
  (`~/scoop/shims`), Chocolatey (`%ProgramData%\chocolatey\bin`). `find_real`
  gains `.exe`/`.cmd`/`PATHEXT` resolution. v1 returns a clear "windows proxy not
  yet implemented" rather than a half-working install.
- **fish / nushell noted.** fish uses `fish_add_path`; nushell mutates
  `$env.PATH` in `config.nu`. `proxy env --shell fish|nu` emits the right form.

## Hard problem 6: transparency / anonymity

The alias is a symlink, so the process the caller spawns is named `op`; `argv[0]`
is preserved. For behavioural indistinguishability:

- **stdout / stderr / exit code:** already faithful. Daemon-up splices the real
  child's stdout to the caller's fd and mirrors the exit code; daemon-down execs
  and inherits everything.
- **stdin / TTY (GAP to close, config-cli-owned):** the daemon-up forward
  currently passes only stdout+stderr fds, not **stdin**. An interactive tool
  that reads stdin (a prompt, `op inject` reading a template) breaks under the
  daemon-up path. Fix: pass the caller's stdin fd too (Run frame carries three
  fds, not two) and wire it to the child's stdin in the daemon's Run handler.
  Passing the real fds (which may be a TTY) also gives the child the controlling
  terminal, so colours and prompts work. **This lands with config-cli** (it owns
  `daemon.rs`), and the splice **MUST preserve invariant #2**: caller-fd ->
  child-fd by fd passing, the daemon never reading or buffering the bytes, the
  same discipline that keeps op's stdout out of daemon memory. It is
  invariant-adjacent, so it takes an **independent security-reviewer pass**.
- **On deny (already implemented, shim side quiet):** the daemon's `fail_closed`
  returns **exit code 1** and the shim exits silently with it (no Latch-branded
  stderr on a clean `Exit`), so the caller just sees a failed command. Today the
  daemon also writes `"request denied\n"` to the caller's stderr fd. That string
  is not Latch-branded, but it is a synthetic line a real tool would not emit, so
  it is a mild anonymity residual. Whether to keep it (a helpful signal for a
  human at a terminal) or drop it (maximal anonymity for an agent caller, since
  the human already sees the denial on the phone and in `latch history`) is a
  **daemon-side decision owned by config-cli**; recommendation: drop it, or gate
  it behind a TTY check, defaulting to silent for non-interactive callers. The
  exit code and the shim's silence need no change.
- **Residuals (anonymity is best-effort, not a security boundary):** a caller
  that inspects its own resolved `PATH` sees `~/.latch/bin`; a protocol-fault
  error path currently prints a string containing "latch"; blocking latency
  during approval is observable. These are enumerated for the security-reviewer;
  none is load-bearing for any invariant. A future `--quiet` could strip the
  Latch word from the fault path.

## CLI surface

The management verbs mount on the **`latch-config`** binary, not the lean
gating `latch` binary. Rationale (Tom, 2026-07-06): a reserved `proxy` verb on
the gating binary would make a real program named `proxy` ungateable, since
`latch <cmd>` reserves its verbs. Keeping the gating binary's reserved surface
minimal means `latch <anything>` can gate anything; the management surface lives
on `latch-config`, which is never on the `latch <cmd>` hot path.

```
latch-config proxy add <cmd> [--real <path>] [--force]
      install the alias, ensure the proxy dir is on PATH (edit rc files for the
      detected shells), record + display the resolved real binary, and print the
      current-session env line. Warns if <cmd> has no gating rule, if a real
      binary already precedes the proxy, or if resolution is ambiguous (--force
      to proceed).

latch-config proxy remove <cmd> [--purge]
      remove the alias. --purge also strips the managed PATH block if no aliases
      remain. Never touches the real binary.

latch-config proxy list
      every installed alias: name, resolved real target, and gating-rule status
      (gated / NO RULE).

latch-config proxy status
      is the proxy dir first on PATH in THIS shell, and present in the
      launchd/agent environment. The at-a-glance "is interception live" view.

latch-config proxy doctor [<cmd>]
      deep diagnosis per alias: PATH order (proxy vs real), which real binary
      resolves, shadowing/clobber warnings, gating-rule coverage, and the
      recursion-guard state. Reuses the generalised ProxyStatus.

latch-config proxy env [--shell zsh|bash|fish|nu]
      print the PATH-prepend line for the current (or named) shell, for the
      session or an agent launcher's environment.
```

The verb handlers are thin; they call the shared-core proxy library
(`ProxyStatus`, `list_aliases`, `ensure_path_in`, `env_line`, install/remove).
`latch shim install|add` remain as thin, hidden back-compat aliases mapping onto
`proxy` (existing tests, `setup`, and docs call them); when the bins split they
stay wherever `setup` lives.

## Package layout and coordination with config-cli

Task #38 (config-cli) restructures the workspace into a shared core lib plus
separate thin `[[bin]]` targets (lean `latch` gating hot-path + `latch-config`
management). The proxy splits by **role**, not as one unit:

- **Proxy RUNTIME stays in the lean `latch` binary**: the installed alias (a
  symlink named `<cmd>` pointing at the `latch` runtime binary, `argv[0]`
  dispatch), `find_real` resolution, and the `LATCH_PROXY_DEPTH` fuse. This is
  the hot path a proxied `op` hits; it must be reserved-verb-minimal so
  `latch <anycmd>` can gate anything.
- **Proxy MANAGEMENT moves to `latch-config`**: the `proxy add|remove|list|
  status|doctor|env` verbs (reserved-verb rationale above). config-cli mounts my
  proxy command module under `latch-config`.
- **The reusable logic** (`ProxyStatus`, `list_aliases`, PATH management,
  `env_line`, `find_real`) lives in the shared core lib so both binaries call it.

**Critical: the alias symlink target.** When `latch-config proxy add op` installs
the symlink, its target must be the **`latch` runtime binary**, not the running
`latch-config` binary. Today (single multicall binary) `current_exe()` is
correct; post-split the installer must resolve the sibling `latch` binary
(e.g. `current_exe().parent().join("latch")`). Symmetrically, the drift detection
(`ProxyStatus`, `list_aliases`) must compare an alias's canonical target against
the **runtime** binary, not the management binary. This design centralises "the
path an alias should point at" in one helper (`proxy::alias_target`) so the split
flips it in exactly one place.

Open coordination points (sent to config-cli):

1. **Final core-lib / bin names**; mount my proxy command module under
   `latch-config`; confirm the sibling `latch` runtime binary path for the alias
   target.
2. **A config-coverage predicate.** `proxy add`/`doctor` need "is `<cmd>` gated
   by any rule?" Proposed helper on the new engine:
   `Config::gates_command(cmd) -> bool` = any rule whose `match_.command ==
   Some(cmd)`. I will consume it rather than reimplement rule matching. (Today
   `shim_add` uses the *old* `CommandStore::resolve`; the migration to `Config`
   must update that call.)
3. **Proxy dir + PATH ownership.** `~/.latch/bin` stays the single proxy dir and
   the PATH story lives in my proxy module, not duplicated in the config CLI.
4. **Two daemon-side gaps config-cli owns** (it owns the `daemon.rs` Run handler;
   see the transparency and recursion sections):
   - splice the **caller's stdin** to the tool child's stdin, so interactive
     tools work. **MUST preserve invariant #2** (secret bytes never enter daemon
     memory): stdin splices caller-fd -> child-fd by the same fd-passing
     discipline as stdout, with the daemon never reading or buffering it. This is
     invariant-adjacent and needs an **independent security-reviewer pass**.
   - set `LATCH_PROXY_DEPTH = n+1` on daemon-spawned tool children, so the
     up-path recursion fuse is bounded.

## Security notes (for the security-reviewer, not self-certified)

PATH manipulation and binary resolution are a hijack surface. Points to review:

- **find_real correctness** is the whole recursion + no-clobber story. Both
  exclusion rules (canonical == current_exe; inside the proxy dir) must hold; a
  regression that returns an alias fork-bombs (bounded by the depth fuse) or, in
  the daemon-up path, could loop the daemon spawning aliases. Adversarial cases:
  a symlink chain, a `PATH` containing the proxy dir twice, a real binary that is
  itself a symlink into the proxy dir, a `<cmd>` copy (not symlink) of the Latch
  binary planted in the proxy dir.
- **Order drift is a gate bypass**, not cosmetic: a real binary before the proxy
  on PATH routes an intercepted command ungated. doctor must treat it as an
  error, and the daemon's startup shim-check already warns on it for `op`;
  generalise that to every configured alias.
- **The env-guard bound (40)** is a liveness fuse, not a security control; it
  must never be the thing standing between a loop and a gate.
- **The stdin splice** (config-cli-owned) is the one proxy change that touches an
  invariant: invariant #2 forbids secret bytes entering daemon memory, so stdin
  must move caller-fd -> child-fd by fd passing with no daemon-side read/buffer.
  A buffering implementation is a critical finding. Independent review required.
- **Anonymity is best-effort** (residuals above) and is explicitly *not* an
  invariant; nothing security-relevant may come to depend on the caller being
  unable to detect Latch.
- The proxy touches no key, token, DEK, envelope, or lease. It changes *which
  binary runs* and *whether a run is gated*; the gate itself, secret handling,
  and fail-closed behaviour are unchanged upstream code paths.

## Increment plan

1. Design doc (this file). [done]
2. Coordinate package layout + `gates_command` predicate with config-cli. [in
   flight]
3. Additive `proxy.rs` in the core lib: generalised `ProxyStatus::detect(cmd)`,
   PATH management for zsh/bash/fish + `.profile`, `proxy env` line generation,
   install/remove/list over the existing `setup`/`paths` helpers, unit tests.
   Non-conflicting with config-cli's in-flight CLI edits.
4. Recursion env-guard (`LATCH_PROXY_DEPTH`) in the shim dispatch. [proxy-owned]
5. [done] Mounted `proxy add|remove|list|status|doctor|env` under `latch-config`
   (`cli::run_config`), flipped `alias_target` to the sibling `latch` runtime
   binary, consumed `Config::gates_command` for coverage. `shim` stays a hidden
   back-compat alias on the lean binary.
6. Close the stdin/TTY transparency gap in the daemon Run handler (coordinate
   with the daemon owner).
7. Windows: implement `.cmd`/`.exe` shims + user-env PATH, or ship the clear
   "not yet implemented" stub.
8. Security-reviewer pass on find_real + PATH order + the recursion guard.
</content>
</invoke>
