# Agent-operated Sigil

Status: agreed design, implemented in the same change set (2026-07-15).
Companion to `docs/design/secret-model.md` (gate, do not broker) and the design
brief. This document covers: the operating model, the `sigil up` keystone, the
daemon reliability fixes it depends on (with the root-cause diagnosis of this
week's outages), the SSH sign-path diagnosis, the Sigil skill, and the
keystore-default decision.

## 1. The operating model: three roles

Sigil becomes agent-operated. The division of labor is strict:

- **The human (Tom)** installs once and approves on the phone. Nothing else.
  No daemon management, no Start button, no terminal incantations. If the human
  ever has to think about the daemon, that is a bug.
- **An agent (Claude + the Sigil skill)** is the operator. It keeps the daemon
  healthy, writes gates and rules, wires SSH keys, explains state, and walks
  the human through the two things only a human can do: the pairing ceremony
  and typing a secret value. The agent NEVER sees a secret value in plaintext;
  it orchestrates structure only (section 5).
- **The daemon** is infrastructure: always on, self-healing under launchd,
  inert at rest, fails closed. It is not "started"; it is *ensured*.

Everything the agent does goes through the same CLI surface a human could use
(`sigil`, `sigil-config`), so there is no privileged agent path and nothing to
audit beyond the existing gate.

## 2. `sigil up`: the one keystone verb

`sigil up` is the single idempotent, self-healing primitive that makes "the
daemon is healthy" true, end to end. Everything calls it instead of managing
pieces: the Mac app on launch, the skill at the start of any Sigil work, the
human (at most once, after install). Running it twice in a row is free; the
second run reports all-ok and changes nothing.

The contract, in order, each step idempotent and reported as `ok` (already
true), `fixed` (made true), or `action needed` (needs the human):

1. **binary installed**. The running binary is copied to `~/.sigil/bin/sigil`
   when the bytes differ (unlink-then-copy, mode 0755). This is the
   install-stable home the plist and the shim aliases point at, so the daemon
   never again depends on a git checkout's `target/release` path surviving.
   Explicit contract: the binary you run `sigil up` from becomes the installed
   runtime. (Dev flow: `cargo build --release && target/release/sigil up`.)
2. **launchd plist current**. The rendered plist (stable program path,
   `RunAtLoad`, unconditional `KeepAlive` true, shim-first `PATH`) is compared
   byte-for-byte with `~/Library/LaunchAgents/works.rainn.sigil.plist`; a
   differing or missing file is written and the agent re-bootstrapped (bootout +
   bootstrap). No keystore variable is pinned: the daemon and the CLI both
   default to the on-disk store with no environment at all, so there is nothing
   to keep in sync. An older plist that still carries a `SIGIL_DEV_KEYSTORE`
   pin is simply rewritten without it (and `up` says so).
3. **agent loaded**. `launchctl print gui/<uid>/works.rainn.sigil` succeeds,
   else bootstrap.
4. **daemon healthy**. A real `Status` control round trip (bounded by socket
   timeouts) must answer. A connect-refused OR a connect-that-never-answers
   both count as down; this is what catches the zombie mode in section 3
   (process alive, listeners gone) that a bare liveness probe calls healthy.
   On failure: `launchctl kickstart -k`, then re-probe with backoff.
5. **ssh agent listening**. The ssh-agent socket accepts a connection
   (informational; it is the same process, kickstart above heals it).
6. **shim wired**. `~/.sigil/bin/op` symlink present and pointing at the
   installed runtime; `~/.sigil/bin` on PATH in the shell profile.
7. **phone paired**. A pairing exists, else `action needed: run sigil pair`
   (the ceremony requires the human and is never automated).

Exit code 0 when everything is `ok`/`fixed`; 1 when anything is
`action needed` or a fix failed. Output is line-per-step, ASCII-safe, no
em-dashes, no emoji.

`sigil start` remains as the thin service verb (plist + bootstrap) and `sigil
setup` calls the same ensure chain; `up` is the verb everyone should reach for.

### Why unconditional KeepAlive

The old `KeepAlive {Crashed:true, SuccessfulExit:false}` leaves the daemon down
after any exit(0) and after launchd-initiated terminations that count as
neither. Always-on means always-on: `KeepAlive true` restarts the daemon after
ANY exit. Stopping deliberately is still possible because `sigil stop` does a
bootout (unload), which KeepAlive does not resurrect.

## 3. Daemon reliability: the actual root causes (diagnosed 2026-07-15)

The "flaky daemon" had two concrete, reproducible-in-logs causes, both in the
accept loop of `serve()` in `crates/sigil/src/daemon.rs`. Evidence:
`~/.sigil/logs/daemon.err.log` and a thread sample of the wedged pid.

**Bug 1: a dead client's socket killed the whole daemon.** Every accepted
connection ran `into_std() ... set_read_timeout(...)` with `?`, propagating a
per-connection error out of `serve()`. On macOS, `setsockopt(SO_RCVTIMEO)`
returns EINVAL when the peer has already disconnected, and the Mac app's
`daemonRunning()` liveness probe is exactly a connect-then-close, so the app's
own polling routinely raced the daemon into this. The log shows five
`set_read_timeout: Invalid argument (os error 22)` lines, each immediately
followed by a fresh startup banner: each occurrence was a full daemon death and
launchd respawn, killing any in-flight approval.

Fix: per-connection setup is now non-fatal (log the connection error, drop that
one connection, keep accepting). Listener-level accept errors also log and
continue (with a short sleep to avoid a hot loop) instead of ending serve.

**Bug 2: the zombie daemon (the worst mode).** When `serve()` did bail, `run()`
returned through `Runtime::drop`, which joins in-flight blocking tasks. The Mac
app's menubar holds a `subscribe_pending` stream open indefinitely; its handler
never returns while the client stays connected, so the join blocked forever.
Result: a process that dropped both listeners (control and ssh-agent sockets
refuse connections, socket files left behind) but stays alive, so launchd's
KeepAlive sees a healthy service and never restarts it. This exact state was
live on the machine during diagnosis: pid up since Jul 14 12:01, both sockets
connection-refused, main thread parked in the blocking-pool join, the ToDaemon
owner thread still polling the relay (so the phone even looked "connected").
This is why the SSH agent "worked earlier, dead now", and why only a manual
kickstart ever revived things.

Fix: `run()` now bounds runtime teardown with `shutdown_timeout` so a stuck
handler cannot pin the process; serve errors reach the CLI, print, and exit
nonzero, which launchd (KeepAlive true) restarts cleanly. Together with Bug 1's
fix the error path should essentially never fire, but when it does it now heals
in seconds instead of wedging forever.

**Hygiene fixed alongside:** the `SIGIL_DEV_KEYSTORE` warning banner printed on
every keystore construction (tens of thousands of times, 23 MB of logs in a
day, because the relay owner loop constructs the keystore per poll); it now
prints once per process. The ssh sign path also gained the same one-line
request log the op path has, so "no sign activity in the log" can never again
be ambiguous between "request never made" and "nothing logs on this path".

## 4. The SSH sign path: diagnosis

Symptom reported: `ssh-add -l` lists the served key, `op` gating reaches the
phone, but `ssh-add -T` (a SIGN_REQUEST) times out with no daemon activity.

Findings, from code trace plus the live logs:

1. **The daemon-side wire path is correct.** REQUEST_IDENTITIES and
   SIGN_REQUEST both parse and dispatch (`sshagent::respond`); the sign path
   routes to `Core::approve_and_sign`, builds the `SshChallenge` context, and
   enters the same `ApprovalGate` -> `RemoteApprover::round_trip` the op path
   uses, with the same transport, envelope seal, and push hint. There is no
   kind-specific filter anywhere daemon-side or relay-side (the relay is
   blind).
2. **A sign request demonstrably completed the full daemon path.** The log
   holds `ssh connection error: Broken pipe`: the daemon read a SIGN_REQUEST,
   gated it, waited out the full approval timeout (120 s; the client gave up
   at ~90 s), and only then failed writing the reply. A failed deposit would
   have denied instantly, so the sealed request reached the relay mailbox.
3. **Therefore the loss is phone-side or timing-side, not daemon-side**: either
   the app was not foreground-polling at that moment (push doorbell removed;
   foreground polling is the only delivery path today, task #44), or the
   installed build mis-renders `kind: ssh_signature` (protocol support exists
   in `apps/phone/src` since 2026-07-04, but the installed build predates the
   uncommitted redesign). `classifyToPhone` accepts any untagged payload as a
   request, so it is a display/decision question, not a parse-drop.
4. **The wedge (section 3) compounded it**: during parts of the session the
   ssh-agent socket was refusing connections entirely while the daemon looked
   alive, which reads exactly like "sign requests vanish".

No daemon-side code bug remains in the sign path itself; the reliability fixes
above remove the failure modes the daemon did own. On-device verification for
the remainder (needs Tom, two minutes):

```sh
# 0. ensure a fresh healthy daemon
target/release/sigil up            # or: sigil up, once installed
# 1. put the phone app FOREGROUND (polling is foreground-only today)
# 2. fire a test signature
export SSH_AUTH_SOCK="$(target/release/sigil sshagent | grep -o '/[^"]*ssh-agent.sock' | head -1)"
ssh-add -l                          # must list id_ed25519_tower
ssh-add -T ~/.ssh/id_ed25519_tower.pub
# 3. watch: daemon log now prints "ssh-sign id_ed25519_tower ..." on arrival;
#    the phone should show an approval sheet with key label, host, fingerprint.
```

Interpretation: log line present + no sheet while foregrounded => phone-side
rendering of `ssh_signature` in the installed build (fix belongs in the phone
redesign, task #75); sheet appears and approving still fails => response path,
capture the phone error. Either way the daemon has done its part.

CLOSED 2026-07-15: Tom's phone received and rendered a live sign request (the
`ssh-add -T` fired during this work), so delivery AND rendering work on the
installed build. The remaining untested leg is approve-to-signature (the
phone's approval carrying back into an emitted SIGN_RESPONSE), which needs
one approved `ssh-add -T` run: expect "Agent signature verified" wording from
ssh-add on success.

### The EINVAL root cause, pinned empirically

`set_read_timeout: Invalid argument (os error 22)` is macOS returning EINVAL
from `setsockopt(SO_RCVTIMEO)` on a unix-stream socket whose peer has FULLY
disconnected. An empirical probe on this machine (macOS 26) measured:

- peer closed before setsockopt: 2000/2000 EINVAL (deterministic);
- peer alive: 0/2000 failures;
- peer half-closed (shutdown of its write side): 0/500 failures.

So EINVAL is a precise dead-peer detector; a LIVE ssh client can never hit
it. Two consequences worth stating because the intuitive story is wrong:

1. EINVAL never dropped `ssh-add -T`'s own connection. That connection stayed
   alive through the whole gate wait (proven by the Broken pipe on the reply
   write, which requires the same connection to have been held and served).
   The way EINVAL broke SSH was indirect and worse: in the old code an EINVAL
   from ANY connection (the Mac app probes connect-then-close every 3 s)
   killed the entire serve loop, destroying every in-flight sign round trip,
   and then the teardown wedge (section 3) kept the corpse alive.
2. The `ssh-add -T` hang itself was the approval round trip running its
   course: request deposited, phone leg pending, client gave up before the
   120 s fail-closed deny. With delivery confirmed working, a hang now means
   only "the human did not answer in time".

Handling: a dead peer's connection is worthless by definition and dead-peer
drops are ROUTINE traffic (liveness probes are connect-then-close by design),
so the daemon drops them silently; any other per-connection ready-up failure
is logged loudly. Deterministic regression tests pin the classification
(`a_peer_that_hung_up_before_serving_reads_as_a_dead_peer`) and loop survival
under a 50-probe storm with a live client still served
(`a_live_peer_readies_cleanly_and_a_dead_peer_storm_does_not_starve_it`).

### Policy: host-unbound signatures are allowed, labeled honestly

`ssh-add -T` (and any pre-8.9 OpenSSH, and most non-OpenSSH agent clients:
Go's x/crypto/ssh, libssh2, JGit) sends no `session-bind`, so the approval
shows `(host not bound)`. Should Sigil warn harder, or deny unbound sign
requests by default?

Decision: ALLOW, with the honest label, unchanged. Reasoning:

- `session-bind` is client-claimed and unverified (sshagent.rs documents
  this): a malicious same-UID client can present any real host's public key
  and look impeccably "bound" to github.com. Denying unbound requests
  therefore adds ZERO security against the adversary it appears aimed at,
  while breaking every honest older or non-OpenSSH client. A gate that only
  inconveniences honest callers is theater.
- The load-bearing consent fields are the key label, the data fingerprint,
  and the human's situational awareness ("am I actually mid-ssh right
  now?"). An unexpected sign request is the signal, bound or not.
- What IS worth doing: the phone should render the unbound (and the
  fingerprint-only) destination as visually suspicious rather than neutral,
  e.g. "destination unverified". That is approval-screen copy in the phone
  redesign (task #75), not daemon policy.

Referred to the independent security reviewer for a second opinion, as an
authorization-shape call.

## 5. The Sigil skill (`.claude/skills/sigil/`)

A Claude Code skill that teaches any agent to operate Sigil. Shape:

- `SKILL.md`: the operating model, the non-negotiable secret-safety rule, the
  keystone habit (`sigil up` first), the CLI surface map, and the recipes:
  health, gating a CLI, sealing env secrets, SSH (file keys, stored keys,
  host routing), diagnosis.

**The crucial rule, stated first and repeated at every recipe that touches a
value: the agent must never see, receive, echo, or log a secret value in
plaintext.** Concretely:

- Sealing a value is always a pipe the HUMAN runs in their own terminal:
  `printf '%s' "$TOKEN" | sigil-config source env set <name> --stdin`.
  The agent writes the command with a placeholder, the human substitutes the
  value; the agent never asks for the value in chat and refuses it if pasted.
- Reading back is impossible by design (write-once seal); the agent verifies
  by structure (`sigil-config list`, key names only), never by value.
- Gated commands run by the agent may RESOLVE secrets into a child process
  (that is the product), but the agent must not run gated commands whose
  purpose is to print a secret to the transcript (e.g. `op read` to stdout)
  unless the human explicitly asks for the value themselves.

The skill treats the phone as provider-blind and the daemon as inert at rest;
it never proposes weakening a gate to make automation smoother.

## 6. Keystore: the on-disk store is the default (settled 2026-08-04)

The daemon identity and the Mac threshold share `m` live in
`~/.sigil/keystore.json`, a 0600 JSON file, on every platform, with no
environment variable involved. An install carrying the older
`~/.sigil/dev-keystore.json` is renamed in place the first time the new name is
opened, so the pairing survives the upgrade untouched.

Why the file and not the login keychain: under the threshold posture neither
blob is a standalone decryption secret (`m` is inert without the phone's
per-request partial), the store must work identically from an unsigned daemon
and an unsigned CLI, and it must not depend on a code signature or a keychain
prompt. The honest residual is unchanged and stated wherever the store is named:
a reader of the file gets the identity key AND `m` together, so a phished
approval could decrypt off-box.

What killed the previous arrangement was not the storage but the *gating*: the
file store was selected by `SIGIL_DEV_KEYSTORE=file`, pinned into the launchd
plist, and therefore invisible to any CLI run from a plain shell. The two halves
disagreed about where the pairing lived, and the resulting error advised a
re-pair that would have destroyed a healthy pairing. One default, resolvable
with no environment, is the fix.

Overrides remain, spelled `SIGIL_KEYSTORE=file|memory|keychain`
(`SIGIL_DEV_KEYSTORE` still works and logs a deprecation line). `memory` is for
tests; `keychain` reaches the login-keychain store, which is also where an
identity from an older build may still be sitting. That case is reported, never
migrated automatically: a keychain read can raise a system prompt, and a daemon
that blocks on a dialog at startup is not a daemon.

Two consequences worth naming. The pairing-authorization Touch ID gate (#48) was
attached to the keychain store; it now asks the HOST instead
(`keystore::presence_plan`), because `LAContext.evaluatePolicy` never needed the
keychain and the gate must not vanish when storage moves. And `Factor::Biometric`
is now reachable only under the keychain override, so an unpaired daemon on the
default store reports "no factor: fails closed" rather than claiming a hardware
factor that has no approve path.

## 7. What changed where (implementation map)

- `crates/sigil/src/daemon.rs`: non-fatal per-connection setup; bounded
  runtime shutdown; ssh sign request log line.
- `crates/sigil/src/service.rs`: plist renders unconditional KeepAlive and the
  stable program path; installed-binary ensure; dev-pin carry-forward.
- `crates/sigil/src/up.rs` (new): the `sigil up` ensure chain and report.
- `crates/sigil/src/cli.rs`: the `up` verb; `setup`/`start` route through the
  same ensure chain.
- `crates/sigil/src/keystore.rs`: warn-once.
- `apps/mac`: Start button removed; the app runs the ensure on launch and
  shows state instead of offering manual lifecycle.
- `.claude/skills/sigil/SKILL.md`: the operator skill.
- `docs/security-claims.md`: residuals from the independent review of the
  serve-loop changes.
