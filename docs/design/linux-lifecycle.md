# Linux lifecycle: how the daemon gets installed, supervised and updated

Status: decision record. All four decisions below are implemented, decision 4
(the supervisor backend behind `sigil up`) included.

`sigil up` is the keystone verb. `docs/design/agent-operated-sigil.md` section 2
states its contract: the daemon "is not 'started'; it is *ensured*". This note
records how that contract is kept on Linux, and why the obvious answers are the
wrong ones here.

## The gap

`up.rs` and `service.rs` contained no `cfg(target_os)` split at all. The same
crate splits on platform in six other files (`local.rs`, `peercode.rs`,
`lease.rs`, `lib.rs`, `keystore.rs`, `daemon.rs`), so this was one subsystem
that never learned about Linux rather than a codebase that never did.

What that meant concretely: `service.rs` rendered a `<!DOCTYPE plist>`
LaunchAgent, wrote `~/Library/LaunchAgents/works.rainn.sigil.plist`, and drove
`launchctl bootout` / `bootstrap` / `kickstart`. On Linux it compiled, then
fabricated an Apple directory under `$HOME` and shelled out to a binary that is
not there. So a Linux host had no supervision, no restart-on-crash, and no
update path.

Six of `ensure_up()`'s seven steps already worked unmodified on Linux. The gap
was one step, and it was the one that makes the daemon stay running.

## What the target actually is

Measured on 2026-08-22, not assumed. Two environments matter, because Sigil's
agents run in a container on a host, and the daemon could live in either.

**The container** (where the agents making gated calls actually run):

- PID 1 is the application process itself, not an init.
- No `systemctl`, no `systemd`, no `/run/systemd/system`.
- No `/run/user` at all.

**The host** (Unraid OS 7.2, kernel 6.12.54):

- PID 1 is `init`; `/sbin/init` is a 53 KB binary, not a systemd symlink.
- **No `systemctl` anywhere in the host's PATH directories.** `/usr/lib/systemd/system`
  exists but holds exactly two unit files, both shipped by the WireGuard package,
  which ships them regardless of init.
- `elogind` is installed (hence `/run/systemd/{seats,sessions,users}` and
  `loginctl`), but elogind is a login-session manager, not a service manager.
- `/run/user` exists and is **empty** after 20 hours of uptime.

## Decision 1: not systemd, and not because it is unfashionable

A systemd unit is the textbook answer and it is unavailable on both sides of
this deployment. There is no `systemctl` to install, enable, start or query a
unit with, on the host or in the container. This is not a preference; the tool
does not exist on the box.

Recording the boundary of that claim: it is a statement about **this**
deployment. A systemd backend would be the right thing on a mainstream Linux
distribution, and nothing here argues against adding one later behind the same
seam. It is simply not what makes Tower work.

## Decision 2: the runtime directory is `/tmp/sigil-<uid>`, never `$TMPDIR`, never `/run/user/<uid>`

`local::runtime_dir()` documents itself as resolving "with zero environment", so
that the daemon, the `op` shim, the CLI and a bare shell all meet at one socket.
Off macOS it did not keep that promise. It was `$TMPDIR/sigil`.

`$TMPDIR` fails the contract by definition, and fails it dangerously in a
container: an agent runner commonly points `$TMPDIR` at a per-run scratch
directory and deletes it when the run ends, so a daemon meant to outlive runs
put its control socket somewhere the next run could not find, and the runner
then removed it underneath the daemon.

`/run/user/<uid>` looks like the right replacement and is not. It is the Linux
analogue of the Darwin per-user temp dir the macOS path already uses, but its
lifetime is owned by the login-session manager: logind or elogind creates it
when a session opens and removes it when the user's last session closes, unless
lingering is enabled. **The Sigil daemon is precisely the thing that must
outlive logins.** Anchoring it there yields a socket path that depends on
whether a human happens to be logged in.

Preferring it "when present, else fall back" is worse than not using it, because
it makes the path a function of session state: a daemon started while a session
was open keeps a socket at a path its own clients later stop resolving to. On
Tower it would also have bought nothing, since `/run/user` is empty there.

So Linux resolves `/tmp/sigil-<uid>` unconditionally, from `getuid()` alone. One
answer, always, for every process.

`/tmp` is world-writable, so this is only safe with a check, and the check is
`local::ensure_private_runtime_dir`. It creates the directory 0700 through
`DirBuilder::mode` (not create-then-chmod, which leaves a window at the ambient
umask), then refuses a symlink, a non-directory, or a directory owned by another
uid, and tightens group/world bits it finds. `prepare_socket` treats a refusal as
fatal: the sockets are chmod 0600 after bind, but a 0600 socket inside somebody
else's directory is not private. The residual is a fail-closed denial of service
(an attacker who pre-creates `/tmp/sigil-<uid>` as another uid stops the daemon
starting rather than reading anything), and `/tmp`'s sticky bit means they
cannot remove the directory once it is ours.

## Decision 3: one daemon per runtime dir, enforced by the kernel

Reproduced on Linux before it was fixed: starting `sigil daemon` twice against
one runtime dir did not refuse. `prepare_socket` unlinks whatever socket file it
finds, so the second daemon removed the first's socket and bound the name
itself. Daemon one stayed alive holding listeners no client could reach, writing
a clean log, while `sigil status` reported `down`.

That is the zombie mode `agent-operated-sigil.md` section 3 describes, reached
from the other direction: not a daemon that lost its listeners, but a daemon
whose listeners were taken from it. On macOS launchd supplied the guard for
free, because a LaunchAgent label is a singleton and `kickstart` heals rather
than duplicates. Nothing supplies it on Linux.

This is a **precondition for supervision, not an independent nicety.** A
supervisor that restarts the daemon must guarantee that a respawn racing a
still-dying predecessor loses, visibly, rather than producing two daemons.

`instance.rs` takes `flock(LOCK_EX | LOCK_NB)` on `daemon.lock` beside the
sockets, in `serve()`, before `prepare_socket` can unlink anything, held for the
life of the process. flock rather than a pidfile because the kernel releases it
on any exit including `SIGKILL`: there is no stale-lock cleanup path to get
wrong, and no recycled-pid false positive. The pid is written into the file only
so the refusal can name the holder; it never decides anything. Applied on all
unix, since under launchd it is belt and braces and the failure it prevents is
silent.

## Decision 4: the supervisor is a Sigil process, behind the existing `up` verb

`up` stays the single idempotent entry point; the platform split goes behind it.
No second verb, per `agent-operated-sigil.md` section 2. `service.rs` is now a
platform-agnostic surface (ensure the definition, is it loaded, bootstrap,
bootout, kickstart) over two backends: `service/launchd.rs` and
`service/supervisor.rs`.

The Linux implementation is a small supervisor process that Sigil ships and
`up` ensures: it takes its own lock, spawns `sigil daemon`, waits, and respawns
it on unexpected exit with a backoff, exiting instead when the stop was
deliberate. The reasons for this over the alternatives:

- **It works in both environments measured above**, including the container
  where PID 1 is an application process and there is no service manager to
  register with, and no reaper for orphans.
- **It composes with the alternatives rather than competing.** A systemd unit,
  a Docker `restart: unless-stopped` policy, or an Unraid rc script can each
  simply run `sigil daemon` directly, and decision 3's lock keeps every
  combination of them honest. Nothing here forecloses adding a systemd backend.
- **It matches the verb's semantics.** `up` ensures a process; it does not
  register a unit and hope.

### How it maps onto launchd

The two backends answer the same five questions, so `up.rs` drives one seam
rather than carrying two code paths:

| launchd | supervisor |
|---|---|
| `~/Library/LaunchAgents/works.rainn.sigil.plist` | `~/.sigil/supervisor.conf` |
| `launchctl bootstrap` | spawn `sigil daemon --supervise`, detached |
| `launchctl bootout` | `SIGTERM` the supervisor, then any daemon still running |
| `launchctl kickstart -k` | `SIGHUP` the supervisor |
| `launchctl print` succeeds | the supervisor holds `supervisor.lock` |
| unconditional `KeepAlive` | the respawn loop, with backoff |

The definition is a file rather than arguments for the same two reasons the
plist is one: `up` compares it byte for byte to decide whether anything changed,
and a human with no `launchctl print` to run can read what the supervisor was
told. It pins the same shim-first `PATH` and, like the plist, pins no keystore
and no `SIGIL_HOME`.

**`--supervise` is a flag on `daemon`, not a new verb.** `sigil daemon` is
already the process launchd invokes and no human types; the supervisor sits at
exactly that level. Making it `sigil supervise` would have grown the
reserved-verb surface, which the CLI keeps deliberately small so that a program
actually named `supervise` stays gateable.

The one thing launchd gives for free and this has to earn is telling a
deliberate stop from a crash. launchd knows because a bootout unloads the job.
Here the supervisor itself is the unit: `SIGTERM` means stop (terminate the
daemon, exit, so nothing respawns it), `SIGHUP` means cycle. A daemon that exits
without either was not asked to, and comes back.

### The one place the backends genuinely differ

`service::RELOAD_ON_BINARY_REFRESH`. When `up` copies new bytes into
`~/.sigil/bin/sigil`, macOS only needs the daemon kickstarted: launchd is the
operating system's, not one of the bytes that just changed. Off macOS the
supervisor **is** one of those bytes, so cycling only the daemon would update the
daemon and leave the supervisor running the previous build indefinitely. That is
a silently half-applied update, which is precisely what this chain exists to make
impossible, so a refreshed binary forces a full reload there.

### The contract the backend must satisfy, and where each item is met

1. **Ensure a process, not register a unit.** `supervisor::bootstrap` spawns and
   waits for the lock, so a success means supervising, not that `fork` returned.
2. **Enforce single-instance** (decision 3). The supervisor takes its own
   `supervisor.lock` beside the daemon's, by the same mechanism.
3. **Restart after an unexpected exit, but not after a deliberate stop.** The
   signal split above, plus a 1s-to-30s doubling backoff that resets once a
   daemon has stayed up for a minute.
4. **A socket path independent of `$TMPDIR`** (decision 2).
5. **`stop` must actually stop, and stay stopped.** `bootout` signals, then
   escalates to `SIGKILL`, and confirms by watching the lock be *released*
   rather than by probing a pid, which cannot be fooled by pid reuse. It then
   stops any daemon still holding its own lock, because a daemon started outside
   this supervisor (by hand, by a container restart policy, by a systemd unit a
   site added) is still a daemon that was asked to stop.
6. **Exit 0 when healthy.** `up::exit_code` is now a separate, tested function
   rather than a counter inside the renderer, because it is a contract:
   `sigil up && <work>` is how the pipeline gates itself. Until this split
   existed, every launchd step failed off Darwin, so `up` could not report
   success on Linux however healthy the daemon was.

### What was verified by running it

On Linux, 2026-08-22, against the built binary. Recorded because a supervisor
that has never been signalled is a belief, not a supervisor.

- A second supervisor is refused and names the holder; the first survives.
- `SIGKILL` to the daemon: respawned with a new pid after the backoff.
- `SIGHUP`: the daemon is cycled immediately, logged as asked-for, no backoff.
- `SIGTERM`: daemon terminated, supervisor exited, lock released, and nothing
  respawned. Confirmed by exe rather than by a name match.
- A daemon that exits instantly forever backs off 1s, 2s, 4s, 8s, 16s: five
  attempts in 25 seconds rather than a busy loop. A stop during a backoff sleep
  breaks out of it instead of waiting the sleep out.
- `sigil up` end to end: definition written to `~/.sigil/supervisor.conf`, no
  `~/Library` fabricated anywhere, daemon answering a real control round trip.
  A second run changes nothing and both pids are unchanged.
- The supervisor is reparented to init with its own session id, so the terminal
  that ran `sigil up` closing (or a Ctrl-C in it) cannot take it down.
- A genuinely different build: **both** the supervisor and the daemon are
  replaced, and the installed copy is the new bytes.

The step that cannot be verified here is pairing, which needs the phone. That is
the one step `up` reports as action-needed on any platform, and it is why a
freshly installed, perfectly healthy Sigil still exits 1 until the human pairs.

### Open question, carried from the lease work

Which uid the daemon runs as is a security decision and must be written into
whatever unit or launcher is produced, not inherited by accident.

The Linux ancestry fill needs `readlink /proc/<pid>/exe` to measure a caller,
which requires `PTRACE_MODE_READ`: the same uid as the target, or
`CAP_SYS_PTRACE`. `/proc/<pid>/stat` is world-readable, so ppid and start time
are fine either way; the executable path is the only gated piece. That leaves
three outcomes: run as root (holds the capability), run as the same uid as the
processes it measures (no capability needed), or run as a third uid, in which
case `resolve()` returns no path, the chain is empty, and **no lease is ever
granted** while the code compiles and the unit tests pass. A hardened unit
heading for a dedicated `sigil` service user therefore needs
`AmbientCapabilities=CAP_SYS_PTRACE` stated explicitly, which is a real
privilege grant on a security daemon and belongs in review, not in a default.

Separately, the keystore is the reason this matters at all: `keystore.rs` makes
the 0600 file store the default on every platform and `SIGIL_KEYSTORE=keychain`
is macOS-only, so on Linux the daemon identity and the threshold share are
protected by the owning uid and nothing else. Note that `SIGIL_HOME` is not the
lever for relocating it: `keystore.rs` records that the default is deliberately
env-independent because a CLI and a daemon once disagreed about where the
pairing lived, and the resulting error advised re-pairing. Setting `SIGIL_HOME`
in a unit file reproduces that bug on Linux exactly.
