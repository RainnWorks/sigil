# Resolving what a gated run actually executes

Status: implemented. Companion to `agent-operated-sigil.md` (the `up` contract)
and `linux-lifecycle.md` (the supervision definition that sets the daemon's
`PATH`).

## The question this answers

When a gated `op read op://vault/item/field` arrives at the daemon, which file on
disk does the daemon spawn?

It is a security question, not a plumbing one. The daemon spawns that child
*after* a human has approved, and for the direct-injection providers it spawns it
*with the approved secret in its environment*. A resolver that can be steered is
a resolver that hands the secret to whatever steered it.

## What was already true

The `Run` frame (`local.rs::Frame::Run`) carries `argv`, `cwd`, `proxy_depth` and
three file descriptors. It carries no environment and no `PATH`. That is
deliberate: the daemon resolves the binary in **its own** `PATH`, which the
supervision definition pins — the launchd plist on macOS,
`~/.sigil/supervisor.conf` elsewhere — to a fixed list of system directories:

```
/usr/local/bin  /usr/bin  /bin  /usr/sbin  /sbin      (+ Homebrew on macOS)
```

preceded by the shim dir, and `paths::find_real` then walks that list skipping
anything that is one of our own aliases.

So a caller cannot poison the resolution, because the caller's `PATH` is never
consulted. That property is load-bearing and this change does not touch it.

## The gap, and how it was found

It was found by installing the shipped Linux artifact on Tower and running it,
under RAI-34. Everything worked: the daemon installed, supervised, healed,
answered its socket, and reported its own state coherently. And `sigil doctor`
said `real op found: no`.

Tower's `op` is at `/mnt/user/HQ/tools/op` — a NAS share, not a system
directory. It is on every human's `PATH` on that box and on none of the daemon's.
So a fully installed, fully paired Sigil on that host could not run a single
gated `op` call, and the reason was invisible: the only diagnostic said "no `op`
on PATH", which invites the operator to fix a `PATH` the daemon does not use.

This is not exotic. `/opt`, a Nix profile, a Homebrew prefix on Linux, a
per-user install, a mounted share: all of them land outside the pinned list.

The code's own comment (`service/supervisor.rs`) already anticipated it and said
what a site in that position should do:

> A site whose `op` lives outside these directories sets an explicit `op_path` in
> config rather than widening this.

**That setting did not exist.** The only `op_path` in the tree was
`OpProvider::op_path`, a test-injection field with no path from any config file
to it. The documented escape hatch had never been built, so the honest state was:
if your tool is not in one of five directories, Sigil cannot run it, and the
documentation tells you to use a fix that is not there.

## Decision: pin the file, do not widen the list

Two shapes were available.

**Widen the daemon's `PATH`.** Let the operator append a directory. One line of
config, and it composes with the existing walk.

**Pin the file.** Let the operator name the exact absolute path of a command's
real executable.

The pin wins, and the reason is the same reason the `PATH` is pinned at all.
Adding `/mnt/user/HQ/tools` to the daemon's search path makes *every present and
future file in that directory* a candidate to be spawned with an approved
credential — including a file some other process drops there next month. Naming
`/mnt/user/HQ/tools/op` makes exactly one file a candidate. The pin is the
narrower grant, and narrowness is the whole reason the list was pinned rather
than inherited.

So: `config.json` gains

```json
"binaries": { "op": "/mnt/user/HQ/tools/op" }
```

authored by `sigil-config binary set op /mnt/user/HQ/tools/op`, read by
`paths::resolve_command`, and surfaced by `sigil-config binary list`.

### Why `config.json` and not `settings.json`

`settings.json` is the preference store the Mac app reads and writes: approval
timeout, notifications, relay URL, retention. Its own module doc says "none of it
is secret".

`config.json` is the rule and source store. The daemon **only ever reads** it, at
arm time, precisely so that a compromised always-on daemon cannot rewrite what is
gated. Anyone who can write it can already author a rule that gates or ungates
any command.

A value that decides which executable gets spawned with a live credential belongs
on the second side of that line, under the integrity boundary that already
governs "what runs and under what gate". Putting it in the preference file the
GUI writes would have been a quiet downgrade.

### Why keyed by command, not attached to a source or a rule

A `Source` says what to inject; a `Rule` says what to gate. Neither is "where the
tool is installed". One `op` install serves every rule that gates `op`, including
`allow` passthrough rules that inject nothing at all, so the natural key is the
command name as it appears in `argv[0]` and the natural cardinality is one entry
per command per box.

## The fail-closed rule, which is the point

**A pin that no longer resolves refuses the run. It never falls back to the
`PATH` walk.**

The tempting behaviour is "pin first, `PATH` if that fails" — it degrades
gracefully and nothing ever breaks. It is wrong. A pin exists *because the
operator does not want the daemon choosing*. Silently choosing the moment the pin
breaks reintroduces exactly the substitution the pinned `PATH` was built to
prevent, and does it at the worst moment: when something has just changed on
disk.

A broken pin is an outage, and it says so at exit 127 with the path it tried. A
silent substitution is an incident nobody sees. We take the outage.

The same reasoning makes a relative pin a refusal rather than a resolution:
relative to *what* has no answer inside a long-running daemon, and both plausible
answers (the caller's cwd, the daemon's) are steerable.

## A pin is not an opt-out of the alias checks

`find_real` excludes two things, either rule sufficient:

1. a candidate that canonicalises to a Sigil binary an alias points at;
2. a candidate resident in the proxy dir `~/.sigil/bin`, symlink or not (this
   catches a hard copy that canonicalisation cannot see).

`resolve_command` re-applies both to a pinned path. Pinning `op` at our own shim
would re-enter the gate and loop until the depth fuse blows, so it is refused
with `PinIsShim` and the reason. A pin is a way to name a file the `PATH` walk
cannot *reach*, not a way to skip what the walk *checks*.

## Validated twice, deliberately

`sigil-config binary set` validates against the filesystem before writing —
absolute, exists, regular file, executable — so a typo is refused where a human
is standing rather than stored and discovered at 3am inside a daemon that can
only fail closed.

`resolve_command` validates again at spawn time, because the file can be removed,
replaced by a directory, or have its execute bit cleared in between, and because
`config.json` is a file a human may edit by hand.

Neither check is the only one.

## The diagnostics had to move too

`sigil status` and `sigil doctor` previously called `find_real_op()` directly.
That answered a *different question* from the one the daemon asks at spawn time,
and the two could only agree by luck: these builders also run CLI-side when the
daemon is down, where the `PATH` being walked is the user's shell's, not the
daemon's.

Both now call the same `resolve_command`, so a pinned `op` reports identically
from either side, and the doctor hint names the actual failure instead of
"no `op` on PATH" — which was wrong for every failure a pin can produce, and
which, on a box whose `op` merely lives somewhere unusual, told the operator to
fix the one thing that cannot help.

## What this does not change

- The `Run` frame still carries no environment. Caller `PATH` poisoning is still
  impossible on the daemon-up path.
- With no pin configured — the default, and what every site whose tools live in
  the usual places gets — resolution is byte-for-byte the previous `PATH` walk,
  exclusions included. There is a test that says so.
- The daemon-down path is unchanged: it uses the caller's `PATH` and injects no
  secret, so a poisoned `PATH` there runs the caller's own binary with no token,
  identical to not having Sigil.

## Provenance

Found on RAI-34 by running the shipped Linux artifact on Tower rather than by
reading the code; the daemon's `PATH` is only observable once something is
actually supervised by it. Fixed under RAI-48.
