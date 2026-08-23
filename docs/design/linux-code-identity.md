# Linux code identity: what `resolve()` measures, and why

Status: decision record. Implemented in `lease.rs`'s Linux `ProcessTable`.

RAI-32 found that `SysProcessTable` returned `None` from both `parent()` and
`resolve()` off macOS, so `walk_ancestry` always produced an empty chain on
Linux and `Caller::may_lease` (`lease.rs`) never granted a window: every gated
call cost a fresh approval, permanently. This note records how that gap was
filled and the measurement decision behind it, per `docs/design/linux-lifecycle.md`'s
own open question at the end of its file, which this closes for the *ancestry*
half and states honestly for the half that is not this ticket's to close.

## The recommendation in one line

Fill Linux with **`IdentityMeasure::Content`**, hashed through the fd
`/proc/<pid>/exe` opens, and read the path off that same fd via
`/proc/self/fd/<n>` rather than a second lookup. No new `IdentityMeasure`
variant, no new grant-key tag: both measures already existed in the enum.

## Why hashing through the fd is not the weaker claim it looks like

The module docs (`lease.rs`) are explicit that a naive file hash is the wrong
answer: it measures a claim about a file, and the whole point of the macOS
guest-object measurement is to measure the *running* image instead, because a
file can be swapped out from under a process after exec.

`/proc/<pid>/exe` is not a path lookup. It is a kernel-held reference to the
inode the process was exec'd from, resolved once at `open()` regardless of
what is later placed at that path. Two properties, both exercised by tests
(`lease.rs::{renaming_over_the_exe_path_does_not_change_what_a_running_process_measures_as,the_kernel_refuses_to_overwrite_a_running_executable_in_place}`,
and reproduced by hand first on 2026-08-22, recorded in the `assessment`
document on RAI-32):

- **A rename-over the path does not move the hash.** Copying a different
  binary to a fresh name and `rename()`-ing it over the running process's exec
  path leaves `measure_running_image` returning the SAME digest, because the
  fd still names the original inode. The path the human sees (`/proc/self/fd/<n>`)
  picks up a ` (deleted)` suffix once the original name is gone, which is
  informational, not a security signal this code reads.
- **An in-place rewrite is refused outright.** `open(O_WRONLY)` against a path
  with a running instance answers `ETXTBSY`, enforced by the kernel per-inode,
  before a single byte can move.

Put together: **on Linux there is no state where the path resolves but the
content does not**, which is the split macOS needs its validity check for
(`SecCodeCheckValidityWithErrors` answering `-67034` while `proc_pidpath`
still succeeds). Linux does not have that split, so `resolve()` does not need
a platform-refusal branch for this attack, and the practical result is that
the self-updating-tool case — a tool that deletes its own binary mid-session,
which is the commonest reason macOS drops an ancestor to `Unmeasured` — stays
fully measured as `Content` on Linux instead, because the kernel keeps a live
process's inode content readable after unlink.

What this is **not**, same as macOS: a signing identity. There is no signer to
ask, so this is `Content`, never `Signed` or `AdHoc` — the same separation the
enum already draws.

## Why `resolve()` still has an `Unmeasured` fallback, and how narrow it is

`measure_running_image` returns `Err` only when: the pid does not resolve at
open time (gone, or `PTRACE_MODE_READ` refused it — see the uid section
below), or a `read()` on the already-open fd fails after the permission gate
already passed. The second case has no realistic trigger on a local
filesystem; it exists so a transient I/O failure drops the ancestor to
`Unmeasured` (process-instance identity, logged via `note_unmeasured`) rather
than truncating the whole chain, matching the macOS path's philosophy of
"some identity beats none whenever some information is available." It is not
covered by a dedicated test because it has no reachable trigger to test
against without faking a `read()` failure; the code path is exercised
structurally by the type system (it compiles and the `Ok` path is proven), and
the choice is stated here rather than left silent.

## Why not a container-identity measure

The ticket that opened this work proposed cgroup path → container ID → image
digest as a new `IdentityMeasure`. Recorded here because it was seriously
considered and rejected, by the Infrastructure Engineer, before this ticket
reached build (`assessment` document on RAI-32, 2026-08-22):

- **A containerised daemon cannot read its own container's identity.** Inside
  this Paperclip container, `/proc/self/cgroup` reads `0::/` — the cgroup
  namespace hides the container's own path from itself. Choosing this measure
  would silently force the daemon onto the Unraid host, which is a deployment
  decision belonging to `docs/design/linux-lifecycle.md`, not this one.
- **On Tower it would discriminate nothing.** Every Paperclip agent runs in
  one container. A container measure is the same 32 bytes hashed into every
  grant key this daemon would ever derive; all the real separation between
  callers still comes from the exe-path chain, exactly as it does today.
- **It needs the Docker API to be worth anything**, which puts a
  root-equivalent dependency inside a security daemon for a digest that, per
  the point above, does not discriminate on this box.

Kept as considered-and-deferred: the condition that revives it is concrete — if
agents ever run one container each, (2) evaporates and container identity
becomes the right unit of trust here.

## The daemon-uid question, carried forward, still open

`docs/design/linux-lifecycle.md` already states this precisely: opening
`/proc/<pid>/exe` is gated by `PTRACE_MODE_READ` (the same uid as the target,
or `CAP_SYS_PTRACE`), while `/proc/<pid>/stat` (ppid, start time) is
world-readable. Verified by the Infrastructure Engineer in this container,
2026-08-22: a cross-uid `readlink`/open of `/proc/<pid>/exe` answers `EACCES`,
and root without `CAP_SYS_PTRACE` (this container's default Docker capability
set) fares no better.

**This build does not resolve which uid the daemon runs as** — no unit or
launcher pinning one has been produced yet, per `linux-lifecycle.md`. What it
does is make the consequence exact and self-documenting rather than a silent
compile-and-pass:

- Same uid as the caller, or `CAP_SYS_PTRACE`: `resolve()` returns `Content`
  for every ancestor, chains measure end to end, leases work.
- A third uid: `resolve()` returns `None` for every ancestor it does not share
  a uid with (`measure_running_image` fails `NoLiveImage`, and the fallback
  readlink for the `Unmeasured` branch is gated by the identical check, so it
  fails too), the walk truncates at the first such ancestor, and the chain is
  empty — the exact pre-this-ticket failure, reintroduced by a deployment
  choice rather than a code gap.

In the deployment mode that exists today — `sigil up` run by hand, no
dedicated service user — the daemon and the processes it measures share a
uid, which is the working case. If Tower ever gets a hardened unit heading for
a dedicated `sigil` service account, that unit needs `AmbientCapabilities=CAP_SYS_PTRACE`
stated explicitly, which is a real privilege grant on a security daemon and
belongs in review, not in a default. That is Tower Platform Owner / deployment
work, not this crate's.

## Why there is still no cache

The module docs state, as a closed decision, that nothing is measured from a
cache on macOS: a stale or forgeable cache key is exactly the shape of bug
that let R3-F2 serve a pre-rewrite identity for a daemon's whole lifetime.
Linux keeps that: every gated command re-hashes every ancestor.

The honest cost, measured on this box (not assumed), streaming-hashing a whole
file with BLAKE2b-256 once, cold-ish cache:

| binary | size | time |
|---|---|---|
| `sleep` | 43 KB | 0.5 ms |
| `sigil` (release) | 3.3 MB | 5.8 ms |
| `sigil` (debug) | 100 MB | 182 ms |
| `node` | 120 MB | 265 ms |

A shell/CLI-scale ancestor costs about what macOS's cdhash lookup costs. A
large interpreter in the chain (`node`, and by extension anything of similar
scale) does not — hundreds of milliseconds is a real, user-visible cost on a
gated command, unlike the macOS number the module docs cite (6.3ms for a real
6-deep chain), because a cdhash read is a signature lookup, not a full read of
the binary.

A `(dev, ino)` cache, taken from the already-open fd's `fstat`, would be sound
here specifically *because* the fd is a reference to a running process's own
exec inode: the kernel cannot recycle that inode number while the process
still holds it, so the cache key cannot go stale the way a path-keyed or
mtime-keyed one can. That soundness argument is recorded here for whoever
picks this up; it is not built. Scope call: this ticket's job was making
leases work at all on Linux, which the current no-cache fill already does: a
shell-and-CLI ancestor chain (the common case `sigil` gates) costs low
single-digit milliseconds, and a node-scale ancestor in the chain is real but
bounded and does not block a lease from ever being granted, only slows the
gated call that needs one. If interpreter-scale ancestors turn out to be
common on real gated chains, that is a follow-up with numbers behind it, not a
default to build against a guess.

## What was verified by running it

Linux, in this container, 2026-08-23, against `crates/sigil/src/lease.rs`'s
test suite:

- `sys_process_table_parent_reads_the_real_ppid_from_proc`: `SysProcessTable::parent`
  against a real spawned child returns this test process's own pid.
- `a_running_binary_measures_as_a_hash_of_its_own_bytes`: a live `/bin/sleep`
  measures as `Content`, matching a direct file read's hash; stable across
  repeat measurement; a second, different binary derives a different digest.
- `renaming_over_the_exe_path_does_not_change_what_a_running_process_measures_as`:
  the rename-over finding, end to end, with an explicit assertion that the
  measured digest differs from a fresh read of the substitute now sitting at
  the path (closing the "never readlink then open by path" requirement from
  the RAI-32 assessment).
- `the_kernel_refuses_to_overwrite_a_running_executable_in_place`: `ETXTBSY`,
  not some other error, on an in-place write attempt.
- `still_running_tracks_the_kernels_start_time_not_just_the_pid`: an
  `Unmeasured` note reads as live while the process is unmoved, stops reading
  as live once reaped, and a stale start time for the same live pid does not
  pass either.
- `a_pid_that_names_no_process_yields_no_identity_at_all`: pid 0 yields no
  identity; the test binary's own real ancestry (a live, same-uid chain)
  measures end to end with zero `Unmeasured` ancestors, which is the shape a
  real gated command arrives in.
- `proc_stat_fields_survive_a_comm_containing_parens_and_spaces`: the `/proc/<pid>/stat`
  parser is not fooled by a hostile `comm` field containing a `)`.

**Not verified by a test in this tree, verified by hand instead and cited
rather than re-asserted**: the cross-uid `EACCES` / root-without-capability
finding in the daemon-uid section above. Reproducing it in `cargo test`
would need a second uid inside the test process, which needs a privilege this
container does not grant its own tests either — the same gate under
discussion. Recorded as the Infrastructure Engineer's probe, not this
ticket's own claim, per `docs/security-claims.md`'s convention of citing what
proves a row.

## ProcessStart resolution, stated honestly

`/proc/<pid>/stat`'s start-time field is in clock ticks since boot; Tower
measures `CLK_TCK = 100`, giving 10ms resolution, against macOS's
kernel-supplied microseconds. A pid recycling inside the same 10ms window
would collide on the `Unmeasured` process-instance key. Practically remote
(reusing a pid within 10ms needs a very fast fork/exit churn), but it is a
real, stated weakening of the guarantee `ProcessStart`'s doc comment describes
for the macOS case, not a silent equivalence.
