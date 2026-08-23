//! Leases and the daemon-verified caller identity they are scoped to.
//!
//! A dev session fires many `op` calls the caller cannot be changed to route
//! differently; they believe they are the real CLI. So the daemon derives the
//! caller's identity itself and never trusts the client's account of it:
//!
//! 1. Read the true peer pid off the unix socket (`LOCAL_PEERPID`).
//! 2. Walk the ancestor chain kernel-side (sysctl `KERN_PROC` on macOS), pid by
//!    pid, resolving each to an executable path and a code-identity measurement
//!    ([`CodeIdentity`]) in ONE lookup of the running process, so the path and
//!    the measurement can never describe two different processes.
//! 3. The grant key is `BLAKE2b(chain ++ project_root ++ kind ++ scope)`. Raw
//!    pids are excluded from the hash because they recycle; only the stable code
//!    identity (path + measure tag + digest) of each ancestor is bound in.
//!    `kind` is the request-kind tag ([`ScopeKind`]), so a command scope and an
//!    SSH scope live in separate namespaces and cannot collide however they are
//!    spelled.
//!
//! # What the ancestor measurement does and does not buy
//!
//! It does **not** authenticate the caller. Any same-UID process can put itself
//! in the chain, name itself anything, and ask; the measurement only decides
//! *which* grant key that chain derives, and therefore which earlier approval it
//! can coalesce with. The authorizing step is always the human on the phone.
//!
//! What it is: **the platform's answer to "what is that pid running", asked of
//! the live process**. Each ancestor is resolved to its guest code object by pid
//! (`SecCodeCopyGuestWithAttributes`), the platform is asked whether it still
//! vouches for that image (`SecCodeCheckValidityWithErrors`), and only then are
//! the cdhash and the executable path taken off that same object
//! ([`crate::peercode::measure_guest`]). Properties that follow:
//!
//! * The measure names the RUNNING image, not a file. Rewriting the file at an
//!   ancestor's path after exec does not hand the caller the identity it put
//!   there: the platform answers `-67034 errSecCSStaticCodeChanged` for that
//!   process (verified here for in-place overwrite and for rename-over) and the
//!   ancestor drops to [`IdentityMeasure::Unmeasured`], keyed to its own process
//!   instance. That is a refusal to measure, not detection of a live tamper.
//! * It is stable across a re-sign of unchanged code (a renewed certificate does
//!   not move the cdhash) and it moves the moment the code moves.
//! * An ad-hoc signature has no signer, so its cdhash asserts nothing a hash of
//!   the bytes would not. It gets its own measure ([`IdentityMeasure::AdHoc`]),
//!   never [`IdentityMeasure::Signed`]. All measures are domain-separated in the
//!   grant key, so a binary that gains a real signature reads as a DIFFERENT
//!   caller (a fresh approval) rather than silently the same one.
//!
//! What it is NOT, and must not be described as: **tamper-evidence.** Three
//! things it does not cover, none of them fixable here:
//!
//! * A cdhash names an executable, never what that process later loaded, and for
//!   an interpreter never the script it is running. `zsh` measures as `zsh`
//!   whatever it is executing.
//! * No page hashes are checked, by us or by the validity call. Measured here:
//!   patching bytes in the file under an INTACT CodeDirectory leaves the cdhash
//!   where it was, so the guest check still succeeds and the ancestor still
//!   measures the same. That is not staleness (the identity genuinely did not
//!   move, and the running process is still running the pages it mapped); it is
//!   the boundary of what a cdhash is. What the validity check catches is
//!   SUBSTITUTION, an image whose identity differs from the one the kernel
//!   executed, which is the attack on this grant key. Page enforcement is the
//!   kernel's: it refuses to run a page-tampered image at all. A userspace
//!   re-check would not help either -- a default-flag `SecStaticCodeCheckValidity`
//!   passes a page-tampered Mach-O, and the strict flags that refuse one
//!   (`kSecCSCheckAllArchitectures | kSecCSStrictValidate`) cost ~200ms per
//!   binary (`codesign -v` catches it too, at similar cost).
//! * The dominant residual is untouched by any of this: an attacker who can run
//!   a process as this user does not need to imitate an ancestor, because they
//!   can spawn UNDER the honest ones and run the genuine gated command, and the
//!   chain then matches by construction.
//!
//! State the last one at its full strength, because a weaker version of it has
//! been written here before. **A chain of measured ancestors is
//! RECONSTRUCTIBLE, not just joinable.** [`grant_key`] binds each ancestor's
//! executable path, measure tag and digest, plus the chain length and the rule
//! name, and NOTHING instance-specific whenever every ancestor measures. So an
//! attacker who can run code as this user need not touch the victim's processes
//! at all: they can exec the same binaries from the same paths in the same
//! nesting and derive the identical key, and `ps` discloses the tree to imitate.
//! Closing that would need a per-session secret the ancestors cannot both hold
//! and be measured by, so it is not closed. The measure's value is telling
//! HONEST tool trees apart, which is what it is for; it is not a fence against a
//! deliberate imitator, and no text here or on a consent surface may imply it is.
//! (The one measure an attacker cannot reconstruct is the unmeasured branch
//! below, which keys to a live process instance.)
//!
//! # When the platform will not describe an ancestor
//!
//! Sometimes it will not answer at all. The overwhelmingly common cause is
//! benign and is not an attack: a tool that updates itself deletes the binary it
//! is running from, and from that moment the platform has no image to describe
//! for a process that is still perfectly healthy. The swap case above lands here
//! too.
//!
//! Such an ancestor is [`IdentityMeasure::Unmeasured`], and its digest is the
//! **process instance**: the pid plus the kernel's start time for it
//! ([`CodeIdentity::unmeasured`]). It keeps its own measure tag, so it can never
//! be confused with a measured one, and the chain still leases.
//!
//! This branch is weaker than the measured ones and it is accepted deliberately:
//!
//! * **What it asserts** is continuity of one process, not identity of code. It
//!   says "the same live process that was here before", and nothing about what
//!   that process is running. A window under it therefore keeps serving while
//!   that process lives, whatever it went on to do.
//! * **What it costs an attacker** is nothing they did not already have. To
//!   collide with a victim's key they would have to BE a descendant of the
//!   victim's ancestors at that pid and that microsecond, which is the honest
//!   chain; and spawning under the honest ancestors was always the dominant
//!   residual above. Neither half is caller-supplied: the daemon reads the pid
//!   off the socket and the start time from the kernel.
//! * **Why not fail closed instead.** Refusing to lease an unmeasured chain was
//!   the first cut and it is the wrong trade for this product. It turns a
//!   background auto-update into a silent return to one phone tap per command,
//!   with a cause no user could diagnose, and per-command approval is the exact
//!   problem leases exist to solve. The narrower rule is what remains: a caller
//!   the daemon could not put a single process behind gets no window at all
//!   ([`Caller::may_lease`]), because every such caller would share one key.
//! * **It is never silent.** The daemon logs each unmeasurable ancestor once per
//!   executable and reason, naming it and why, and `sigil doctor` carries a row
//!   for as long as any are outstanding ([`unmeasured_notes`]).
//!
//! Honest limit on the chain: every gated command reaches the daemon through a
//! `~/.sigil/bin` symlink to the ONE `sigil` binary, and macOS `proc_pidpath`
//! resolves symlinks, so the chain leaf is byte-identical for every gated
//! command. The chain distinguishes *tool trees*, never commands. The rule name
//! in the scope is the whole command-discriminating boundary; the chain is an
//! outer fence around it.
//!
//! What the daemon puts in `project_root` and `scope` decides how wide one
//! approval reaches, and the two callers differ deliberately:
//!
//! * **A gated command run** ([`crate::daemon`]'s `fulfill`) passes an empty
//!   project root and the matched RULE's name as the scope. So a lease covers
//!   "this caller chain, running anything this rule matches, from anywhere":
//!   `op read A` and `op item get B` from the same tree share one lease, and a
//!   `cd` no longer splits it. Breadth is bounded by the rule the user wrote
//!   plus the rule's own lease policy (a run-once rule never leases at all).
//! * **An SSH signature** passes an empty project root and a scope that folds in
//!   the data-to-sign fingerprint, so every signature is its own approval. That
//!   path grants no lease; the key only coalesces byte-identical re-signs.
//!
//! A lease is RAM-only and triple-scoped (grant key + account + scope), plus the
//! [`LeaseBinding`] fingerprint of the source material a cached value came from.
//! What it holds depends on the rule it covers:
//!
//! * **Plain gate** (`op`, `env-file`): an empty presence marker. The lease only
//!   says "this caller already got a yes"; nothing is injected.
//! * **Sealed inline `env`**: the unsealed values themselves, so a burst of runs
//!   inside the window injects from RAM with no phone round trip. This is the
//!   only place a credential lives in daemon memory across requests, and it is
//!   why the window has to die the moment anything under it moves.
//!
//! Everything that can end the window zeroizes it: TTL expiry, `sigil lease
//! revoke`, daemon restart/ctrl-c ([`LeaseStore::clear`]), and a config change
//! that removes or edits the covering rule ([`LeaseStore::revoke_scope`], driven
//! by `daemon::Core::reload_config`). A re-seal of the source is caught by the
//! `binding` mismatch on lookup, so a stale plaintext is never injected.
//!
//! Client-supplied ancestry is never consulted; the whole chain is measured
//! here.
//!
//! macOS ancestors are measured through the live guest code object, the same
//! machinery [`crate::peercode`] uses for the keystore gate, with the validity
//! check gating the answer. Linux has no such object to ask, so ancestors are
//! measured by hashing the executable through the fd `/proc/<pid>/exe` opens,
//! which the kernel resolves to the RUNNING image regardless of what the path
//! now names on disk, the same property the macOS path buys by a different
//! mechanism (see `docs/design/linux-code-identity.md` for the verification and
//! the daemon-uid precondition it depends on). Nothing is measured from a path
//! on either platform, and nothing is cached: a stale or forgeable cache key is
//! a way to be told an ancestor is code it is no longer running, so every
//! request measures afresh (a few fractions of a millisecond per ancestor on
//! macOS, well under the cost of the `op` child the request goes on to spawn;
//! the Linux cost is higher for a large ancestor and is stated honestly in the
//! design note rather than assumed away).
//!
//! Residuals that remain (for the reviewer, not a verdict): the caller-chain
//! imitation class above; the process-instance branch, which asserts continuity
//! of a process rather than identity of code and is stated in full in its own
//! section; the measure is macOS/Linux-only, so a future Windows process table
//! has to fill the seam or every ancestor there is unmeasured; and the walk
//! resolves ancestors by pid, so a pid recycled between the parent lookup and
//! the measurement pairs one process's chain position with another's identity.
//! That last one fails closed (the mismatched pair derives a key nobody holds,
//! so the run takes a fresh approval) and cannot widen a grant.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::secrets::Token;

type Blake2b256 = Blake2b<U32>;

const GRANT_DOMAIN: &[u8] = b"sigil.grant.v1";
/// Domain for folding a variable-width cdhash down to the 32 bytes the chain
/// carries. Separate from [`GRANT_DOMAIN`] so the two hashes are unrelated.
const CDHASH_DOMAIN: &[u8] = b"sigil.cdhash.v1";
/// Domain for the process-instance digest an unmeasurable ancestor gets. Its own
/// string so it can never coincide with a cdhash fold.
const UNMEASURED_DOMAIN: &[u8] = b"sigil.unmeasured.v1";
/// Cap the ancestry walk so a pathological or looping process table cannot spin.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// How an ancestor's 32 bytes of code identity were arrived at. Hashed into the
/// grant key alongside the digest, exactly as [`ScopeKind`] is, so the measures
/// never share a namespace: a signed binary and an unsigned one cannot collide,
/// and a binary that gains a signature derives a new key (a fresh approval)
/// rather than inheriting the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMeasure {
    /// The platform's own answer about a running image whose signature has a
    /// signer: its cdhash, taken off a guest code object the platform vouched
    /// for.
    Signed,
    /// The same measurement of a running image whose signature is ad-hoc. An
    /// ad-hoc signature has no signer, so its cdhash is a digest of the binary
    /// and nothing more; it is separated from [`IdentityMeasure::Signed`] so it
    /// is never read as a signing identity. Most of a dev box lands here
    /// (Homebrew, cargo and npm binaries are ad-hoc signed).
    AdHoc,
    /// A hash of the executable's bytes. Nothing on macOS produces this: it is
    /// what a platform with no code-identity machinery would fall back to, and
    /// what the synthetic process tables in tests use.
    Content,
    /// No measurement was obtainable: the pid does not resolve to a live guest,
    /// or the platform declined to vouch for the image (which is what a
    /// post-exec swap of the executable looks like).
    ///
    /// This is the one measure that names a PROCESS rather than code: the digest
    /// is derived from the pid and the kernel's start time for it, so it holds
    /// for the life of that one process instance and no other. It is weaker than
    /// the measures above and deliberately so; see the module docs for what it
    /// buys and what it costs.
    Unmeasured,
}

impl IdentityMeasure {
    /// The tag hashed into the grant key. Short and fixed; never displayed.
    fn tag(self) -> &'static [u8] {
        match self {
            IdentityMeasure::Signed => b"cdhash",
            IdentityMeasure::AdHoc => b"adhoc",
            IdentityMeasure::Content => b"bytes",
            IdentityMeasure::Unmeasured => b"none",
        }
    }
}

/// The kernel's start time for a process: seconds and microseconds since the
/// epoch, as `proc_pidinfo` reports them. Together with a pid it names one
/// process instance, which is the strongest thing available about a process
/// whose code the platform will not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStart {
    pub sec: u64,
    pub usec: u32,
}

/// A 32-byte code-identity measurement of one executable, plus how it was
/// measured. Both halves bind into the grant key; the digest alone is not an
/// identity, because two measures can produce the same 32 bytes only by
/// coincidence and must still be told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeIdentity {
    pub measure: IdentityMeasure,
    pub digest: [u8; 32],
}

impl CodeIdentity {
    /// A cdhash off a running image, folded to 32 bytes under its own domain
    /// string (a cdhash is 20 bytes today and the width is not ours to fix).
    /// `adhoc` decides the measure, never the digest: a signature with no signer
    /// is a different KIND of claim, not a different hash.
    pub fn from_cdhash(cdhash: &[u8], adhoc: bool) -> Self {
        let mut h = Blake2b256::new();
        h.update(CDHASH_DOMAIN);
        h.update((cdhash.len() as u64).to_le_bytes());
        h.update(cdhash);
        Self {
            measure: if adhoc {
                IdentityMeasure::AdHoc
            } else {
                IdentityMeasure::Signed
            },
            digest: h.finalize().into(),
        }
    }

    /// A measurement of the executable's bytes, for a platform with no
    /// code-identity machinery to ask.
    pub fn content(digest: [u8; 32]) -> Self {
        Self {
            measure: IdentityMeasure::Content,
            digest,
        }
    }

    /// The nothing-to-measure case, keyed to one process INSTANCE: the pid plus
    /// the kernel's start time for it.
    ///
    /// Both halves are load-bearing. The pid alone recycles, and a recycled pid
    /// inheriting the previous process's window would be a real widening; the
    /// start time (microsecond resolution, kernel-supplied, not settable by the
    /// process) is what makes a new process a new identity. Neither is
    /// caller-supplied: the daemon reads the pid off the socket and walks the
    /// ancestry itself, so a caller cannot present a victim's pid and start time
    /// without actually being that process's descendant, which is the honest
    /// chain anyway.
    pub fn unmeasured(pid: i32, started: ProcessStart) -> Self {
        let mut h = Blake2b256::new();
        h.update(UNMEASURED_DOMAIN);
        h.update(pid.to_le_bytes());
        h.update(started.sec.to_le_bytes());
        h.update(started.usec.to_le_bytes());
        Self {
            measure: IdentityMeasure::Unmeasured,
            digest: h.finalize().into(),
        }
    }
}

/// One resolved ancestor: its pid (for display only, never hashed), executable
/// path, and the code-identity measurement of that executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub pid: i32,
    pub exe: PathBuf,
    pub identity: CodeIdentity,
}

/// The daemon's own measurement of who is calling: the leaf process and its
/// ancestors, root-first. Never built from anything the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub chain: Vec<Ancestor>,
}

impl Caller {
    /// A short human string for the approval screen, e.g. `zsh → claude → op`.
    pub fn provenance(&self) -> String {
        self.chain
            .iter()
            .map(|a| {
                a.exe
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| a.pid.to_string())
            })
            .collect::<Vec<_>>()
            .join(" \u{2192} ")
    }

    /// Whether this caller may touch a lease at all.
    ///
    /// The one disqualifier is having no identity whatsoever: an empty chain
    /// means the daemon could not name a single process behind the request (no
    /// peer pid, or a pid that resolves to nothing), and every such caller would
    /// derive the SAME grant key. That is the one shape where a window could be
    /// shared by callers with nothing in common, so it gets no window. Such a
    /// request is still gated and still shown to the human; only the auto-release
    /// is withheld.
    ///
    /// An ancestor that could not be MEASURED does not disqualify the chain; it
    /// is keyed to that process instance instead ([`CodeIdentity::unmeasured`]).
    /// See [`Caller::unmeasured`] for what that is worth.
    pub fn may_lease(&self) -> bool {
        !self.chain.is_empty()
    }

    /// The ancestors the platform would not describe, if any. Empty in the
    /// normal case; non-empty means this caller's window is keyed partly to a
    /// process instance rather than wholly to code, which the daemon logs and
    /// `sigil doctor` reports so the state is visible rather than mysterious.
    pub fn unmeasured(&self) -> Vec<&Ancestor> {
        self.chain
            .iter()
            .filter(|a| a.identity.measure == IdentityMeasure::Unmeasured)
            .collect()
    }
}

/// The kernel's view of the process table, abstracted so the ancestry walk can
/// be unit-tested against a synthetic tree.
pub trait ProcessTable {
    /// The parent pid of `pid`, or `None` at the root / for an unknown pid.
    fn parent(&self, pid: i32) -> Option<i32>;
    /// The executable path backing `pid` and the code identity of the image it
    /// is running, as ONE resolution: the two are read off the same object so a
    /// recycled pid cannot pair one process's path with another's measurement.
    /// `None` means the pid does not name a process at all, which truncates the
    /// walk.
    fn resolve(&self, pid: i32) -> Option<(PathBuf, CodeIdentity)>;
}

/// Walk from `start` up to the root, resolving each process. Returns the chain
/// root-first so the grant key is stable regardless of tree depth ordering.
pub fn walk_ancestry(table: &dyn ProcessTable, start: i32) -> Caller {
    let mut chain = Vec::new();
    let mut pid = start;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if pid <= 1 || !seen.insert(pid) {
            break;
        }
        let Some((exe, identity)) = table.resolve(pid) else {
            break;
        };
        chain.push(Ancestor { pid, exe, identity });
        match table.parent(pid) {
            Some(ppid) if ppid != pid => pid = ppid,
            _ => break,
        }
    }
    chain.reverse(); // root-first
    Caller { chain }
}

/// Which kind of request a scope string belongs to. Hashed into the grant key so
/// the two scope namespaces are separated: a rule named exactly like an SSH sign
/// scope (or vice versa) can never derive the same key, whatever the strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// A gated command run; the scope is the matched rule's name.
    Command,
    /// One SSH signature; the scope folds in the data-to-sign fingerprint.
    SshSignature,
}

impl ScopeKind {
    /// The tag hashed into the grant key. Short and fixed; never displayed.
    fn tag(self) -> &'static [u8] {
        match self {
            ScopeKind::Command => b"cmd",
            ScopeKind::SshSignature => b"ssh",
        }
    }
}

/// `BLAKE2b(domain ++ chain ++ project_root ++ kind ++ scope)`, the lease grant
/// key.
///
/// Only the stable code identity of each ancestor is bound in, never its pid.
/// Two runs of the same tool tree for the same kind and scope therefore share a
/// grant key (so one approval leases the burst); a different tool chain, kind, or
/// scope derives a different key. `project_root` still hashes in when a caller
/// supplies one, but the command path passes it empty on purpose (see the module
/// docs): a lease is scoped to the rule, not to the directory the command
/// happened to run in.
///
/// Every field is length-prefixed, so no two different inputs can serialize to
/// the same byte string. Each ancestor contributes its path, the tag naming HOW
/// its identity was measured ([`IdentityMeasure`]), and the digest, so two
/// measures can never derive one key even if their 32 bytes coincided.
///
/// Read "a different tool chain derives a different key" as the honest-tree
/// statement it is, never as unforgeability. Every input above is a property of
/// code on disk plus the shape of the tree, all of it readable with `ps`, so a
/// chain in which every ancestor MEASURES can be reconstructed from scratch by
/// anyone able to exec those same binaries from those same paths. The unmeasured
/// branch is the only one that binds something an outsider cannot restage (a
/// live process instance). See the module docs.
pub fn grant_key(caller: &Caller, kind: ScopeKind, project_root: &str, scope: &str) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(GRANT_DOMAIN);
    h.update((caller.chain.len() as u64).to_le_bytes());
    for a in &caller.chain {
        let exe = a.exe.as_os_str().as_encoded_bytes();
        h.update((exe.len() as u64).to_le_bytes());
        h.update(exe);
        let measure = a.identity.measure.tag();
        h.update((measure.len() as u64).to_le_bytes());
        h.update(measure);
        h.update(a.identity.digest);
    }
    let root = project_root.as_bytes();
    h.update((root.len() as u64).to_le_bytes());
    h.update(root);
    let tag = kind.tag();
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag);
    let scope = scope.as_bytes();
    h.update((scope.len() as u64).to_le_bytes());
    h.update(scope);
    h.finalize().into()
}

/// Everything besides the grant key that a lease must match on. Grouped into one
/// value so three adjacent strings can never be passed in the wrong order, and
/// so a lookup is forced to name the same three things a grant did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBinding {
    /// The account/source label the grant covers. Empty for a plain gate, which
    /// injects nothing and so has no account to bind.
    pub account: String,
    /// The matched rule's name for a command lease (so the whole rule is
    /// covered, not one argv). Never a raw command line.
    pub scope: String,
    /// A fingerprint of the exact source material a cached value came from (for
    /// sealed inline `env`, the sealed record's ephemeral public point, which is
    /// fresh on every re-seal). Empty when the lease caches nothing. A lookup
    /// misses once the source is re-sealed, so a stale plaintext can never be
    /// injected: the run falls back to a fresh approval.
    pub source: String,
    /// The config generation this grant was decided under.
    ///
    /// Rule invalidation on reload cannot cover a lease that does not exist yet:
    /// an approval blocks on the phone for as long as the human takes, and a
    /// config edit landing during that wait is invalidated before the grant is
    /// filed. Binding the generation closes that by construction rather than by
    /// timing, since a lease decided under generation N cannot match any lookup
    /// after a reload has moved it.
    pub config_gen: u64,
}

impl LeaseBinding {
    /// A binding over cached source material, decided under config `generation`.
    pub fn cached(account: &str, scope: &str, source: &str, generation: u64) -> Self {
        Self {
            account: account.to_string(),
            scope: scope.to_string(),
            source: source.to_string(),
            config_gen: generation,
        }
    }

    /// A binding for a lease that caches nothing (the plain-gate presence
    /// marker): no source material to pin.
    pub fn presence(account: &str, scope: &str, generation: u64) -> Self {
        Self::cached(account, scope, "", generation)
    }
}

/// A granted lease: a RAM-only, scoped, TTL-bound auto-approve window.
///
/// `token` is what the grant releases on a later matching run. A plain gate
/// stores an empty marker (it injects nothing, so the lease only means "this
/// caller already got a yes"); a sealed inline `env` rule stores the unsealed
/// values, which is the one place a credential outlives a single request. Every
/// removal path drops the `Zeroizing` token and wipes it.
struct Lease {
    grant: [u8; 32],
    /// This window's opaque id: 128 bits of OS randomness, minted when the window
    /// OPENS and preserved for its whole life (a refresh extends one window, it
    /// does not start another). RAM-only, and it dies with the window.
    ///
    /// It exists because **the grant key cannot do this job**, on three counts:
    ///
    /// * It is DETERMINISTIC. The same caller chain running the same rule derives
    ///   the same key tomorrow, so a key names a *lease shape*, not a *lease*. A
    ///   revoke that named only the key would be aimed at every window that shape
    ///   will ever have -- fine for a human typing `sigil lease revoke <prefix>`
    ///   at a terminal, not fine for a message that crossed a hostile relay and
    ///   could be handed back to a later daemon.
    /// * It is NOT UNIQUE. Several live windows share one key with different
    ///   [`LeaseBinding`]s, so revoking "the row I tapped" by key would kill
    ///   unseen siblings.
    /// * It is a DURABLE CORRELATOR: a hash of the caller's ancestor
    ///   code-identity chain plus the rule, describing the shape of the machine,
    ///   outliving the window and surviving in phone storage across re-pairs.
    ///
    /// So the remote path names this instead, exactly
    /// ([`LeaseStore::revoke_id`]), and the grant key never leaves the Mac.
    ///
    /// Random rather than a granted-at timestamp: two windows granted in the same
    /// millisecond would share a timestamp, a clock is a thing that moves, and
    /// [`LeaseStore::grant`] does not re-stamp `granted` on a refresh, so a
    /// re-approved window would carry the original instant and a stale revoke
    /// would still land on it.
    id: [u8; 16],
    binding: LeaseBinding,
    /// The daemon-rendered coverage label for the rule this window covers, e.g.
    /// `op read`. Display only, and deliberately NOT part of [`LeaseBinding`]:
    /// the binding is the lookup key, and a description of a window must never be
    /// able to widen, narrow, or split it. Empty when none was rendered.
    covers: String,
    token: Token,
    granted: Instant,
    expires: Instant,
}

/// A read-only view of an active lease for `sigil lease list`.
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    pub grant_hex: String,
    /// This window's opaque id as lowercase hex (32 chars). Unlike
    /// [`Self::grant_hex`] it names ONE window, is unique across windows, and is
    /// derived from nothing, so it is the only identifier safe to hand to a remote
    /// controller. See [`Lease::id`].
    pub lease_id: String,
    pub account: String,
    /// The rule name the lease covers. Display must make the breadth plain: the
    /// lease covers any command that rule matches, not the one that opened it.
    pub scope: String,
    /// What that rule matches, in the daemon's own words (`op read`,
    /// `op with --account "rowmhq.1password.eu"`, …): the same string the approver
    /// consented to, so the CLI states the breadth instead of gesturing at it.
    /// Empty when the daemon rendered none.
    pub covers: String,
    pub remaining: Duration,
    pub age: Duration,
}

/// The character width of a lease id in hex. Mirrors
/// [`sigil_proto::LEASE_ID_CHARS`]; asserted equal in the tests below so the two
/// crates can never drift into disagreeing about what an id is.
const LEASE_ID_HEX_CHARS: usize = 32;

/// The only capabilities the remote (phone) lease-control path is given.
///
/// This trait exists to make a class of bug **structurally impossible** rather
/// than merely absent. The daemon's remote approver holds one of these, not a
/// [`LeaseStore`], so no code reachable from an inbound network message can call
/// [`LeaseStore::grant`], [`LeaseStore::revoke`] (the prefix-matched CLI path),
/// [`LeaseStore::token_for`] (which hands out cached credential values), or
/// anything else the store can do. A future edit that wanted to would have to
/// widen this trait, which is a visible, reviewable act.
///
/// Read the two methods as the whole authority granted to a paired phone: it may
/// see which windows are open, and it may close one. It may never open one,
/// extend one, or read what one holds.
pub trait LeaseControl: Send + Sync {
    /// Active windows, newest first, for display on the approver.
    fn list(&self) -> Vec<LeaseInfo>;
    /// Close exactly the window named by this opaque id; see
    /// [`LeaseStore::revoke_id`].
    fn revoke_id(&self, lease_id: &str) -> bool;
}

impl LeaseControl for LeaseStore {
    fn list(&self) -> Vec<LeaseInfo> {
        LeaseStore::list(self)
    }
    fn revoke_id(&self, lease_id: &str) -> bool {
        LeaseStore::revoke_id(self, lease_id)
    }
}

/// All active leases. The tokens live only here, in RAM; every removal path
/// drops the `Zeroizing` token and so wipes it.
#[derive(Default)]
pub struct LeaseStore {
    inner: Mutex<Vec<Lease>>,
}

impl LeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant (or refresh) a lease for `grant` + `binding` with `ttl`. Refreshing
    /// replaces the cached token, so the newest approval's values are the ones
    /// served (the old ones are dropped, and so zeroized).
    ///
    /// `covers` is the display-only coverage label for the rule the binding names
    /// (see [`Lease::covers`]). It never participates in the match, so it cannot
    /// change which runs a window serves; a refresh re-stamps it so the readout
    /// follows the latest approval rather than the first one.
    pub fn grant(
        &self,
        grant: [u8; 32],
        binding: &LeaseBinding,
        covers: &str,
        token: Token,
        ttl: Duration,
    ) {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        if let Some(l) = leases
            .iter_mut()
            .find(|l| l.grant == grant && &l.binding == binding)
        {
            l.token = token;
            l.covers = covers.to_string();
            l.expires = now + ttl;
            // The id is deliberately NOT re-minted. A refresh extends the one
            // window the human is already looking at, so a revoke they aimed at it
            // before the refresh must still land. A new id is minted only when a
            // window genuinely ended and a fresh approval opened another, which is
            // exactly the case a stale revoke must not reach.
            return;
        }
        leases.push(Lease {
            grant,
            id: new_lease_id(),
            binding: binding.clone(),
            covers: covers.to_string(),
            token,
            granted: now,
            expires: now + ttl,
        });
    }

    /// The token for an active lease matching `grant` + `binding`, if any. All
    /// four legs must match: a different account, rule, or source fingerprint is
    /// a miss, and a miss means a fresh approval. Expired leases are purged (and
    /// zeroized) as a side effect.
    pub fn token_for(&self, grant: &[u8; 32], binding: &LeaseBinding) -> Option<Token> {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        leases
            .iter()
            .find(|l| &l.grant == grant && &l.binding == binding)
            .map(|l| l.token.clone())
    }

    /// Active leases, newest first, for display.
    pub fn list(&self) -> Vec<LeaseInfo> {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        let mut out: Vec<LeaseInfo> = leases
            .iter()
            .map(|l| LeaseInfo {
                grant_hex: hex32(&l.grant),
                lease_id: hex16(&l.id),
                account: l.binding.account.clone(),
                scope: l.binding.scope.clone(),
                covers: l.covers.clone(),
                remaining: l.expires.saturating_duration_since(now),
                age: now.saturating_duration_since(l.granted),
            })
            .collect();
        out.sort_by_key(|l| std::cmp::Reverse(l.age));
        out
    }

    /// Revoke every lease whose grant-key hex starts with `prefix`. Returns the
    /// number zeroized.
    pub fn revoke(&self, prefix: &str) -> usize {
        let mut leases = self.inner.lock().expect("lease store poisoned");
        let before = leases.len();
        leases.retain(|l| !hex32(&l.grant).starts_with(prefix));
        before - leases.len()
    }

    /// Revoke the ONE live lease whose opaque id is exactly `lease_id`. Returns
    /// whether one was found and zeroized.
    ///
    /// This is the remote (phone) revoke path, and it is deliberately unlike
    /// [`revoke`](Self::revoke) in every respect that matters:
    ///
    /// * **Exact, not prefix.** A prefix is a convenience for a human typing at a
    ///   terminal who can see what they are aiming at. A message off the network
    ///   gets no such latitude, and the reason is concrete: `"".starts_with(p)`
    ///   holds for every string, so a truncated or empty identifier reaching the
    ///   prefix API would be a silent global lease wipe reported as a success.
    ///   The width is re-checked here rather than trusted from the caller.
    /// * **Keyed on the opaque id, never the grant key.** A grant key is
    ///   deterministic and shared across windows; the id names exactly one window
    ///   and nothing that will exist later ([`Lease::id`]). That is what makes a
    ///   captured revoke, re-flown after a restart against an empty replay guard,
    ///   inert rather than dangerous.
    ///
    /// Expired leases are purged (and zeroized) first, so a window that lapsed on
    /// its own reports `false` exactly like one that was never held. The caller
    /// must not distinguish the reasons for `false`; see
    /// [`LeaseRevokeReply`](sigil_proto::LeaseRevokeReply).
    pub fn revoke_id(&self, lease_id: &str) -> bool {
        // An id that is not exactly-width lowercase hex cannot name a window this
        // store minted, so refuse before touching anything. Belt to the proto's
        // braces: neither layer relies on the other having checked.
        if lease_id.len() != LEASE_ID_HEX_CHARS || !lease_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return false;
        }
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        let before = leases.len();
        leases.retain(|l| hex16(&l.id) != lease_id);
        before != leases.len()
    }

    /// Revoke every lease whose scope is exactly `scope`. The config-change path:
    /// a lease names a rule by a mutable string, so when that rule is removed or
    /// edited the window it opened must die with it rather than transfer to the
    /// new definition. Returns the number zeroized.
    pub fn revoke_scope(&self, scope: &str) -> usize {
        let mut leases = self.inner.lock().expect("lease store poisoned");
        let before = leases.len();
        leases.retain(|l| l.binding.scope != scope);
        before - leases.len()
    }

    /// Drop and zeroize every lease. The daemon-restart path.
    pub fn clear(&self) -> usize {
        let mut leases = self.inner.lock().expect("lease store poisoned");
        let n = leases.len();
        leases.clear();
        n
    }

    /// Count of active leases (purging expired first).
    pub fn active(&self) -> usize {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        leases.len()
    }
}

/// Lowercase hex of a 32-byte key.
pub fn hex32(bytes: &[u8; 32]) -> String {
    hex(bytes)
}

/// Lowercase hex of a 16-byte lease instance id.
pub fn hex16(bytes: &[u8; 16]) -> String {
    hex(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A fresh opaque lease id from the OS CSPRNG. See [`Lease::id`] for why this is
/// random rather than a timestamp or a counter.
fn new_lease_id() -> [u8; 16] {
    use rand_core::RngCore;
    let mut id = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut id);
    id
}

/// The peer process id on the far end of a unix socket, verified by the kernel.
///
/// NEEDS-VERIFICATION (macOS `LOCAL_PEERPID` value / behaviour under
/// launchd-spawned callers). Confirm the pid matches the true caller with:
///   lsof -p <pid>   # against the pid the daemon logs for a known `op` call
#[cfg(target_os = "macos")]
pub fn peer_pid(fd: std::os::fd::RawFd) -> Option<i32> {
    // <sys/un.h>: SOL_LOCAL = 0, LOCAL_PEERPID = 0x002.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `pid`, a live pid_t.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0 && pid > 0).then_some(pid)
}

#[cfg(target_os = "linux")]
pub fn peer_pid(fd: std::os::fd::RawFd) -> Option<i32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred; len bounds the write.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0 && cred.pid > 0).then_some(cred.pid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_pid(_fd: std::os::fd::RawFd) -> Option<i32> {
    None
}

/// The real process table: `proc_pidinfo` for ancestry, and the platform's own
/// code identity of the RUNNING image for both the path and the measurement.
///
/// Nothing is measured from a path and nothing is memoized. A cache would have
/// to be keyed on something, and every candidate key is either forgeable by the
/// file's owner (any stat field) or a claim about a file rather than about a
/// running process; being told an ancestor is code it is no longer running is
/// exactly the failure this measurement exists to avoid. Measuring afresh costs
/// fractions of a millisecond per ancestor (see [`measure_running_image`]),
/// which is noise beside the `op` child the request goes on to spawn.
pub struct SysProcessTable;

/// Measure the image running as `pid`: its executable path and its code
/// identity, both off the one guest code object the platform vouched for.
///
/// `Err` when the platform will not answer for that pid at all (it exited, its
/// image is gone) or will not vouch for the image (the file at its path was
/// replaced after exec, `-67034 errSecCSStaticCodeChanged`). The caller keeps
/// the process in the chain, under [`IdentityMeasure::Unmeasured`] and keyed to
/// the process instance, and says so out loud.
///
/// Cost, measured on an M-series Mac (release build, no cache anywhere): 0.15ms
/// for an ad-hoc Homebrew binary, 0.47ms for `/bin/zsh`, 1.2-2.1ms for a large
/// Developer-ID binary, and **6.3ms for a whole real 6-deep chain** (login, zsh,
/// claude, zsh, cargo, leaf) on every gated command. That is an order of
/// magnitude below the `op` child the command goes on to spawn (40-90ms for
/// `op --version` alone, more for a real read) and two below the 236ms the
/// original unconditional content hash cost on the same chain.
#[cfg(target_os = "macos")]
fn measure_running_image(
    pid: i32,
) -> Result<(PathBuf, CodeIdentity), crate::peercode::GuestFailure> {
    let m = crate::peercode::measure_guest(pid)?;
    Ok((m.exe, CodeIdentity::from_cdhash(&m.cdhash, m.adhoc)))
}

/// One ancestor the platform would not describe, remembered so a human can find
/// out why their approvals came back.
///
/// Non-secret by construction: a pid, a start time, an executable path and a
/// fixed reason string. It never leaves the machine (`sigil doctor` reads it
/// over the local control socket) and it holds nothing about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmeasuredNote {
    pub pid: i32,
    pub started: ProcessStart,
    pub exe: PathBuf,
    pub reason: crate::peercode::GuestFailure,
}

impl UnmeasuredNote {
    /// The ancestor's short name, for a one-line report.
    pub fn name(&self) -> String {
        self.exe
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.pid.to_string())
    }
}

/// Cap on remembered notes. A handful of ancestors go unmeasurable in a long
/// session; this exists only so a process churning through unmeasurable
/// executables cannot grow the daemon. The oldest is evicted, which at worst
/// costs a repeated log line later.
///
/// Only the macOS and Linux `ProcessTable`s record notes today, so elsewhere
/// this is reached from the registry's tests and from nowhere else. It stays
/// compiled on every platform because the registry logic is
/// platform-independent and those tests are what keep it honest.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
const UNMEASURED_NOTES_MAX: usize = 64;

fn unmeasured_registry() -> &'static Mutex<Vec<UnmeasuredNote>> {
    static NOTES: std::sync::OnceLock<Mutex<Vec<UnmeasuredNote>>> = std::sync::OnceLock::new();
    NOTES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Every ancestor this daemon has failed to measure, oldest first.
pub fn unmeasured_notes() -> Vec<UnmeasuredNote> {
    unmeasured_registry()
        .lock()
        .expect("unmeasured registry poisoned")
        .clone()
}

/// The unmeasurable ancestors that are still running, for a report about the
/// state a human is in RIGHT NOW rather than about everything that ever
/// happened. The process instance is checked, not just the pid: a recycled pid
/// is a different process and its predecessor's note is history, not news.
pub fn live_unmeasured_notes() -> Vec<UnmeasuredNote> {
    unmeasured_notes()
        .into_iter()
        .filter(still_running)
        .collect()
}

#[cfg(target_os = "macos")]
fn still_running(note: &UnmeasuredNote) -> bool {
    start_time(note.pid) == Some(note.started)
}

#[cfg(target_os = "linux")]
fn still_running(note: &UnmeasuredNote) -> bool {
    start_time(note.pid) == Some(note.started)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn still_running(_note: &UnmeasuredNote) -> bool {
    false
}

/// Record an unmeasurable ancestor and log it ONCE per executable and reason.
///
/// Once, not once per command: a gated command walks the same chain every time,
/// and an ancestor that will not measure now will not measure for the rest of its
/// life, so per-command logging would bury the daemon log in a repetition that
/// says nothing new.
///
/// The dedup key is the PATH plus the reason, not the process instance, which is
/// R4-F3. An instance key is right for a long-lived ancestor and degenerate for
/// the leaf: the shim is a fresh process per gated command, so a build whose shim
/// will not measure (an unsigned x86_64 one, where every process answers `-5`)
/// used to emit a line and consume a registry slot per command, and the 64-slot
/// cap then evicted the long-lived note `sigil doctor` exists to surface. Keyed
/// by path, that whole class collapses to one entry and one line, and the entry
/// is REFRESHED to the newest instance so the row keeps naming a process that is
/// actually running. Nothing is lost: the actionable content of the line is the
/// path and the reason, and the pid is only there to find it with.
///
/// See [`UNMEASURED_NOTES_MAX`] for why this is compiled but uncalled off
/// macOS and Linux.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn note_unmeasured(note: UnmeasuredNote) {
    let mut notes = unmeasured_registry()
        .lock()
        .expect("unmeasured registry poisoned");
    if let Some(seen) = notes
        .iter_mut()
        .find(|n| n.exe == note.exe && n.reason == note.reason)
    {
        // Same problem, newer process: keep the row current and stay quiet.
        *seen = note;
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "sigil daemon: [{ts}] caller ancestor not measurable \u{b7} {} \u{b7} pid {} \u{b7} {} \u{b7} \
         leases under it are keyed to this process, not to its code",
        note.exe.display(),
        note.pid,
        note.reason.explain(),
    );
    if notes.len() >= UNMEASURED_NOTES_MAX {
        let doomed = doomed_index(&notes, still_running);
        notes.remove(doomed);
    }
    notes.push(note);
}

/// Which note the registry drops when it is full: the first whose process is
/// over, and only if every note is still live, the oldest.
///
/// Eviction order matters because the registry's whole job is answering "what is
/// the human in RIGHT NOW" (`sigil doctor` reads only the live notes). A note
/// about a process that has exited is history and costs nothing to drop; dropping
/// a live one loses the row that was going to explain why approvals came back.
///
/// See [`UNMEASURED_NOTES_MAX`] for why this is compiled but uncalled off
/// macOS and Linux.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn doomed_index(notes: &[UnmeasuredNote], live: impl Fn(&UnmeasuredNote) -> bool) -> usize {
    notes.iter().position(|n| !live(n)).unwrap_or_default()
}

/// The kernel's BSD info for `pid`: parent, start time, and the rest.
#[cfg(target_os = "macos")]
fn bsdinfo(pid: i32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info` and returns
    // the count written, or <= 0 on failure.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n >= size).then_some(info)
}

/// The executable path `proc_pidpath` reports for `pid`. Used only where the
/// platform would not describe the image: the measured path always comes off the
/// guest object instead.
#[cfg(target_os = "macos")]
fn proc_path(pid: i32) -> Option<PathBuf> {
    let mut buf = [0u8; 4096];
    // SAFETY: proc_pidpath writes at most buf.len() bytes and returns the
    // length written, or <= 0 on failure.
    let n =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..n as usize]).ok()?;
    Some(PathBuf::from(s))
}

#[cfg(target_os = "macos")]
impl ProcessTable for SysProcessTable {
    fn parent(&self, pid: i32) -> Option<i32> {
        let ppid = bsdinfo(pid)?.pbi_ppid as i32;
        (ppid > 0).then_some(ppid)
    }

    fn resolve(&self, pid: i32) -> Option<(PathBuf, CodeIdentity)> {
        let failure = match measure_running_image(pid) {
            Ok(resolved) => return Some(resolved),
            Err(failure) => failure,
        };
        // The platform would not describe this process's image. It still gets a
        // name in the chain, because the human on the phone should see the whole
        // tree that reached the daemon, and it still gets an identity, because a
        // self-updating tool that deletes its own binary mid-session is the
        // common cause and must not silently cost the session its leases. That
        // identity is the process INSTANCE (pid plus kernel start time), so it
        // holds while this process lives and no new process can inherit it.
        //
        // Both halves have to come from the kernel. Without a start time there is
        // no instance to key on, so the walk truncates here rather than keying on
        // a pid that recycles; a shorter chain is a different grant key, never a
        // wider one.
        let started = start_time(pid)?;
        let exe = proc_path(pid)?;
        note_unmeasured(UnmeasuredNote {
            pid,
            started,
            exe: exe.clone(),
            reason: failure,
        });
        Some((exe, CodeIdentity::unmeasured(pid, started)))
    }
}

/// The kernel's start time for `pid`.
#[cfg(target_os = "macos")]
fn start_time(pid: i32) -> Option<ProcessStart> {
    let info = bsdinfo(pid)?;
    Some(ProcessStart {
        sec: info.pbi_start_tvsec,
        usec: info.pbi_start_tvusec as u32,
    })
}

// ---- Linux: ancestry from /proc, code identity from a hashed fd ----
//
// There is no guest-code-object machinery to ask here (no cdhash), so
// `resolve()` measures by hashing the executable's bytes through the fd
// `/proc/<pid>/exe` opens rather than by reading it from a path. See
// `docs/design/linux-code-identity.md` for the verification this rests on
// (a rename over the path does not move the hash; an in-place rewrite is
// refused outright) and for the daemon-uid precondition the whole fill
// depends on.

/// `/proc/<pid>/stat`, split after the `pid (comm) ` prefix. `comm` is the
/// only field that can itself contain spaces or a `)` (it is user/attacker
/// settable via `exec`/`prctl(PR_SET_NAME)`), which is why this splits on the
/// LAST `)` rather than counting fields from the start. What remains begins at
/// field 3 (`state`) in `proc(5)`'s 1-indexed numbering, so field `k` (k >= 3)
/// sits at index `k - 3` of the returned vector.
#[cfg(target_os = "linux")]
fn parse_stat_fields(raw: &str) -> Option<Vec<String>> {
    let close = raw.rfind(')')?;
    Some(
        raw.get(close + 1..)?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    )
}

/// Read and parse `/proc/<pid>/stat` for `pid`. `None` for any pid that does
/// not currently name a process, which is the common case this walk needs to
/// truncate on rather than fail on.
#[cfg(target_os = "linux")]
fn proc_stat_fields(pid: i32) -> Option<Vec<String>> {
    parse_stat_fields(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Ticks per second `/proc/<pid>/stat`'s start-time field is counted in.
/// POSIX requires this fixed for the life of the process, so one `sysconf`
/// call serves every pid. Tower measures 100 (`getconf CLK_TCK`), which gives
/// 10ms resolution on the start time -- coarser than macOS's kernel-supplied
/// microseconds. See `docs/design/linux-code-identity.md` for what that costs.
#[cfg(target_os = "linux")]
fn clock_ticks_per_sec() -> Option<u64> {
    // SAFETY: sysconf reads a fixed kernel constant; no pointer arguments and
    // no memory it writes through.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then_some(hz as u64)
}

/// The kernel's boot time (seconds since the epoch), read fresh on every call
/// rather than cached once: caching it would silently mis-date every start
/// time this process computes for the rest of its life across a real reboot,
/// and the file is a handful of bytes.
#[cfg(target_os = "linux")]
fn boot_time_secs() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// The kernel's start time for `pid`, folded to the same (seconds,
/// microseconds) shape [`ProcessStart`] uses on macOS. `/proc/<pid>/stat`
/// field 22 is ticks since boot; `/proc/stat`'s `btime` anchors it to the
/// epoch. Both are kernel-supplied and neither is settable by the process
/// itself, which is what makes the pair usable as a process-instance identity.
#[cfg(target_os = "linux")]
fn start_time(pid: i32) -> Option<ProcessStart> {
    let fields = proc_stat_fields(pid)?;
    let ticks: u64 = fields.get(19)?.parse().ok()?; // field 22, index 22-3
    let hz = clock_ticks_per_sec()?;
    let btime = boot_time_secs()?;
    Some(ProcessStart {
        sec: btime + ticks / hz,
        usec: ((ticks % hz) * 1_000_000 / hz) as u32,
    })
}

/// Measure the image running as `pid`: hash its bytes through the fd
/// `/proc/<pid>/exe` opens, and read the path off that SAME fd via
/// `/proc/self/fd/<n>` rather than a second `/proc/<pid>/exe` lookup, so a pid
/// recycled between the two cannot pair one process's path with a different
/// process's digest.
///
/// `/proc/<pid>/exe` is not a path lookup: it is a kernel-held reference to
/// the inode the process was exec'd from, so opening it measures the RUNNING
/// image even after the file at that path is replaced (verified: a
/// rename-over the path leaves the hash unchanged) or unlinked (the kernel
/// keeps a live process's inode around; the link just gains a ` (deleted)`
/// suffix). The one thing it cannot survive is an in-place rewrite, and the
/// kernel refuses that outright (`ETXTBSY`) against any executable with a
/// running instance -- so unlike macOS there is no state here where the path
/// resolves but the content does not, and no platform-refusal branch is
/// needed for this attack. Full verification, with the commands run, is in
/// `docs/design/linux-code-identity.md`.
///
/// Opening (not just reading) `/proc/<pid>/exe` is gated by
/// `PTRACE_MODE_READ`: the same uid as `pid`, or `CAP_SYS_PTRACE`. A daemon
/// running as a third uid gets `Err(NoLiveImage)` for every ancestor it does
/// not share a uid with, which truncates the chain -- see the daemon-uid
/// section of the design note; this is a deployment decision, not a bug here.
#[cfg(target_os = "linux")]
fn measure_running_image(
    pid: i32,
) -> Result<(PathBuf, CodeIdentity), crate::peercode::GuestFailure> {
    use crate::peercode::GuestFailure;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let mut f =
        std::fs::File::open(format!("/proc/{pid}/exe")).map_err(|_| GuestFailure::NoLiveImage)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
        .map_err(|_| GuestFailure::NoLiveImage)?;
    let mut hasher = Blake2b256::new();
    let mut buf = [0u8; 65536];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(GuestFailure::NoLiveImage),
        }
    }
    Ok((path, CodeIdentity::content(hasher.finalize().into())))
}

#[cfg(target_os = "linux")]
impl ProcessTable for SysProcessTable {
    fn parent(&self, pid: i32) -> Option<i32> {
        let ppid: i32 = proc_stat_fields(pid)?.get(1)?.parse().ok()?; // field 4
        (ppid > 0).then_some(ppid)
    }

    fn resolve(&self, pid: i32) -> Option<(PathBuf, CodeIdentity)> {
        let failure = match measure_running_image(pid) {
            Ok(resolved) => return Some(resolved),
            Err(failure) => failure,
        };
        // Reachable only if the open above succeeded and a later read failed
        // (the permission gate already passed), or the process exited between
        // the open and here -- in which case this readlink fails too and the
        // walk truncates, same as macOS's "no live image" case. Keep the
        // ancestor named rather than dropping the whole chain over a read
        // failure that says nothing about who the caller is.
        let started = start_time(pid)?;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        note_unmeasured(UnmeasuredNote {
            pid,
            started,
            exe: exe.clone(),
            reason: failure,
        });
        Some((exe, CodeIdentity::unmeasured(pid, started)))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl ProcessTable for SysProcessTable {
    fn parent(&self, _pid: i32) -> Option<i32> {
        None
    }
    fn resolve(&self, _pid: i32) -> Option<(PathBuf, CodeIdentity)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    /// Synthetic process tree for exercising the ancestry walk deterministically.
    struct MapTable {
        parent: HashMap<i32, i32>,
        exe: HashMap<i32, PathBuf>,
        ident: HashMap<i32, CodeIdentity>,
    }

    impl MapTable {
        fn node(&mut self, pid: i32, ppid: i32, exe: &str, id: u8) {
            self.parent.insert(pid, ppid);
            self.exe.insert(pid, PathBuf::from(exe));
            self.ident.insert(pid, CodeIdentity::content([id; 32]));
        }
    }

    impl ProcessTable for MapTable {
        fn parent(&self, pid: i32) -> Option<i32> {
            self.parent.get(&pid).copied()
        }
        fn resolve(&self, pid: i32) -> Option<(PathBuf, CodeIdentity)> {
            let exe = self.exe.get(&pid).cloned()?;
            let identity = self
                .ident
                .get(&pid)
                .copied()
                .unwrap_or_else(|| CodeIdentity::content([0u8; 32]));
            Some((exe, identity))
        }
    }

    /// The kind every command-path test derives keys under.
    const CMD: ScopeKind = ScopeKind::Command;

    fn tree() -> MapTable {
        // 1 (init) → 100 zsh → 200 claude → 300 op
        let mut t = MapTable {
            parent: HashMap::new(),
            exe: HashMap::new(),
            ident: HashMap::new(),
        };
        t.node(300, 200, "/opt/homebrew/bin/op", 3);
        t.node(200, 100, "/usr/local/bin/claude", 2);
        t.node(100, 1, "/bin/zsh", 1);
        t
    }

    #[test]
    fn ancestry_walk_is_root_first_and_stops_at_init() {
        let caller = walk_ancestry(&tree(), 300);
        let names: Vec<_> = caller
            .chain
            .iter()
            .map(|a| a.exe.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["zsh", "claude", "op"]);
        assert_eq!(caller.provenance(), "zsh \u{2192} claude \u{2192} op");
    }

    #[test]
    fn ancestry_walk_terminates_on_a_cycle() {
        let mut t = MapTable {
            parent: HashMap::new(),
            exe: HashMap::new(),
            ident: HashMap::new(),
        };
        t.node(10, 20, "/a", 1);
        t.node(20, 10, "/b", 2); // cycle
        let caller = walk_ancestry(&t, 10);
        assert_eq!(caller.chain.len(), 2, "cycle must not loop forever");
    }

    #[test]
    fn grant_key_is_stable_for_the_same_tree_scope_and_root() {
        let c = walk_ancestry(&tree(), 300);
        let a = grant_key(
            &c,
            CMD,
            "/Projects/rowm",
            "item get .env --vault Engineering",
        );
        let b = grant_key(
            &c,
            CMD,
            "/Projects/rowm",
            "item get .env --vault Engineering",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn grant_key_ignores_recycled_pids() {
        // Same executables and identities, different pids: the grant key must
        // not move, because pids recycle and are excluded from the hash.
        let mut t2 = MapTable {
            parent: HashMap::new(),
            exe: HashMap::new(),
            ident: HashMap::new(),
        };
        t2.node(999, 888, "/opt/homebrew/bin/op", 3);
        t2.node(888, 777, "/usr/local/bin/claude", 2);
        t2.node(777, 1, "/bin/zsh", 1);

        let a = grant_key(&walk_ancestry(&tree(), 300), CMD, "/p", "s");
        let b = grant_key(&walk_ancestry(&t2, 999), CMD, "/p", "s");
        assert_eq!(a, b, "grant key must not depend on pids");
    }

    /// The command path's call shape: no project root, the matched rule's name
    /// as the scope. Mirrors `daemon::fulfill` so these tests move if it does.
    fn rule_key(caller: &Caller, rule: &str) -> [u8; 32] {
        grant_key(caller, CMD, "", rule)
    }

    #[test]
    fn request_kinds_live_in_separate_scope_namespaces() {
        // A rule may be named anything, including exactly what the SSH path uses
        // as its scope. The kind tag is what stops the two from ever deriving one
        // key (and so from ever sharing a coalesced approval).
        let c = walk_ancestry(&tree(), 300);
        let same = "ssh-sign GitHub SHA256:abc";
        assert_ne!(
            grant_key(&c, ScopeKind::Command, "", same),
            grant_key(&c, ScopeKind::SshSignature, "", same),
            "identical scope strings of different kinds must not collide"
        );
    }

    #[test]
    fn one_rule_covers_any_command_it_matches() {
        // The point of rule scoping: `op read A` and `op item get B` are the same
        // lease as long as the same caller chain runs them under the same rule.
        let c = walk_ancestry(&tree(), 300);
        assert_eq!(
            rule_key(&c, "op"),
            rule_key(&c, "op"),
            "the argv is not in the key at all, so any two commands under one rule match"
        );
    }

    #[test]
    fn cwd_no_longer_splits_a_lease() {
        // Historically the project root was hashed in, so a `cd` cost a fresh
        // approval. The command path now passes "", so the key is cwd-blind.
        let c = walk_ancestry(&tree(), 300);
        assert_eq!(rule_key(&c, "op"), grant_key(&c, CMD, "", "op"));
        assert_ne!(
            grant_key(&c, CMD, "/Projects/rowm", "op"),
            grant_key(&c, CMD, "/Projects/other", "op"),
            "the root still hashes in when a caller supplies one"
        );
    }

    #[test]
    fn different_rules_do_not_share_a_grant_key() {
        let c = walk_ancestry(&tree(), 300);
        assert_ne!(
            rule_key(&c, "op"),
            rule_key(&c, "op-account-rowmhq-1password-eu"),
            "a lease on one rule must not cover another rule"
        );
    }

    #[test]
    fn different_caller_chains_do_not_share_a_rule_lease() {
        // Same rule, different tool tree: the lease must not carry across. This
        // is the whole security boundary now that argv and cwd are out of the key.
        //
        // What it proves is separation between HONEST trees, and only that. It is
        // not a claim that a tree cannot be imitated: every input to the key is
        // reconstructible by anyone who can exec the same binaries from the same
        // paths in the same nesting (see the module docs, R4-F1).
        let mine = walk_ancestry(&tree(), 300);
        let mut other = tree();
        other.node(300, 200, "/opt/homebrew/bin/op", 3);
        other.node(200, 100, "/usr/local/bin/some-other-tool", 9);
        assert_ne!(
            rule_key(&mine, "op"),
            rule_key(&walk_ancestry(&other, 300), "op"),
            "a different caller chain is a different grant"
        );

        // And a tampered ancestor (same paths, different code identity) too.
        let mut tampered = tree();
        tampered
            .ident
            .insert(200, CodeIdentity::content([0x42; 32]));
        assert_ne!(
            rule_key(&mine, "op"),
            rule_key(&walk_ancestry(&tampered, 300), "op"),
            "ancestor code identity must still matter"
        );
    }

    #[test]
    fn grant_key_changes_with_root_scope_or_ancestry() {
        let c = walk_ancestry(&tree(), 300);
        let base = grant_key(&c, CMD, "/p", "s");
        assert_ne!(base, grant_key(&c, CMD, "/other", "s"), "root must matter");
        assert_ne!(base, grant_key(&c, CMD, "/p", "other"), "scope must matter");

        // A different ancestor identity (e.g. a tampered claude) must move it.
        let mut t = tree();
        t.ident.insert(200, CodeIdentity::content([0x42; 32]));
        assert_ne!(
            base,
            grant_key(&walk_ancestry(&t, 300), CMD, "/p", "s"),
            "ancestor code identity must matter"
        );
    }

    // ---- Ancestor code identity: the platform measure and its fallback ----

    /// A scratch dir for the measurement tests, unique per test and per process.
    ///
    /// Every caller is a macOS-only measurement test, so off macOS there is
    /// nothing to give it a directory for.
    #[cfg(target_os = "macos")]
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-measure-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn the_measures_are_domain_separated_in_the_grant_key() {
        // The core of the change: identical 32 bytes under different measures
        // must not derive one key. This is what makes a binary that gains a real
        // signature a DIFFERENT caller rather than silently the same one, and
        // what stops an ad-hoc cdhash from ever reading as a signing identity.
        let digest = [0x5a; 32];
        let mk = |identity: CodeIdentity| Caller {
            chain: vec![Ancestor {
                pid: 42,
                exe: PathBuf::from("/opt/homebrew/bin/op"),
                identity,
            }],
        };
        let with = |measure| CodeIdentity { measure, digest };
        let key = |i: CodeIdentity| grant_key(&mk(i), CMD, "", "op");
        let measures = [
            IdentityMeasure::Signed,
            IdentityMeasure::AdHoc,
            IdentityMeasure::Content,
            IdentityMeasure::Unmeasured,
        ];
        for (i, a) in measures.iter().enumerate() {
            for b in &measures[i + 1..] {
                assert_ne!(
                    key(with(*a)),
                    key(with(*b)),
                    "{a:?} and {b:?} share 32 bytes but must not share a key"
                );
            }
        }
    }

    #[test]
    fn a_cdhash_measurement_is_stable_and_distinguishing() {
        // The fold from a 20-byte cdhash to the 32 the chain carries must be a
        // function of the cdhash and nothing else, and must separate cdhashes.
        let a = CodeIdentity::from_cdhash(&[1u8; 20], false);
        assert_eq!(a, CodeIdentity::from_cdhash(&[1u8; 20], false));
        assert_eq!(a.measure, IdentityMeasure::Signed);
        assert_ne!(
            a.digest,
            CodeIdentity::from_cdhash(&[2u8; 20], false).digest
        );
        // Length is bound in, so a short cdhash cannot be a prefix of a long one.
        assert_ne!(
            a.digest,
            CodeIdentity::from_cdhash(&[1u8; 21], false).digest
        );
        // Ad-hoc is a different KIND of claim about the same bytes: same digest,
        // different measure, and the grant key separates them.
        let adhoc = CodeIdentity::from_cdhash(&[1u8; 20], true);
        assert_eq!(adhoc.digest, a.digest);
        assert_eq!(adhoc.measure, IdentityMeasure::AdHoc);
    }

    #[test]
    fn an_unmeasured_ancestor_is_keyed_to_one_process_instance() {
        // The weaker branch, and exactly how weak. An ancestor the platform will
        // not describe is keyed to the process instance: the same live process
        // keeps its window (the point -- a tool that deleted its own binary
        // mid-session must not silently cost the session its leases), while a
        // recycled pid must NOT inherit it, which is what the start time is for.
        let start = ProcessStart {
            sec: 1_770_000_000,
            usec: 123_456,
        };
        let later = ProcessStart {
            usec: start.usec + 1,
            ..start
        };
        assert_eq!(
            CodeIdentity::unmeasured(100, start).digest,
            CodeIdentity::unmeasured(100, start).digest,
            "one process instance keeps one identity while it lives"
        );
        assert_ne!(
            CodeIdentity::unmeasured(100, start).digest,
            CodeIdentity::unmeasured(100, later).digest,
            "a recycled pid must not inherit the previous process's window"
        );
        assert_ne!(
            CodeIdentity::unmeasured(100, start).digest,
            CodeIdentity::unmeasured(101, start).digest,
            "and a different pid is a different instance"
        );
        assert_eq!(
            CodeIdentity::unmeasured(100, start).measure,
            IdentityMeasure::Unmeasured,
            "it keeps its own measure tag, never Signed and never AdHoc"
        );

        // Such a chain may still lease. The only caller that may not is one with
        // no identity at all, because every one of those derives the same key.
        let ancestor = |identity| Ancestor {
            pid: 7,
            exe: PathBuf::from("/bin/zsh"),
            identity,
        };
        let measured = Caller {
            chain: vec![
                ancestor(CodeIdentity::from_cdhash(&[9u8; 20], false)),
                ancestor(CodeIdentity::from_cdhash(&[8u8; 20], true)),
            ],
        };
        assert!(measured.may_lease());
        assert!(measured.unmeasured().is_empty());

        let mut mixed = measured.clone();
        mixed
            .chain
            .push(ancestor(CodeIdentity::unmeasured(7, start)));
        assert!(mixed.may_lease(), "an unmeasured ancestor still leases");
        assert_eq!(
            mixed.unmeasured().len(),
            1,
            "but it is reported, so the state is visible rather than mysterious"
        );
        assert!(
            !Caller { chain: vec![] }.may_lease(),
            "a caller with no identity at all gets no window"
        );
    }

    /// A live child to measure, killed when the guard drops.
    #[cfg(target_os = "macos")]
    struct Running(std::process::Child);

    /// The long-lived process the swap test needs, spawned from a COPY of a
    /// binary it may then overwrite. It has to be ad-hoc signed to run from an
    /// arbitrary path at all (a copy of a platform binary is arm64e and the
    /// kernel refuses to exec it outside the trust cache), and the one ad-hoc
    /// binary a unit test can always find is itself. So the test binary is
    /// copied and re-run pointed at this one ignored "test", which just sleeps.
    /// Ignored, and inert unless the env var is set, so a plain `cargo test` and
    /// even `cargo test -- --ignored` skip past it in microseconds.
    #[cfg(target_os = "macos")]
    const SLEEPER: &str = "lease::tests::a_sleeper_helper_for_the_swap_test";

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "helper process for the swap test, not a test"]
    fn a_sleeper_helper_for_the_swap_test() {
        if std::env::var_os("SIGIL_TEST_SLEEPER").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[cfg(target_os = "macos")]
    impl Running {
        /// A copy of this test binary, running the sleeper helper above.
        fn sleeper_at(path: &std::path::Path) -> Self {
            std::fs::copy(std::env::current_exe().expect("current exe"), path)
                .expect("copy an ad-hoc signed binary to the victim path");
            let child = std::process::Command::new(path)
                .args(["--exact", SLEEPER, "--ignored", "--test-threads=1"])
                .env("SIGIL_TEST_SLEEPER", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn");
            std::thread::sleep(std::time::Duration::from_millis(300));
            Self(child)
        }

        fn spawn(exe: &std::path::Path) -> Self {
            let child = std::process::Command::new(exe)
                .arg("30")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn");
            // Give the child time to exec; before that it is still a fork of the
            // test binary and would measure as the test binary.
            std::thread::sleep(std::time::Duration::from_millis(200));
            Self(child)
        }
        fn pid(&self) -> i32 {
            self.0.id() as i32
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_signed_binary_measures_as_the_platform_identity() {
        // /bin/sleep is signed by the platform, so the measurement must come
        // from the code signature of the RUNNING image, and the path must come
        // off that same object rather than from a second lookup.
        let sleeper = Running::spawn(std::path::Path::new("/bin/sleep"));
        let (exe, id) =
            measure_running_image(sleeper.pid()).expect("a live system binary measures");
        assert_eq!(exe, std::path::Path::new("/bin/sleep"));
        assert_eq!(
            id.measure,
            IdentityMeasure::Signed,
            "a platform binary has a signer"
        );
        let content: [u8; 32] = Blake2b256::digest(std::fs::read("/bin/sleep").unwrap()).into();
        assert_ne!(id.digest, content, "it is the cdhash, not the bytes");

        // Stability is the whole point (an unstable measure means a fresh
        // approval per command), and two binaries must never land on one
        // identity.
        assert_eq!(
            measure_running_image(sleeper.pid()).map(|(_, i)| i),
            Ok(id),
            "the same process measures the same way twice"
        );
        let other = Running::spawn(std::path::Path::new("/usr/bin/yes"));
        let (_, id2) = measure_running_image(other.pid()).expect("also signed");
        assert_ne!(id.digest, id2.digest, "two binaries, two identities");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_ad_hoc_process_measures_under_its_own_tag() {
        // This test binary is linker/ad-hoc signed: a signature with no signer,
        // whose cdhash asserts nothing a hash of the bytes does not. Reporting
        // it as a platform identity would overstate it.
        let (exe, id) =
            measure_running_image(std::process::id() as i32).expect("this process measures");
        assert_eq!(exe, std::env::current_exe().expect("current exe"));
        assert_eq!(
            id.measure,
            IdentityMeasure::AdHoc,
            "an ad-hoc signature is not a signing identity"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pid_that_names_no_process_yields_no_identity_at_all() {
        // A pid that names nothing is not "unmeasured", it is nothing: there is
        // no process instance to key on, so the walk truncates rather than
        // inventing an identity, and a caller with an empty chain gets no window.
        assert_eq!(
            measure_running_image(0),
            Err(crate::peercode::GuestFailure::NoLiveImage)
        );
        assert_eq!(SysProcessTable.resolve(0), None);
        assert!(
            !walk_ancestry(&SysProcessTable, 0).may_lease(),
            "a caller with no identity at all gets no window"
        );

        // The daemon's own chain, on the other hand, measures end to end: this is
        // the shape a real gated command arrives in, and it is what keeps the
        // unmeasured branch rare rather than routine.
        let me = walk_ancestry(&SysProcessTable, std::process::id() as i32);
        assert!(!me.chain.is_empty(), "this process has ancestors");
        assert!(me.may_lease());
        assert!(
            me.unmeasured().is_empty(),
            "a normal live chain measures end to end: {}",
            me.provenance()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn swapping_the_file_under_a_running_process_does_not_change_what_it_measures_as() {
        // The regression this measurement exists to prevent, end to end and with
        // a real second process. A caller who can write an ancestor's executable
        // path used to be able to choose that ancestor's identity, victim's
        // cdhash included, by replacing the file after exec: the static read
        // reported the SUBSTITUTED binary. Measured on the live image instead,
        // the platform refuses (-67034 errSecCSStaticCodeChanged) and the
        // ancestor drops to an identity of its own process instance, which is
        // nobody else's and is nothing the attacker chose.
        let dir = scratch("swap");
        let victim = dir.join("victim");
        let running = Running::sleeper_at(&victim);
        // The platform answers a fully resolved path (the scratch dir lives under
        // the /var -> /private/var symlink), so compare against the same form.
        let victim = victim.canonicalize().expect("canonical victim path");

        let (exe, before) = measure_running_image(running.pid()).expect("measures while honest");
        assert_eq!(exe, victim);
        assert_eq!(
            before.measure,
            IdentityMeasure::AdHoc,
            "a copy of this ad-hoc signed test binary measures as ad-hoc"
        );

        // The attack: put a different binary at that path while the process runs.
        // This is what used to hand the caller `/bin/ls`'s identity for a process
        // running none of that code. Rename-over rather than overwrite-in-place:
        // both flavours are refused by the platform, but this one leaves the
        // victim running, so the daemon's view of a live swapped ancestor is what
        // gets asserted below.
        let decoy = dir.join("decoy");
        std::fs::copy("/bin/ls", &decoy).expect("stage the substitute");
        std::fs::rename(&decoy, &victim).expect("rename the substitute over the exec path");

        assert_eq!(
            measure_running_image(running.pid()),
            Err(crate::peercode::GuestFailure::ImageNotVouched),
            "the platform must refuse to vouch for a swapped image"
        );
        let (path, id) = SysProcessTable
            .resolve(running.pid())
            .expect("the process is still named for the human");
        assert_eq!(path, victim);
        assert_eq!(
            id.measure,
            IdentityMeasure::Unmeasured,
            "a swapped image measures as nothing, never as the substituted binary"
        );
        assert_ne!(
            id.digest, before.digest,
            "so a window opened before the swap does not survive it"
        );
        // What it drops to is this process instance and nothing else: the
        // attacker gets an identity nobody holds, not the victim's.
        let started = start_time(running.pid()).expect("a live process has a start time");
        assert_eq!(id, CodeIdentity::unmeasured(running.pid(), started));
        assert_ne!(
            id.digest,
            CodeIdentity::unmeasured(
                running.pid(),
                ProcessStart {
                    usec: started.usec.wrapping_add(1),
                    ..started
                }
            )
            .digest,
            "and it is the instance, not the pid, that fixes it"
        );

        // The daemon says so out loud rather than degrading silently, and while
        // the process lives it is reported as the state the human is in now.
        let note = live_unmeasured_notes()
            .into_iter()
            .find(|n| n.pid == running.pid())
            .expect("the unmeasurable ancestor is recorded for `sigil doctor`");
        assert_eq!(note.reason, crate::peercode::GuestFailure::ImageNotVouched);
        assert_eq!(note.exe, victim);
        assert_eq!(note.started, started);

        // A note about a process that has since exited is history, not news.
        let stale = UnmeasuredNote {
            pid: running.pid(),
            started: ProcessStart {
                usec: started.usec.wrapping_add(1),
                ..started
            },
            ..note
        };
        assert!(
            !still_running(&stale),
            "a recycled pid must not keep its predecessor's note alive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R4-F3. The leaf of every chain is a fresh shim process per gated command,
    /// so a build whose shim will not measure hits this once per command. Keyed
    /// by process instance that was one log line and one registry slot each, and
    /// the cap then evicted the long-lived note the report exists to carry.
    #[test]
    fn a_repeating_unmeasurable_executable_collapses_to_one_note() {
        // A path no other test uses: the registry is process-wide.
        let exe = PathBuf::from("/nonexistent/sigil-r4f3/shim");
        for pid in 9_000..9_064 {
            note_unmeasured(UnmeasuredNote {
                pid,
                started: ProcessStart {
                    sec: 1_770_000_000 + u64::try_from(pid).unwrap_or(0),
                    usec: 1,
                },
                exe: exe.clone(),
                reason: crate::peercode::GuestFailure::ImageNotVouched,
            });
        }
        let mine: Vec<UnmeasuredNote> = unmeasured_notes()
            .into_iter()
            .filter(|n| n.exe == exe)
            .collect();
        assert_eq!(
            mine.len(),
            1,
            "64 runs of one unmeasurable executable must be one note, not 64"
        );
        // And the surviving note names the process that is running NOW, so the
        // doctor row is about a live problem rather than a dead first sighting.
        assert_eq!(mine[0].pid, 9_063);

        // A second reason for the same path is a different problem and does speak
        // up: the dedup is per path AND reason, not per path.
        note_unmeasured(UnmeasuredNote {
            pid: 9_100,
            started: ProcessStart {
                sec: 1_770_000_001,
                usec: 2,
            },
            exe: exe.clone(),
            reason: crate::peercode::GuestFailure::NoLiveImage,
        });
        assert_eq!(
            unmeasured_notes().iter().filter(|n| n.exe == exe).count(),
            2
        );
    }

    #[test]
    fn a_full_registry_evicts_a_finished_process_before_a_live_one() {
        let note = |pid| UnmeasuredNote {
            pid,
            started: ProcessStart {
                sec: 1_770_000_000,
                usec: 0,
            },
            exe: PathBuf::from(format!("/opt/tools/t{pid}")),
            reason: crate::peercode::GuestFailure::NoIdentity,
        };
        let notes: Vec<UnmeasuredNote> = (1..=4).map(note).collect();

        // The oldest is still running and the third has exited: the third goes,
        // so the report keeps the state the human is actually in.
        assert_eq!(doomed_index(&notes, |n| n.pid != 3), 2);
        // Every note live: the cap still has to give, and it gives up the oldest.
        assert_eq!(doomed_index(&notes, |_| true), 0);
        assert_eq!(doomed_index(&[], |_| true), 0);
    }

    // ---- Linux: ancestry via /proc, code identity via a hashed fd ----

    #[cfg(target_os = "linux")]
    fn linux_scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-linux-measure-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_fields_survive_a_comm_containing_parens_and_spaces() {
        // comm is set by the process itself (exec's argv[0] basename, or
        // prctl(PR_SET_NAME)) and can contain anything but NUL or `/`,
        // including parens and spaces. The parser must split on the LAST `)`
        // or a hostile comm can shift every field that follows, including
        // ppid.
        let raw = "4242 (evil) proc) S 4241 4242 4242 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        let fields = parse_stat_fields(raw).expect("parses");
        assert_eq!(fields[0], "S", "field 3, state");
        assert_eq!(fields[1], "4241", "field 4, ppid -- not shifted by the fake `)` in comm");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sys_process_table_parent_reads_the_real_ppid_from_proc() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            SysProcessTable.parent(child.id() as i32),
            Some(std::process::id() as i32),
            "the test process is the child's real parent"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_binary_measures_as_a_hash_of_its_own_bytes() {
        let mut sleeper = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        std::thread::sleep(Duration::from_millis(100));
        let pid = sleeper.id() as i32;

        let (exe, id) = measure_running_image(pid).expect("a live binary measures");
        assert_eq!(
            id.measure,
            IdentityMeasure::Content,
            "Linux has no signer to ask, so this is always Content"
        );
        // /proc/<pid>/exe resolves to the canonical inode path, which on a
        // usr-merged system is /usr/bin/sleep even when invoked as /bin/sleep.
        assert_eq!(
            exe,
            std::fs::canonicalize("/bin/sleep").expect("canonicalize the invoked path")
        );
        let expected: [u8; 32] =
            Blake2b256::digest(std::fs::read("/bin/sleep").expect("read it directly")).into();
        assert_eq!(
            id.digest, expected,
            "must be the same hash a direct read of the binary gives, while nothing has changed"
        );

        // Stable across repeat measurement.
        assert_eq!(
            measure_running_image(pid).map(|(_, i)| i),
            Ok(id),
            "the same process measures the same way twice"
        );

        // Two different binaries never collide. `cat` with its stdin held open
        // blocks on read() forever, so it stays alive without a fixed sleep.
        let mut other = std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a second, different binary");
        std::thread::sleep(Duration::from_millis(100));
        let (_, id2) = measure_running_image(other.id() as i32).expect("also measures");
        assert_ne!(id.digest, id2.digest, "two binaries, two identities");

        let _ = sleeper.kill();
        let _ = sleeper.wait();
        let _ = other.kill();
        let _ = other.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pid_that_names_no_process_yields_no_identity_at_all() {
        // pid 0 names no process on Linux; /proc/0 does not exist.
        assert_eq!(
            measure_running_image(0),
            Err(crate::peercode::GuestFailure::NoLiveImage)
        );
        assert_eq!(SysProcessTable.resolve(0), None);
        assert!(
            !walk_ancestry(&SysProcessTable, 0).may_lease(),
            "a caller with no identity at all gets no window"
        );

        // The daemon's own chain, the shape a real gated command arrives in:
        // this test binary and every ancestor above it share this process's
        // uid, so the whole chain measures end to end.
        let me = walk_ancestry(&SysProcessTable, std::process::id() as i32);
        assert!(!me.chain.is_empty(), "this process has ancestors");
        assert!(me.may_lease());
        assert!(
            me.unmeasured().is_empty(),
            "a normal same-uid chain measures end to end: {}",
            me.provenance()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn renaming_over_the_exe_path_does_not_change_what_a_running_process_measures_as() {
        // The core of the R3-F1-class attack, replayed on Linux: a caller who
        // can write an ancestor's executable path used to be able to choose
        // that ancestor's identity by replacing the file after exec. Verified
        // by hand first (see docs/design/linux-code-identity.md); this is the
        // same finding as a real test.
        let dir = linux_scratch("swap");
        let victim = dir.join("victim");
        // Stage under a different name and rename into place rather than
        // executing straight after `copy`: on some container storage drivers
        // (overlay2) a fresh copy can transiently answer ETXTBSY to an exec
        // that follows immediately, because the writeback that closed it has
        // not settled. A rename has no such window -- by the time it returns
        // the target is fully written and has no writer fd.
        std::fs::copy("/bin/sleep", dir.join("victim.tmp")).expect("stage the victim binary");
        std::fs::rename(dir.join("victim.tmp"), &victim).expect("place it before executing");
        let mut running = std::process::Command::new(&victim)
            .arg("30")
            .spawn()
            .expect("run the victim");
        std::thread::sleep(Duration::from_millis(100));
        let pid = running.id() as i32;

        let (_, before) = measure_running_image(pid).expect("measures while honest");
        assert_eq!(before.measure, IdentityMeasure::Content);

        // The attack: put a different binary at the same path while the
        // process is still running the original.
        let decoy = dir.join("decoy");
        std::fs::copy("/bin/ls", &decoy).expect("stage the substitute");
        std::fs::rename(&decoy, &victim).expect("rename the substitute over the exec path");

        let (_, after) = measure_running_image(pid)
            .expect("still measures: /proc/<pid>/exe outlives a rename at its old path");
        assert_eq!(
            after.digest, before.digest,
            "the running image is unchanged by a rename at its old path"
        );

        let substitute_digest: [u8; 32] =
            Blake2b256::digest(std::fs::read(&victim).expect("read what is now at the path"))
                .into();
        assert_ne!(
            after.digest, substitute_digest,
            "and it must differ from the substitute now sitting at that path -- proving this \
             measured the running image, never a fresh read by path"
        );

        let _ = running.kill();
        let _ = running.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_refuses_to_overwrite_a_running_executable_in_place() {
        // The other half of the finding: an in-place rewrite (no rename) is
        // refused outright, so there is no window where a byte-patched image
        // is served either.
        let dir = linux_scratch("etxtbsy");
        let victim = dir.join("victim");
        // See the rename-into-place comment in the swap test above.
        std::fs::copy("/bin/sleep", dir.join("victim.tmp")).expect("stage the victim binary");
        std::fs::rename(dir.join("victim.tmp"), &victim).expect("place it before executing");
        let mut running = std::process::Command::new(&victim)
            .arg("30")
            .spawn()
            .expect("run the victim");
        std::thread::sleep(Duration::from_millis(100));

        match std::fs::OpenOptions::new().write(true).open(&victim) {
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::ETXTBSY),
                "must be refused as text-file-busy, not some other error"
            ),
            Ok(_) => panic!("kernel allowed opening its own running executable for writing"),
        }

        let _ = running.kill();
        let _ = running.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn still_running_tracks_the_kernels_start_time_not_just_the_pid() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        std::thread::sleep(Duration::from_millis(100));
        let pid = child.id() as i32;
        let started = start_time(pid).expect("a live process has a start time");
        let note = UnmeasuredNote {
            pid,
            started,
            exe: PathBuf::from("/bin/sleep"),
            reason: crate::peercode::GuestFailure::NoIdentity,
        };
        assert!(still_running(&note), "the process is alive and unmoved");

        // A stale start time for the SAME live pid must not read as current --
        // this is what stops a recycled pid inheriting its predecessor's note.
        let stale = UnmeasuredNote {
            started: ProcessStart {
                usec: started.usec.wrapping_add(1),
                ..started
            },
            ..note.clone()
        };
        assert!(!still_running(&stale));

        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !still_running(&note),
            "a reaped pid must not read as still running"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_stamp_preserving_rewrite_is_never_served_the_old_identity() {
        // The R3-F2 regression, ported to the scheme that replaced the cache it
        // was about. The old measurement cache was keyed on (path, dev, ino,
        // size, mtime, mtime_nsec) -- every field settable by the file's owner,
        // since ctime is the only one an in-place rewrite moves and it was not in
        // the key. So a same-length patch plus `utimensat` was served the
        // pre-patch identity for the daemon's lifetime. Here the same forgery is
        // performed against a RUNNING process, and the measurement must not come
        // back equal to the one taken before it.
        use std::io::{Seek, Write};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let dir = scratch("stamp-forge");
        let victim = dir.join("victim");
        let running = Running::sleeper_at(&victim);
        let (_, before) = measure_running_image(running.pid()).expect("measures while honest");
        let stamp = std::fs::metadata(&victim).expect("stat");

        // Rewrite in place at exactly the same length with a DIFFERENT code
        // identity (`/bin/ls`, zero-padded up to the victim's size), then restore
        // mtime to the nanosecond. Same inode, same size, same mtime: the stamp
        // is identical, and the identity at that path is now one the attacker
        // chose. Note the weaker forgery is not enough here and should not be
        // confused with this one: patching bytes UNDER an intact CodeDirectory
        // does not move the cdhash at all, so it changes no identity, and running
        // the patched pages is what the kernel refuses.
        {
            let mut substitute = std::fs::read("/bin/ls").expect("read a different binary");
            assert!(substitute.len() < stamp.size() as usize);
            substitute.resize(stamp.size() as usize, 0);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&victim)
                .expect("open the victim for writing");
            f.seek(std::io::SeekFrom::Start(0)).expect("seek");
            f.write_all(&substitute).expect("rewrite in place");
        }
        let ts = libc::timespec {
            tv_sec: stamp.mtime(),
            tv_nsec: stamp.mtime_nsec(),
        };
        let times = [ts, ts];
        let c = std::ffi::CString::new(victim.as_os_str().as_bytes()).unwrap();
        // SAFETY: utimensat reads the NUL-terminated path and the two-element
        // timespec array, both of which outlive the call.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "the owner may always restore mtime");
        let after_stamp = std::fs::metadata(&victim).expect("stat");
        assert_eq!(
            (
                stamp.dev(),
                stamp.ino(),
                stamp.size(),
                stamp.mtime(),
                stamp.mtime_nsec()
            ),
            (
                after_stamp.dev(),
                after_stamp.ino(),
                after_stamp.size(),
                after_stamp.mtime(),
                after_stamp.mtime_nsec()
            ),
            "every field the old cache keyed on is restored: this is the forgery"
        );

        // Either the platform refuses to vouch for the rewritten image, or the
        // process is already gone; both leave the ancestor unmeasured. What must
        // never happen is being handed the pre-rewrite identity again.
        let served_old = match measure_running_image(running.pid()) {
            Ok((_, id)) => id.digest == before.digest,
            Err(_) => false,
        };
        assert!(
            !served_old,
            "different bytes must not be served the old measurement"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn token(s: &str) -> Token {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    /// The config generation these store-level tests bind under; which one does
    /// not matter here, only that grant and lookup agree (the daemon-level tests
    /// cover a generation actually moving).
    const GEN: u64 = 0;

    /// The display-only coverage label a grant is stamped with. It is not part of
    /// the binding, so every lookup below must succeed without naming it.
    const COVERS: &str = "op read";

    /// A presence binding (what a plain gate stores).
    fn gate(account: &str, scope: &str) -> LeaseBinding {
        LeaseBinding::presence(account, scope, GEN)
    }

    #[test]
    fn lease_grant_lookup_and_scope_isolation() {
        // Scope is the rule name; every leg of the binding must match on lookup.
        let store = LeaseStore::new();
        let gk = rule_key(&walk_ancestry(&tree(), 300), "op");
        let b = gate("Rowm", "op");
        store.grant(gk, &b, COVERS, token("tok"), Duration::from_secs(60));

        assert_eq!(store.active(), 1);
        let t = store.token_for(&gk, &b).unwrap();
        assert_eq!(&t[..], b"tok");
        // Wrong rule, account, or grant key does not match.
        assert!(store.token_for(&gk, &gate("Rowm", "op-eu")).is_none());
        assert!(store.token_for(&gk, &gate("Other", "op")).is_none());
        assert!(store.token_for(&[0u8; 32], &b).is_none());
    }

    #[test]
    fn a_reseal_of_the_source_misses_the_cached_lease() {
        // The source-material leg: a lease holding values unsealed from record E
        // must not serve a run whose source has since been re-sealed under E'.
        // The lookup misses, so that run takes a fresh approval instead of being
        // handed values that are no longer what is on disk.
        let store = LeaseStore::new();
        let gk = rule_key(&walk_ancestry(&tree(), 300), "deploy");
        let sealed_then = LeaseBinding::cached("prod-env", "deploy", "E-original", GEN);
        let sealed_now = LeaseBinding::cached("prod-env", "deploy", "E-after-reseal", GEN);
        store.grant(
            gk,
            &sealed_then,
            COVERS,
            token("TOKEN=old"),
            Duration::from_secs(60),
        );

        assert!(store.token_for(&gk, &sealed_then).is_some());
        assert!(
            store.token_for(&gk, &sealed_now).is_none(),
            "a re-sealed source must not hit the old cache"
        );
        // And a presence lookup (no cached material) is a different binding too.
        assert!(store.token_for(&gk, &gate("prod-env", "deploy")).is_none());
    }

    #[test]
    fn coverage_is_carried_for_display_and_never_joins_the_lookup() {
        // The label describes the window; the binding decides it. Two leases whose
        // labels differ but whose bindings match are ONE lease, and a lookup that
        // knows nothing about labels still hits: a description can never widen,
        // narrow, or split a grant.
        let store = LeaseStore::new();
        let gk = rule_key(&walk_ancestry(&tree(), 300), "op");
        let b = gate("Rowm", "op");
        store.grant(gk, &b, COVERS, token("tok"), Duration::from_secs(60));
        assert_eq!(store.list()[0].covers, COVERS);
        assert_eq!(store.list()[0].scope, "op", "scope stays the rule name");
        assert!(store.token_for(&gk, &b).is_some());

        // A refresh under a re-rendered label (the rule was edited) re-stamps the
        // readout without forking the window.
        store.grant(
            gk,
            &b,
            "op with --account rowm",
            token("tok2"),
            Duration::from_secs(60),
        );
        assert_eq!(store.active(), 1);
        assert_eq!(store.list()[0].covers, "op with --account rowm");
    }

    #[test]
    fn lease_expires_and_is_purged() {
        let store = LeaseStore::new();
        let gk = [7u8; 32];
        let b = gate("Rowm", "s");
        store.grant(gk, &b, COVERS, token("tok"), Duration::from_millis(15));
        assert!(store.token_for(&gk, &b).is_some());
        std::thread::sleep(Duration::from_millis(30));
        assert!(store.token_for(&gk, &b).is_none());
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn an_expired_cached_lease_stops_serving_its_values() {
        // The cache-path lifecycle in miniature: values are served while the
        // window is live and are gone (and wiped with the purge) the moment it
        // lapses. A caller past the TTL gets nothing to inject, so it re-gates.
        let store = LeaseStore::new();
        let gk = [9u8; 32];
        let b = LeaseBinding::cached("prod-env", "deploy", "E1", GEN);
        store.grant(
            gk,
            &b,
            COVERS,
            token("TOKEN=live"),
            Duration::from_millis(15),
        );
        assert_eq!(&store.token_for(&gk, &b).unwrap()[..], b"TOKEN=live");
        std::thread::sleep(Duration::from_millis(30));
        assert!(store.token_for(&gk, &b).is_none(), "the window lapsed");
        assert_eq!(store.active(), 0, "and the values were purged with it");
    }

    /// The opaque id is what lets a remote controller name ONE window rather than
    /// a shape of window. Three properties make it worth having, and all three are
    /// load-bearing for the phone's revoke path.
    #[test]
    fn a_lease_id_names_one_window_and_survives_a_refresh() {
        // The two crates must agree on what an id is, or the daemon would reject
        // ids the proto happily produced.
        assert_eq!(LEASE_ID_HEX_CHARS, sigil_proto::LEASE_ID_CHARS);

        let store = LeaseStore::new();
        let gk = [0xa1; 32];
        let b = gate("Rowm", "op");

        // 1. Minted when the window opens, and opaque: 128 bits of lowercase hex
        //    derived from nothing.
        store.grant(gk, &b, COVERS, token("t"), Duration::from_secs(60));
        let first = store.list()[0].lease_id.clone();
        assert_eq!(first.len(), LEASE_ID_HEX_CHARS);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));

        // 2. Preserved across a REFRESH. A later approval under the same key
        //    extends the window the human is already looking at; a revoke they
        //    aimed at it before the refresh must still land.
        store.grant(gk, &b, COVERS, token("t2"), Duration::from_secs(600));
        assert_eq!(store.active(), 1, "a refresh does not open a second window");
        assert_eq!(store.list()[0].lease_id, first, "same window, same id");

        // 3. A genuinely NEW window gets a new id, even though the grant key is
        //    deterministic and recurs. This is the whole point: the key cannot
        //    distinguish yesterday's window from today's, and the id can.
        assert!(store.revoke_id(&first));
        store.grant(gk, &b, COVERS, token("t3"), Duration::from_secs(60));
        assert_eq!(store.list()[0].grant_hex, hex32(&gk), "the key recurs");
        assert_ne!(store.list()[0].lease_id, first, "the id does not");
    }

    /// **R7-F5: lease id PERMANENCE, which a remote controller reasons from.**
    ///
    /// The phone infers "a window absent from a later list has closed". That
    /// inference is only sound if a live window's id never moves, so this pins the
    /// property from the consumer's side rather than from the implementation's:
    ///
    /// * A live window appears in every snapshot under the SAME id, no matter what
    ///   happens to other windows around it (grants, revokes, expiries, repeated
    ///   listing). If an id could be re-minted for a continuing window, the phone
    ///   would report a still-open window as closed, which is the dangerous
    ///   direction.
    /// * An id is never handed to a second window. If one could be reused, the
    ///   phone could carry stale row state onto a window it never saw approved.
    ///
    /// There is exactly ONE assignment of `Lease::id` in this file (the insert in
    /// `grant`), and nothing ever reassigns it; that is what makes the property
    /// hold.
    ///
    /// **Who breaks if this changes:** `leaseListReceived` in
    /// `apps/phone/src/state/store.ts`, which settles a pending revoke when a
    /// later snapshot omits the window. Its comment names this test, and this one
    /// names it back, because the coupling is invisible from either side alone: a
    /// reader here would not guess that a phone is reasoning from it, and a reader
    /// there cannot see what pins it. If a future change adds continuity by
    /// reusing an id across re-grants, this test fails FIRST and that code starts
    /// lying second. The two must be revisited together.
    #[test]
    fn a_live_window_keeps_its_id_and_a_dead_one_never_lends_it_out() {
        let store = LeaseStore::new();
        let gk = [0xf1; 32];
        let b = gate("Rowm", "op");
        store.grant(gk, &b, COVERS, token("t"), Duration::from_secs(60));
        let watched = store.list()[0].lease_id.clone();

        // Churn everything AROUND the watched window: other windows opened, other
        // windows revoked by both paths, an unrelated window left to lapse, and a
        // config-driven scope revoke. The watched id must not move once.
        let id_of = |scope: &str| {
            store
                .list()
                .into_iter()
                .find(|l| l.scope == scope)
                .map(|l| l.lease_id)
        };
        store.grant(
            [0xf2; 32],
            &gate("A", "other"),
            COVERS,
            token("a"),
            Duration::from_secs(60),
        );
        store.grant(
            [0xf3; 32],
            &gate("B", "doomed"),
            COVERS,
            token("b"),
            Duration::from_millis(10),
        );
        let other = id_of("other").expect("filed");
        assert!(store.revoke_id(&other));
        store.revoke_scope("nothing-matches-this");
        std::thread::sleep(Duration::from_millis(30)); // the doomed one lapses
        for _ in 0..5 {
            assert_eq!(
                id_of("op").as_deref(),
                Some(watched.as_str()),
                "a live window must appear under one unchanging id"
            );
        }
        // A refresh is the case most likely to re-mint by accident.
        store.grant(gk, &b, COVERS, token("t2"), Duration::from_secs(600));
        assert_eq!(id_of("op").as_deref(), Some(watched.as_str()));

        // And the converse the phone relies on: once the window is gone, its id is
        // gone from every later snapshot, so an omission really does mean closed.
        assert!(store.revoke_id(&watched));
        assert_eq!(id_of("op"), None);

        // No id is ever handed out twice, across many open/close cycles under the
        // SAME grant key and binding (the shape that would recur in real use).
        let mut seen = std::collections::HashSet::new();
        seen.insert(watched);
        seen.insert(other);
        for _ in 0..200 {
            store.grant(gk, &b, COVERS, token("t"), Duration::from_secs(60));
            let id = store.list()[0].lease_id.clone();
            assert!(store.revoke_id(&id));
            assert!(seen.insert(id), "a lease id was reused for a later window");
        }
    }

    /// Two live windows can share ONE grant key with different bindings. That is
    /// exactly why the grant key cannot be the remote revoke target: killing "the
    /// row I tapped" by key would take unseen siblings with it. The id does not
    /// have this problem, and this pins the difference.
    #[test]
    fn one_grant_key_can_hold_several_windows_and_ids_still_separate_them() {
        let store = LeaseStore::new();
        let gk = [0xd1; 32];
        store.grant(
            gk,
            &LeaseBinding::cached("A", "rule", "src-1", GEN),
            COVERS,
            token("a"),
            Duration::from_secs(60),
        );
        store.grant(
            gk,
            &LeaseBinding::cached("B", "rule", "src-2", GEN),
            COVERS,
            token("b"),
            Duration::from_secs(60),
        );
        let rows = store.list();
        assert_eq!(rows.len(), 2, "one key, two windows");
        assert_eq!(rows[0].grant_hex, rows[1].grant_hex, "sharing the key");
        assert_ne!(rows[0].lease_id, rows[1].lease_id, "but not the id");

        // Revoking one by id leaves its sibling alone. A key-targeted revoke could
        // not have made that distinction.
        let doomed = rows[0].lease_id.clone();
        let spared = rows[1].lease_id.clone();
        assert!(store.revoke_id(&doomed));
        let left = store.list();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].lease_id, spared);
    }

    /// The remote revoke path is exact and silent about misses, so a stale or
    /// mis-aimed revoke can never take down a window it was not aimed at, and
    /// never reveals what this daemon holds.
    #[test]
    fn revoke_by_id_is_exact_and_refuses_anything_prefix_shaped() {
        let store = LeaseStore::new();
        store.grant(
            [0xb1; 32],
            &gate("A", "rule-a"),
            COVERS,
            token("a"),
            Duration::from_secs(60),
        );
        store.grant(
            [0xb2; 32],
            &gate("B", "rule-b"),
            COVERS,
            token("b"),
            Duration::from_secs(60),
        );
        let rows = store.list();
        let one = rows.iter().find(|l| l.scope == "rule-a").unwrap().clone();
        let two = rows.iter().find(|l| l.scope == "rule-b").unwrap().clone();

        // THE one that matters: an empty id must revoke NOTHING. The store's other
        // revoke entry point is prefix-matched, and "" is a prefix of every string,
        // so an empty identifier reaching that path would wipe every window and
        // report success. This path refuses on width before it looks at anything.
        assert!(!store.revoke_id(""));
        assert_eq!(store.active(), 2, "an empty id is not a wildcard");

        // Every other near miss is equally inert.
        assert!(
            !store.revoke_id(&one.lease_id[..8]),
            "a prefix is not an id"
        );
        assert!(!store.revoke_id(&one.grant_hex), "a grant key is not an id");
        assert!(!store.revoke_id(&format!("{}0", one.lease_id)), "too long");
        assert!(!store.revoke_id(&"z".repeat(32)), "not hex");
        assert!(!store.revoke_id(&"f".repeat(32)), "an id nobody minted");
        assert_eq!(store.active(), 2, "no near miss killed anything");

        // The exact id kills exactly one window, and only once.
        assert!(store.revoke_id(&one.lease_id));
        assert_eq!(store.active(), 1);
        assert!(
            !store.revoke_id(&one.lease_id),
            "idempotent: revoking a dead window is a clean false, never an error"
        );
        assert_eq!(store.list()[0].lease_id, two.lease_id, "the other survives");
    }

    #[test]
    fn revoke_by_id_reports_false_for_a_window_that_already_lapsed() {
        // An expired window and a window that never existed must be
        // indistinguishable, so the reply is not an oracle for what this daemon
        // holds. Both are a bare `false`.
        let store = LeaseStore::new();
        store.grant(
            [0xc1; 32],
            &gate("Rowm", "op"),
            COVERS,
            token("t"),
            Duration::from_millis(15),
        );
        let row = store.list()[0].clone();
        std::thread::sleep(Duration::from_millis(30));
        assert!(!store.revoke_id(&row.lease_id));
        assert!(!store.revoke_id(&"e".repeat(32)));
    }

    /// F9: the remote path's handle exposes exactly two capabilities. This is a
    /// compile-time property, so the test is that the narrow handle type is what
    /// the daemon actually passes -- a `dyn LeaseControl` cannot reach `grant`,
    /// `token_for`, or the prefix-matched `revoke` at all.
    #[test]
    fn the_lease_control_handle_can_only_list_and_revoke_by_id() {
        let store = Arc::new(LeaseStore::new());
        store.grant(
            [0xe1; 32],
            &gate("Rowm", "op"),
            COVERS,
            token("t"),
            Duration::from_secs(60),
        );
        let control: Arc<dyn LeaseControl> = store.clone();
        assert_eq!(control.list().len(), 1);
        let id = control.list()[0].lease_id.clone();
        assert!(control.revoke_id(&id));
        assert_eq!(control.list().len(), 0);
        // `control.grant(..)`, `control.token_for(..)` and `control.revoke(..)` do
        // not compile: the trait has two methods and neither creates or reads a
        // window. The store itself still has them, for the CLI and the gate.
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn clear_zeroizes_all_leases() {
        let store = LeaseStore::new();
        store.grant(
            [1u8; 32],
            &gate("A", "s"),
            COVERS,
            token("a"),
            Duration::from_secs(60),
        );
        store.grant(
            [2u8; 32],
            &gate("B", "s"),
            COVERS,
            token("b"),
            Duration::from_secs(60),
        );
        assert_eq!(store.active(), 2);
        assert_eq!(store.clear(), 2);
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn revoke_by_grant_prefix() {
        let store = LeaseStore::new();
        let gk = [0xabu8; 32];
        let b = gate("A", "s");
        store.grant(gk, &b, COVERS, token("a"), Duration::from_secs(60));
        let prefix = &hex32(&gk)[..8];
        assert_eq!(store.revoke(prefix), 1);
        assert_eq!(store.active(), 0);
        assert!(
            store.token_for(&gk, &b).is_none(),
            "revoke drops the values"
        );
    }

    #[test]
    fn revoke_scope_kills_every_lease_on_one_rule() {
        // The config-change path: one rule's window dies whoever opened it, and
        // other rules' windows are untouched.
        let store = LeaseStore::new();
        let doomed = LeaseBinding::cached("prod-env", "deploy", "E1", GEN);
        store.grant(
            [1u8; 32],
            &doomed,
            COVERS,
            token("TOKEN=a"),
            Duration::from_secs(60),
        );
        store.grant(
            [2u8; 32],
            &doomed,
            COVERS,
            token("TOKEN=b"),
            Duration::from_secs(60),
        );
        store.grant(
            [3u8; 32],
            &gate("", "op"),
            COVERS,
            token(""),
            Duration::from_secs(60),
        );

        assert_eq!(store.revoke_scope("deploy"), 2);
        assert_eq!(store.active(), 1, "the unrelated rule keeps its lease");
        assert!(store.token_for(&[1u8; 32], &doomed).is_none());
        assert_eq!(store.revoke_scope("deploy"), 0, "idempotent");
    }

    #[test]
    fn lease_refresh_keeps_one_entry() {
        let store = LeaseStore::new();
        let gk = [3u8; 32];
        let b = gate("A", "s");
        store.grant(gk, &b, COVERS, token("a"), Duration::from_secs(1));
        store.grant(gk, &b, COVERS, token("b"), Duration::from_secs(60));
        assert_eq!(store.active(), 1);
        assert_eq!(&store.token_for(&gk, &b).unwrap()[..], b"b");
    }
}
