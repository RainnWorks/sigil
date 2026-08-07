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
//!   ancestor's path after exec does not change what that ancestor measures as:
//!   the platform answers `-67034 errSecCSStaticCodeChanged` for that process
//!   (verified here for in-place overwrite and for rename-over) and the ancestor
//!   becomes [`IdentityMeasure::Unmeasured`], which declines to lease at all.
//!   That is a refusal to measure, not detection of a live tamper.
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
//!   chain then matches by construction. The measure's value is telling honest
//!   tool trees apart.
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
//! check gating the answer. Nothing is measured from a path, and nothing is
//! cached: a stale or forgeable cache key is a way to be told an ancestor is
//! code it is no longer running, so every request measures afresh (a few
//! fractions of a millisecond per ancestor, well under the cost of the `op` child
//! the request goes on to spawn).
//!
//! Residuals that remain (for the reviewer, not a verdict): the caller-chain
//! imitation class above; the measure is macOS-only, so a future Linux/Windows
//! process table has to fill the seam or every ancestor there is unmeasured; and
//! the walk resolves ancestors by pid, so a pid recycled between the parent
//! lookup and the measurement pairs one process's chain position with another's
//! identity. That last one fails closed (the mismatched pair derives a key nobody
//! holds, so the run takes a fresh approval) and cannot widen a grant.

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
    /// post-exec swap of the executable looks like). Fails closed twice over:
    /// the digest is derived from the pid so it is not stable across runs, and
    /// [`Caller::fully_measured`] refuses to lease a chain containing one.
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

    /// The nothing-to-measure case. The digest is derived from the pid so two
    /// unmeasurable ancestors are not silently one identity; it is NOT a claim
    /// that this coalesces with nothing, because the same pid at the same path
    /// derives the same 32 bytes. The fail-closed part is
    /// [`Caller::fully_measured`]: a chain holding one of these never leases.
    pub fn unmeasured(pid: i32) -> Self {
        Self {
            measure: IdentityMeasure::Unmeasured,
            digest: Blake2b256::digest(pid.to_le_bytes()).into(),
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

    /// Whether every ancestor in the chain was actually measured.
    ///
    /// False means the platform would not tell us what some ancestor is running:
    /// it exited mid-walk, its image is gone, or the file at its path was
    /// replaced after exec (which answers `errSecCSStaticCodeChanged`). A chain
    /// like that still gets an approval like any other request, and the human
    /// still sees it; what it must not do is open or ride a LEASE, because a
    /// lease is the one thing that releases a later request with no human in the
    /// loop, and the identity that would key it is the one thing we could not
    /// establish. Fail closed: no measurement, no window.
    pub fn fully_measured(&self) -> bool {
        !self.chain.is_empty()
            && self
                .chain
                .iter()
                .all(|a| a.identity.measure != IdentityMeasure::Unmeasured)
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
    pub account: String,
    /// The rule name the lease covers. Display must make the breadth plain: the
    /// lease covers any command that rule matches, not the one that opened it.
    pub scope: String,
    /// What that rule matches, in the daemon's own words (`op read`,
    /// `op with --account rowmhq.1password.eu`, …): the same string the approver
    /// consented to, so the CLI states the breadth instead of gesturing at it.
    /// Empty when the daemon rendered none.
    pub covers: String,
    pub remaining: Duration,
    pub age: Duration,
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
            return;
        }
        leases.push(Lease {
            grant,
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
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
/// `None` when the platform will not answer for that pid at all (it exited, its
/// image is gone) or will not vouch for the image (the file at its path was
/// replaced after exec, `-67034 errSecCSStaticCodeChanged`). The caller keeps
/// the process in the chain for the human to see, under
/// [`IdentityMeasure::Unmeasured`], and [`Caller::fully_measured`] then refuses
/// to lease it.
///
/// Cost, measured on an M-series Mac (release build, no cache anywhere): 0.15ms
/// for an ad-hoc Homebrew binary, 0.47ms for `/bin/zsh`, 1.2-2.1ms for a large
/// Developer-ID binary, and **6.3ms for a whole real 6-deep chain** (login, zsh,
/// claude, zsh, cargo, leaf) on every gated command. That is an order of
/// magnitude below the `op` child the command goes on to spawn (40-90ms for
/// `op --version` alone, more for a real read) and two below the 236ms the
/// original unconditional content hash cost on the same chain.
#[cfg(target_os = "macos")]
fn measure_running_image(pid: i32) -> Option<(PathBuf, CodeIdentity)> {
    let m = crate::peercode::measure_guest(pid)?;
    Some((m.exe, CodeIdentity::from_cdhash(&m.cdhash, m.adhoc)))
}

#[cfg(target_os = "macos")]
impl ProcessTable for SysProcessTable {
    fn parent(&self, pid: i32) -> Option<i32> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: proc_pidinfo writes at most `size` bytes into `info` and
        // returns the count written, or <= 0 on failure.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if n < size {
            return None;
        }
        let ppid = info.pbi_ppid as i32;
        (ppid > 0).then_some(ppid)
    }

    fn resolve(&self, pid: i32) -> Option<(PathBuf, CodeIdentity)> {
        if let Some(resolved) = measure_running_image(pid) {
            return Some(resolved);
        }
        // The platform would not vouch for this process's image. It still gets a
        // name in the chain, because the human on the phone should see the whole
        // tree that reached the daemon, but it is explicitly unmeasured and so
        // cannot open or ride a lease. `proc_pidpath` is display only here.
        let mut buf = [0u8; 4096];
        // SAFETY: proc_pidpath writes at most buf.len() bytes and returns the
        // length written, or <= 0 on failure.
        let n = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n <= 0 {
            return None;
        }
        let s = std::str::from_utf8(&buf[..n as usize]).ok()?;
        Some((PathBuf::from(s), CodeIdentity::unmeasured(pid)))
    }
}

#[cfg(not(target_os = "macos"))]
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
    fn an_unmeasured_ancestor_refuses_to_lease() {
        // The fail-closed rule, and the reason the pid-derived digest is not
        // load-bearing: an unmeasured ancestor anywhere in the chain means the
        // chain may not open or ride a window at all. It does NOT mean "this
        // coalesces with nothing" -- the same pid derives the same 32 bytes, so
        // the refusal has to come from here, not from the digest.
        assert_eq!(
            CodeIdentity::unmeasured(100).digest,
            CodeIdentity::unmeasured(100).digest,
            "same pid, same digest: the digest alone does not isolate anything"
        );
        assert_ne!(
            CodeIdentity::unmeasured(100).digest,
            CodeIdentity::unmeasured(101).digest
        );

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
        assert!(measured.fully_measured());

        let mut mixed = measured.clone();
        mixed.chain.push(ancestor(CodeIdentity::unmeasured(7)));
        assert!(
            !mixed.fully_measured(),
            "one unmeasured ancestor is enough to refuse the window"
        );
        assert!(
            !Caller { chain: vec![] }.fully_measured(),
            "and an empty chain is not a measured caller either"
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
            Some(id),
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
    fn a_pid_with_no_live_image_is_unmeasured_and_never_leases() {
        // Fail closed: a pid that names no live guest measures as nothing, and
        // the process table hands back `Unmeasured` (or truncates the walk)
        // rather than any identity a caller could ride.
        assert_eq!(measure_running_image(0), None);
        assert_eq!(SysProcessTable.resolve(0), None);
        assert!(
            !walk_ancestry(&SysProcessTable, 0).fully_measured(),
            "an empty chain is not a measured caller"
        );

        // The daemon's own chain, on the other hand, is measurable end to end:
        // this is the shape a real gated command arrives in, and if it were not
        // fully measured, leases would silently never open.
        let me = walk_ancestry(&SysProcessTable, std::process::id() as i32);
        assert!(!me.chain.is_empty(), "this process has ancestors");
        assert!(
            me.fully_measured(),
            "a normal live chain must measure end to end: {}",
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
        // the platform refuses (-67034 errSecCSStaticCodeChanged), the ancestor
        // becomes `Unmeasured`, and the chain stops being leasable.
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

        let after = measure_running_image(running.pid());
        assert_eq!(
            after, None,
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
            "and it certainly does not keep the pre-swap identity"
        );
        assert!(
            !Caller {
                chain: vec![Ancestor {
                    pid: running.pid(),
                    exe: path,
                    identity: id,
                }],
            }
            .fully_measured(),
            "a chain holding it must not lease"
        );
        let _ = std::fs::remove_dir_all(&dir);
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

        // Either the platform refuses to vouch for the patched image, or the
        // process is already gone; both are `Unmeasured`. What must never happen
        // is being handed the pre-patch identity again.
        let after = measure_running_image(running.pid());
        assert!(
            after.is_none_or(|(_, id)| id.digest != before.digest),
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
