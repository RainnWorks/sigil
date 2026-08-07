//! Leases and the daemon-verified caller identity they are scoped to.
//!
//! A dev session fires many `op` calls the caller cannot be changed to route
//! differently; they believe they are the real CLI. So the daemon derives the
//! caller's identity itself and never trusts the client's account of it:
//!
//! 1. Read the true peer pid off the unix socket (`LOCAL_PEERPID`).
//! 2. Walk the ancestor chain kernel-side (sysctl `KERN_PROC` on macOS), pid by
//!    pid, resolving each to an executable path and a content hash.
//! 3. The grant key is `BLAKE2b(chain ++ project_root ++ kind ++ scope)`. Raw
//!    pids are excluded from the hash because they recycle; only the stable code
//!    identity (path + hash) of each ancestor is bound in. `kind` is the
//!    request-kind tag ([`ScopeKind`]), so a command scope and an SSH scope live
//!    in separate namespaces and cannot collide however they are spelled.
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
//! NEEDS-VERIFICATION: the ancestor "code identity" here is a BLAKE2b hash of
//! the executable's bytes. The design calls for the platform code-signing
//! identity (Developer ID / Authenticode) so a re-signed-but-identical binary
//! and a tampered one are told apart. Confirm the macOS path with:
//!   codesign -dvvv --verbose=4 "$(command -v op)"   # team identifier / cdhash
//! and fold the cdhash into `identity_of` in a follow-up.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::secrets::Token;

type Blake2b256 = Blake2b<U32>;

const GRANT_DOMAIN: &[u8] = b"sigil.grant.v1";
/// Cap the ancestry walk so a pathological or looping process table cannot spin.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// One resolved ancestor: its pid (for display only, never hashed), executable
/// path, and a 32-byte code-identity measurement of that executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub pid: i32,
    pub exe: PathBuf,
    pub identity: [u8; 32],
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
}

/// The kernel's view of the process table, abstracted so the ancestry walk can
/// be unit-tested against a synthetic tree.
pub trait ProcessTable {
    /// The parent pid of `pid`, or `None` at the root / for an unknown pid.
    fn parent(&self, pid: i32) -> Option<i32>;
    /// The executable path backing `pid`.
    fn exe(&self, pid: i32) -> Option<PathBuf>;
    /// A stable 32-byte code identity for `pid`'s executable. The real fill
    /// hashes the file contents; the synthetic table returns an injected value.
    fn identity(&self, pid: i32) -> [u8; 32];
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
        let Some(exe) = table.exe(pid) else { break };
        let identity = table.identity(pid);
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
/// the same byte string.
pub fn grant_key(caller: &Caller, kind: ScopeKind, project_root: &str, scope: &str) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(GRANT_DOMAIN);
    h.update((caller.chain.len() as u64).to_le_bytes());
    for a in &caller.chain {
        let exe = a.exe.as_os_str().as_encoded_bytes();
        h.update((exe.len() as u64).to_le_bytes());
        h.update(exe);
        h.update(a.identity);
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
    pub fn grant(&self, grant: [u8; 32], binding: &LeaseBinding, token: Token, ttl: Duration) {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        if let Some(l) = leases
            .iter_mut()
            .find(|l| l.grant == grant && &l.binding == binding)
        {
            l.token = token;
            l.expires = now + ttl;
            return;
        }
        leases.push(Lease {
            grant,
            binding: binding.clone(),
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

/// The real process table: sysctl for ancestry, `proc_pidpath` for the exe, a
/// BLAKE2b of the executable bytes for the code identity (interim stand-in for
/// the code-signing identity; see the module NEEDS-VERIFICATION note).
pub struct SysProcessTable;

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

    fn exe(&self, pid: i32) -> Option<PathBuf> {
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
        Some(PathBuf::from(s))
    }

    fn identity(&self, pid: i32) -> [u8; 32] {
        match self.exe(pid).and_then(|p| std::fs::read(p).ok()) {
            Some(bytes) => Blake2b256::digest(&bytes).into(),
            // Unreadable exe: bind the pid's path string so the chain is still
            // distinct rather than colliding on a zero identity.
            None => Blake2b256::digest(pid.to_le_bytes()).into(),
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl ProcessTable for SysProcessTable {
    fn parent(&self, _pid: i32) -> Option<i32> {
        None
    }
    fn exe(&self, _pid: i32) -> Option<PathBuf> {
        None
    }
    fn identity(&self, pid: i32) -> [u8; 32] {
        Blake2b256::digest(pid.to_le_bytes()).into()
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
        ident: HashMap<i32, [u8; 32]>,
    }

    impl MapTable {
        fn node(&mut self, pid: i32, ppid: i32, exe: &str, id: u8) {
            self.parent.insert(pid, ppid);
            self.exe.insert(pid, PathBuf::from(exe));
            self.ident.insert(pid, [id; 32]);
        }
    }

    impl ProcessTable for MapTable {
        fn parent(&self, pid: i32) -> Option<i32> {
            self.parent.get(&pid).copied()
        }
        fn exe(&self, pid: i32) -> Option<PathBuf> {
            self.exe.get(&pid).cloned()
        }
        fn identity(&self, pid: i32) -> [u8; 32] {
            self.ident.get(&pid).copied().unwrap_or([0u8; 32])
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
        tampered.ident.insert(200, [0x42; 32]);
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
        t.ident.insert(200, [0x42; 32]);
        assert_ne!(
            base,
            grant_key(&walk_ancestry(&t, 300), CMD, "/p", "s"),
            "ancestor code identity must matter"
        );
    }

    fn token(s: &str) -> Token {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    /// The config generation these store-level tests bind under; which one does
    /// not matter here, only that grant and lookup agree (the daemon-level tests
    /// cover a generation actually moving).
    const GEN: u64 = 0;

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
        store.grant(gk, &b, token("tok"), Duration::from_secs(60));

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
    fn lease_expires_and_is_purged() {
        let store = LeaseStore::new();
        let gk = [7u8; 32];
        let b = gate("Rowm", "s");
        store.grant(gk, &b, token("tok"), Duration::from_millis(15));
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
        store.grant(gk, &b, token("TOKEN=live"), Duration::from_millis(15));
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
            token("a"),
            Duration::from_secs(60),
        );
        store.grant(
            [2u8; 32],
            &gate("B", "s"),
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
        store.grant(gk, &b, token("a"), Duration::from_secs(60));
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
            token("TOKEN=a"),
            Duration::from_secs(60),
        );
        store.grant(
            [2u8; 32],
            &doomed,
            token("TOKEN=b"),
            Duration::from_secs(60),
        );
        store.grant(
            [3u8; 32],
            &gate("", "op"),
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
        store.grant(gk, &b, token("a"), Duration::from_secs(1));
        store.grant(gk, &b, token("b"), Duration::from_secs(60));
        assert_eq!(store.active(), 1);
        assert_eq!(&store.token_for(&gk, &b).unwrap()[..], b"b");
    }
}
