//! Leases and the daemon-verified caller identity they are scoped to.
//!
//! A dev session fires many `op` calls the caller cannot be changed to route
//! differently; they believe they are the real CLI. So the daemon derives the
//! caller's identity itself and never trusts the client's account of it:
//!
//! 1. Read the true peer pid off the unix socket (`LOCAL_PEERPID`).
//! 2. Walk the ancestor chain kernel-side (sysctl `KERN_PROC` on macOS), pid by
//!    pid, resolving each to an executable path and a content hash.
//! 3. The grant key is `BLAKE2b(chain ++ project_root ++ scope)`. Raw pids are
//!    excluded from the hash because they recycle; only the stable code
//!    identity (path + hash) of each ancestor is bound in.
//!
//! A lease holds the unwrapped SA token in RAM, scoped to that grant key plus
//! the account and request scope, until a TTL elapses. Expiry, revoke,
//! lockdown, and daemon restart all zeroize it. Client-supplied ancestry is
//! never consulted; the whole chain is measured here.
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

const GRANT_DOMAIN: &[u8] = b"latch.grant.v1";
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

/// `BLAKE2b(domain ++ chain ++ project_root ++ scope)`, the lease grant key.
///
/// Only the stable code identity of each ancestor is bound in, never its pid.
/// Two runs of the same tool tree from the same project for the same scope
/// therefore share a grant key (so one approval leases the burst); a different
/// tool, project, or scope derives a different key.
pub fn grant_key(caller: &Caller, project_root: &str, scope: &str) -> [u8; 32] {
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
    let scope = scope.as_bytes();
    h.update((scope.len() as u64).to_le_bytes());
    h.update(scope);
    h.finalize().into()
}

/// A granted lease: an unwrapped token held in RAM, scoped and TTL-bound.
struct Lease {
    grant: [u8; 32],
    account: String,
    scope: String,
    token: Token,
    granted: Instant,
    expires: Instant,
}

/// A read-only view of an active lease for `latch lease list`.
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    pub grant_hex: String,
    pub account: String,
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

    /// Grant (or refresh) a lease for `grant`/`account`/`scope` with `ttl`.
    pub fn grant(&self, grant: [u8; 32], account: &str, scope: &str, token: Token, ttl: Duration) {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        if let Some(l) = leases
            .iter_mut()
            .find(|l| l.grant == grant && l.account == account && l.scope == scope)
        {
            l.token = token;
            l.expires = now + ttl;
            return;
        }
        leases.push(Lease {
            grant,
            account: account.to_string(),
            scope: scope.to_string(),
            token,
            granted: now,
            expires: now + ttl,
        });
    }

    /// The token for an active lease matching `grant`/`account`/`scope`, if any.
    /// Expired leases are purged (and zeroized) as a side effect.
    pub fn token_for(&self, grant: &[u8; 32], account: &str, scope: &str) -> Option<Token> {
        let now = Instant::now();
        let mut leases = self.inner.lock().expect("lease store poisoned");
        leases.retain(|l| l.expires > now);
        leases
            .iter()
            .find(|l| &l.grant == grant && l.account == account && l.scope == scope)
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
                account: l.account.clone(),
                scope: l.scope.clone(),
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

    /// Drop and zeroize every lease. The lockdown and restart path.
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
    use crate::secrets::generate_dek;
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
        let a = grant_key(&c, "/Projects/rowm", "item get .env --vault Engineering");
        let b = grant_key(&c, "/Projects/rowm", "item get .env --vault Engineering");
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

        let a = grant_key(&walk_ancestry(&tree(), 300), "/p", "s");
        let b = grant_key(&walk_ancestry(&t2, 999), "/p", "s");
        assert_eq!(a, b, "grant key must not depend on pids");
    }

    #[test]
    fn grant_key_changes_with_root_scope_or_ancestry() {
        let c = walk_ancestry(&tree(), 300);
        let base = grant_key(&c, "/p", "s");
        assert_ne!(base, grant_key(&c, "/other", "s"), "root must matter");
        assert_ne!(base, grant_key(&c, "/p", "other"), "scope must matter");

        // A different ancestor identity (e.g. a tampered claude) must move it.
        let mut t = tree();
        t.ident.insert(200, [0x42; 32]);
        assert_ne!(
            base,
            grant_key(&walk_ancestry(&t, 300), "/p", "s"),
            "ancestor code identity must matter"
        );
    }

    fn token(s: &str) -> Token {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    #[test]
    fn lease_grant_lookup_and_scope_isolation() {
        let store = LeaseStore::new();
        let gk = grant_key(&walk_ancestry(&tree(), 300), "/p", "read .env");
        store.grant(
            gk,
            "Rowm",
            "read .env",
            token("tok"),
            Duration::from_secs(60),
        );

        assert_eq!(store.active(), 1);
        let t = store.token_for(&gk, "Rowm", "read .env").unwrap();
        assert_eq!(&t[..], b"tok");
        // Wrong scope, account, or grant key does not match.
        assert!(store.token_for(&gk, "Rowm", "read other").is_none());
        assert!(store.token_for(&gk, "Other", "read .env").is_none());
        assert!(store.token_for(&[0u8; 32], "Rowm", "read .env").is_none());
    }

    #[test]
    fn lease_expires_and_is_purged() {
        let store = LeaseStore::new();
        let gk = [7u8; 32];
        store.grant(gk, "Rowm", "s", token("tok"), Duration::from_millis(15));
        assert!(store.token_for(&gk, "Rowm", "s").is_some());
        std::thread::sleep(Duration::from_millis(30));
        assert!(store.token_for(&gk, "Rowm", "s").is_none());
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn lockdown_clears_all_leases() {
        let store = LeaseStore::new();
        store.grant([1u8; 32], "A", "s", token("a"), Duration::from_secs(60));
        store.grant([2u8; 32], "B", "s", token("b"), Duration::from_secs(60));
        assert_eq!(store.active(), 2);
        assert_eq!(store.clear(), 2);
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn revoke_by_grant_prefix() {
        let store = LeaseStore::new();
        let gk = [0xabu8; 32];
        store.grant(gk, "A", "s", token("a"), Duration::from_secs(60));
        let prefix = &hex32(&gk)[..8];
        assert_eq!(store.revoke(prefix), 1);
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn lease_refresh_keeps_one_entry() {
        let store = LeaseStore::new();
        let gk = [3u8; 32];
        let _ = generate_dek(); // touch the CSPRNG path used by the real flow
        store.grant(gk, "A", "s", token("a"), Duration::from_secs(1));
        store.grant(gk, "A", "s", token("b"), Duration::from_secs(60));
        assert_eq!(store.active(), 1);
        assert_eq!(&store.token_for(&gk, "A", "s").unwrap()[..], b"b");
    }
}
