//! The approval gate: nothing is fulfilled without a fresh out-of-band decision.
//!
//! The phone approver lands later; the interim approving factor here is local.
//! [`LocalApprover`] resolves a decision one of three ways, in order:
//!
//! * `LATCH_DEV_AUTOAPPROVE` set — headless auto-approve, for the gated-loop
//!   tests and dev. `=lease` makes it a session lease; anything else a
//!   single-shot approve. This is a dev switch, never a shipping path.
//! * a live Mac Secure Enclave DEK envelope — prompt Touch ID to unwrap it
//!   (NEEDS-VERIFICATION; see [`crate::keystore_macos`]).
//! * otherwise — register the request as pending and block until a
//!   `latch approve --local --id <id>` (or `deny`) arrives over the control
//!   socket, or the timeout fires and it fails closed as a deny.
//!
//! [`ApprovalGate`] wraps an approver with request coalescing: identical
//! in-flight requests (same grant key + scope) wait behind one decision, so a
//! burst costs one glance. Deny/timeout always fails closed.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::keystore::Keystore;

/// Default wait for a local decision before failing closed.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// The outcome of an approval. `Lease` carries the session TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Lease(Duration),
    Deny,
}

impl Decision {
    pub fn is_grant(&self) -> bool {
        matches!(self, Decision::Approve | Decision::Lease(_))
    }
    pub fn lease_ttl(&self) -> Option<Duration> {
        match self {
            Decision::Lease(ttl) => Some(*ttl),
            _ => None,
        }
    }
}

/// What the approver is shown about a request. Names and provenance only; never
/// a secret value.
#[derive(Debug, Clone)]
pub struct ApprovalContext {
    /// uuidv7, the address for a local approve/deny round trip.
    pub id: String,
    pub account: String,
    /// The op scope, e.g. `item get .env --vault Engineering`.
    pub scope: String,
    /// Grant-key hex, for correlating with `latch lease list`.
    pub grant_hex: String,
    /// Human process chain, e.g. `zsh → claude → op`.
    pub provenance: String,
    pub cwd: String,
}

/// Resolves an approval request to a decision. Blocking; may time out to `Deny`.
pub trait Approver: Send + Sync {
    fn decide(&self, ctx: &ApprovalContext) -> Decision;
}

/// Registry of pending local approvals, keyed by request id. Shared between the
/// [`LocalApprover`] (which parks a waiter) and the daemon's control handler
/// (which resolves it when `latch approve --local` arrives).
#[derive(Default)]
pub struct PendingRegistry {
    waiters: Mutex<HashMap<String, Sender<Decision>>>,
}

impl PendingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn park(&self, id: &str) -> Receiver<Decision> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.waiters
            .lock()
            .expect("pending registry poisoned")
            .insert(id.to_string(), tx);
        rx
    }

    fn unpark(&self, id: &str) {
        self.waiters
            .lock()
            .expect("pending registry poisoned")
            .remove(id);
    }

    /// Deliver a decision to a parked local approval. Returns true if a waiter
    /// was found (the id was pending).
    pub fn resolve(&self, id: &str, decision: Decision) -> bool {
        let tx = self
            .waiters
            .lock()
            .expect("pending registry poisoned")
            .get(id)
            .cloned();
        match tx {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Ids currently awaiting a local decision.
    pub fn pending_ids(&self) -> Vec<String> {
        self.waiters
            .lock()
            .expect("pending registry poisoned")
            .keys()
            .cloned()
            .collect()
    }
}

/// Headless auto-approve mode, resolved once at construction (never re-read per
/// request, so tests are not racing a process-global env var).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevMode {
    Off,
    Approve,
    Lease(Duration),
}

impl DevMode {
    /// Read `LATCH_DEV_AUTOAPPROVE`: `lease` -> a 15m session lease, any other
    /// non-empty value -> single-shot approve, unset/empty/`0` -> off.
    pub fn from_env() -> Self {
        match std::env::var("LATCH_DEV_AUTOAPPROVE") {
            Ok(v) if v == "lease" => DevMode::Lease(Duration::from_secs(15 * 60)),
            Ok(v) if !v.is_empty() && v != "0" => DevMode::Approve,
            _ => DevMode::Off,
        }
    }

    fn decision(self) -> Option<Decision> {
        match self {
            DevMode::Off => None,
            DevMode::Approve => Some(Decision::Approve),
            DevMode::Lease(ttl) => Some(Decision::Lease(ttl)),
        }
    }
}

/// The interim local approver (see module docs).
pub struct LocalApprover {
    keystore: Arc<dyn Keystore>,
    pending: Arc<PendingRegistry>,
    timeout: Duration,
    dev: DevMode,
}

impl LocalApprover {
    /// Build an approver, reading the dev auto-approve switch once from the env.
    pub fn new(keystore: Arc<dyn Keystore>, pending: Arc<PendingRegistry>) -> Self {
        Self {
            keystore,
            pending,
            timeout: DEFAULT_APPROVAL_TIMEOUT,
            dev: DevMode::from_env(),
        }
    }

    /// Override the local-decision timeout (tests use a short one).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the dev auto-approve mode explicitly (tests, and the daemon when it
    /// resolves the switch itself).
    pub fn with_dev(mut self, dev: DevMode) -> Self {
        self.dev = dev;
        self
    }
}

impl Approver for LocalApprover {
    fn decide(&self, ctx: &ApprovalContext) -> Decision {
        // 1. Dev auto-approve switch.
        if let Some(d) = self.dev.decision() {
            return d;
        }

        // 2. Mac Secure Enclave + Touch ID, when provisioned. The unwrap itself
        //    is the biometric gate; a successful unwrap is the approval. Only a
        //    real biometric keystore counts here, so a dev/in-memory keystore
        //    (whose unwrap is not a biometric) can never auto-approve. Held
        //    behind NEEDS-VERIFICATION until exercised on hardware, so today it
        //    falls through to the control-socket path below rather than
        //    approving on an unverified enclave call.
        if self.keystore.is_biometric() && self.keystore.has_dek() {
            match self
                .keystore
                .unwrap_dek(&format!("Approve {} for {}", ctx.scope, ctx.account))
            {
                Ok(_dek) => return Decision::Approve,
                Err(crate::keystore::KeystoreError::Declined) => return Decision::Deny,
                Err(_) => { /* NeedsVerification / no-dek: fall through */ }
            }
        }

        // 3. Park until `latch approve|deny --local --id <ctx.id>` or timeout.
        eprintln!(
            "latch daemon: approval required · {} · {}\n            approve: latch approve --local --id {}\n            deny:    latch deny --local --id {}",
            ctx.account, ctx.scope, ctx.id, ctx.id
        );
        let rx = self.pending.park(&ctx.id);
        let decision = rx.recv_timeout(self.timeout).unwrap_or(Decision::Deny);
        self.pending.unpark(&ctx.id);
        decision
    }
}

/// A slot behind which coalesced requests wait for one decision.
struct Slot {
    done: Mutex<Option<Decision>>,
    cv: Condvar,
}

/// Wraps an approver with request coalescing. Requests with an identical
/// coalesce key (grant key + scope) that arrive while one is pending wait for
/// that single decision instead of prompting again.
pub struct ApprovalGate {
    approver: Box<dyn Approver>,
    inflight: Mutex<HashMap<[u8; 32], Arc<Slot>>>,
}

impl ApprovalGate {
    pub fn new(approver: Box<dyn Approver>) -> Self {
        Self {
            approver,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `ctx`, coalescing behind any in-flight request with the same
    /// `key`. Exactly one caller (the leader) drives the approver; the rest
    /// block on the shared slot and receive the same decision.
    pub fn decide(&self, key: [u8; 32], ctx: &ApprovalContext) -> Decision {
        enum Role {
            Leader(Arc<Slot>),
            Follower(Arc<Slot>),
        }
        let role = {
            let mut map = self.inflight.lock().expect("gate poisoned");
            match map.get(&key) {
                Some(slot) => Role::Follower(slot.clone()),
                None => {
                    let slot = Arc::new(Slot {
                        done: Mutex::new(None),
                        cv: Condvar::new(),
                    });
                    map.insert(key, slot.clone());
                    Role::Leader(slot)
                }
            }
        };

        match role {
            Role::Leader(slot) => {
                let decision = self.approver.decide(ctx);
                // Publish, wake followers, and clear the in-flight entry so the
                // next burst re-prompts.
                self.inflight.lock().expect("gate poisoned").remove(&key);
                *slot.done.lock().expect("slot poisoned") = Some(decision);
                slot.cv.notify_all();
                decision
            }
            Role::Follower(slot) => {
                let mut done = slot.done.lock().expect("slot poisoned");
                while done.is_none() {
                    done = slot.cv.wait(done).expect("slot poisoned");
                }
                done.expect("decision published")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ctx(id: &str, scope: &str) -> ApprovalContext {
        ApprovalContext {
            id: id.into(),
            account: "Rowm".into(),
            scope: scope.into(),
            grant_hex: "deadbeef".into(),
            provenance: "zsh \u{2192} op".into(),
            cwd: "/p".into(),
        }
    }

    /// Counts calls and returns a fixed decision after a short delay so the
    /// coalescing window is real.
    struct Counting {
        calls: AtomicUsize,
        decision: Decision,
    }
    impl Approver for Counting {
        fn decide(&self, _ctx: &ApprovalContext) -> Decision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(40));
            self.decision
        }
    }

    #[test]
    fn identical_inflight_requests_coalesce_to_one_decision() {
        let counting = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            decision: Decision::Approve,
        });
        // The gate owns a thin forwarder to the shared Counting approver.
        struct Fwd(Arc<Counting>);
        impl Approver for Fwd {
            fn decide(&self, c: &ApprovalContext) -> Decision {
                self.0.decide(c)
            }
        }
        let gate = Arc::new(ApprovalGate::new(Box::new(Fwd(counting.clone()))));
        let key = [9u8; 32];

        let mut handles = Vec::new();
        for i in 0..8 {
            let gate = gate.clone();
            handles.push(std::thread::spawn(move || {
                gate.decide(key, &ctx(&format!("id-{i}"), "read .env"))
            }));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), Decision::Approve);
        }
        assert_eq!(
            counting.calls.load(Ordering::SeqCst),
            1,
            "a burst with one grant key must prompt exactly once"
        );
    }

    #[test]
    fn different_keys_do_not_coalesce() {
        let counting = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            decision: Decision::Deny,
        });
        struct Fwd(Arc<Counting>);
        impl Approver for Fwd {
            fn decide(&self, c: &ApprovalContext) -> Decision {
                self.0.decide(c)
            }
        }
        let gate = ApprovalGate::new(Box::new(Fwd(counting.clone())));
        assert_eq!(gate.decide([1u8; 32], &ctx("a", "s1")), Decision::Deny);
        assert_eq!(gate.decide([2u8; 32], &ctx("b", "s2")), Decision::Deny);
        assert_eq!(counting.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dev_autoapprove_grants_without_biometrics() {
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = LocalApprover::new(ks.clone(), Arc::new(PendingRegistry::new()))
            .with_dev(DevMode::Approve);
        assert_eq!(approver.decide(&ctx("x", "s")), Decision::Approve);

        let lease = LocalApprover::new(ks, Arc::new(PendingRegistry::new()))
            .with_dev(DevMode::Lease(Duration::from_secs(60)));
        assert!(matches!(lease.decide(&ctx("x", "s")), Decision::Lease(_)));
    }

    #[test]
    fn dev_mode_from_env_parses() {
        // Isolated from other tests: this is the only test touching this var,
        // and it restores it before returning.
        let prev = std::env::var("LATCH_DEV_AUTOAPPROVE").ok();
        std::env::set_var("LATCH_DEV_AUTOAPPROVE", "lease");
        assert!(matches!(DevMode::from_env(), DevMode::Lease(_)));
        std::env::set_var("LATCH_DEV_AUTOAPPROVE", "1");
        assert_eq!(DevMode::from_env(), DevMode::Approve);
        std::env::set_var("LATCH_DEV_AUTOAPPROVE", "0");
        assert_eq!(DevMode::from_env(), DevMode::Off);
        match prev {
            Some(v) => std::env::set_var("LATCH_DEV_AUTOAPPROVE", v),
            None => std::env::remove_var("LATCH_DEV_AUTOAPPROVE"),
        }
    }

    #[test]
    fn local_control_round_trip_approves() {
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = LocalApprover::new(ks, pending.clone())
            .with_dev(DevMode::Off)
            .with_timeout(Duration::from_secs(2));

        let approver = Arc::new(approver);
        let a2 = approver.clone();
        let handle = std::thread::spawn(move || a2.decide(&ctx("req-1", "read .env")));

        // Wait for the approver to register the pending id, then resolve it.
        let mut tries = 0;
        while !pending.pending_ids().contains(&"req-1".to_string()) {
            std::thread::sleep(Duration::from_millis(5));
            tries += 1;
            assert!(tries < 200, "approver never parked the request");
        }
        assert!(pending.resolve("req-1", Decision::Approve));
        assert_eq!(handle.join().unwrap(), Decision::Approve);
    }

    #[test]
    fn local_timeout_fails_closed() {
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = LocalApprover::new(ks, pending)
            .with_dev(DevMode::Off)
            .with_timeout(Duration::from_millis(30));
        assert_eq!(approver.decide(&ctx("req-2", "read .env")), Decision::Deny);
    }
}
