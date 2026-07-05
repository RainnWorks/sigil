//! The approval gate: nothing is fulfilled without a fresh out-of-band decision.
//!
//! The real shipping factor is the paired phone ([`crate::remote::RemoteApprover`]);
//! this module is the local factor. [`LocalApprover`] resolves a decision in
//! order:
//!
//! * `LATCH_DEV_AUTOAPPROVE` — headless auto-approve for the gated-loop tests
//!   and dev. Only functions when the daemon enabled it via `with_dev`, which
//!   happens **only** under `--dev-insecure` (see [`crate::factor`]).
//! * a live Mac Secure Enclave DEK envelope — prompt Touch ID to unwrap it
//!   (NEEDS-VERIFICATION; see [`crate::keystore_macos`]). A successful unwrap is
//!   the biometric approving factor.
//! * the control socket — register the request as pending and block until a
//!   `latch approve --local --id <id>` (or `deny`) arrives, or the timeout fails
//!   closed. This path is same-UID forgeable (`docs/security-claims.md`
//!   residual #1), so it is gated behind `with_control_socket`, enabled **only**
//!   under `--dev-insecure`. Without it, an unresolved local decision fails
//!   closed at once instead of offering a self-approvable gate.
//!
//! A daemon with no real factor and no `--dev-insecure` runs a [`NullApprover`]
//! that denies everything, so it is never silently self-approvable.
//!
//! [`ApprovalGate`] wraps an approver with request coalescing: identical
//! in-flight requests (same grant key + scope) wait behind one decision, so a
//! burst costs one glance. Deny/timeout always fails closed.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::keystore::Keystore;
use crate::secrets::Dek;

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

/// The full result of an approval: the [`Decision`], plus the DEK when the
/// approving factor *supplied* one.
///
/// This is the seam that lets the inert daemon serve a secret with no key at
/// rest. The local approver (Touch ID / control socket) returns `dek: None`; the
/// daemon then unwraps the DEK from its own keystore. The remote approver (the
/// paired phone / softphone) returns `dek: Some(_)`: the phone holds the one DEK
/// and delivers it, re-sealed to the daemon, per approval. Either way the DEK is
/// used once and zeroized (`Dek` is `Zeroizing`).
#[derive(Clone)]
pub struct ApprovalOutcome {
    pub decision: Decision,
    pub dek: Option<Dek>,
    /// For a v2 (threshold) account: the phone's partial `Z_F = x(f·E)` the
    /// daemon combines with its Mac share `m` to open the token. Mutually
    /// exclusive with [`dek`](Self::dek) in practice — a v1 approve carries a
    /// DEK, a v2 approve carries this. Zeroize-on-drop.
    pub zf: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl ApprovalOutcome {
    /// A decision with no key material: the daemon unwraps its own key (local
    /// path) or, for v2, this is a deny.
    pub fn local(decision: Decision) -> Self {
        Self {
            decision,
            dek: None,
            zf: None,
        }
    }

    /// A grant that carries the phone-delivered DEK (remote v1 path).
    pub fn with_dek(decision: Decision, dek: Dek) -> Self {
        Self {
            decision,
            dek: Some(dek),
            zf: None,
        }
    }

    /// A grant that carries the phone's v2 threshold partial `Z_F` (remote v2
    /// path). The daemon combines it with the Mac share to derive the token key.
    pub fn with_partial(decision: Decision, zf: zeroize::Zeroizing<[u8; 32]>) -> Self {
        Self {
            decision,
            dek: None,
            zf: Some(zf),
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
    /// The scope string used for lease bookkeeping and local display, e.g.
    /// `read op://Engineering/.env`. Internal; the remote request carries the
    /// generic [`command`](Self::command)/[`secret_refs`](Self::secret_refs).
    pub scope: String,
    /// Grant-key hex, for correlating with `latch lease list`.
    pub grant_hex: String,
    /// Human process chain, e.g. `zsh → claude → op`.
    pub provenance: String,
    pub cwd: String,
    /// The argv the shim intercepted. Carried verbatim into the remote request.
    pub command: Vec<String>,
    /// Provider-agnostic references the daemon's provider derived from the
    /// command, for the approver's readout. Empty for non-secret requests.
    pub secret_refs: Vec<latch_proto::SecretRef>,
    /// The display hint the provider assigned (how the approver should render).
    pub kind: latch_proto::RequestKind,
    /// The risk policy for this request (from the command config, or a provider
    /// default). Scales the approve friction on the phone; deny is always one tap.
    pub risk: latch_proto::RiskLevel,
    /// Present for an `ssh_signature` request: the key label, derived
    /// destination, and data-to-sign fingerprint the approver renders. `None`
    /// for secret reads and control requests.
    pub ssh: Option<latch_proto::SshChallenge>,
    /// Present when the routed account is a v2 (threshold) account: the base
    /// point `E` the phone key-agrees against, plus the account binding it shows
    /// and consents to (R5). The remote approver copies this into the request; a
    /// v1 account leaves it `None` and takes the DEK path.
    pub threshold: Option<latch_proto::ThresholdChallenge>,
}

/// Resolves an approval request to an [`ApprovalOutcome`]. Blocking; may time
/// out to a `Deny` outcome. Every failure path must fail closed (return a `Deny`
/// outcome, never a grant).
pub trait Approver: Send + Sync {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome;
}

/// One parked local approval: the channel a decision is delivered on, plus the
/// request context and timing the daemon needs to enumerate it for `pending`.
struct Waiter {
    tx: Sender<Decision>,
    ctx: ApprovalContext,
    queued_at_ms: u64,
    timeout_ms: u64,
}

/// A read-only view of one parked request, for `latch pending --json`.
#[derive(Debug, Clone)]
pub struct PendingSnapshot {
    pub ctx: ApprovalContext,
    /// When the request parked, unix ms.
    pub queued_at_ms: u64,
    /// The local-decision timeout, ms (the countdown full scale).
    pub timeout_ms: u64,
}

/// The mutable inside of [`PendingRegistry`]: the parked waiters plus a version
/// counter bumped on every change, so a subscriber can block until the set moves.
#[derive(Default)]
struct Inner {
    waiters: HashMap<String, Waiter>,
    version: u64,
}

/// Registry of pending local approvals, keyed by request id. Shared between the
/// [`LocalApprover`] (which parks a waiter) and the daemon's control handler
/// (which resolves it, enumerates the parked set for `pending`, or streams
/// changes for `subscribe_pending`).
#[derive(Default)]
pub struct PendingRegistry {
    inner: Mutex<Inner>,
    /// Notified whenever `inner.version` changes, waking `wait_for_change`.
    changed: Condvar,
}

impl PendingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump the version and wake any subscriber. Caller holds `inner`.
    fn bump(&self, inner: &mut Inner) {
        inner.version += 1;
        self.changed.notify_all();
    }

    fn park(&self, ctx: &ApprovalContext, timeout: Duration) -> Receiver<Decision> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut inner = self.inner.lock().expect("pending registry poisoned");
        inner.waiters.insert(
            ctx.id.clone(),
            Waiter {
                tx,
                ctx: ctx.clone(),
                queued_at_ms: latch_proto::now_ms(),
                timeout_ms: timeout.as_millis() as u64,
            },
        );
        self.bump(&mut inner);
        rx
    }

    fn unpark(&self, id: &str) {
        let mut inner = self.inner.lock().expect("pending registry poisoned");
        if inner.waiters.remove(id).is_some() {
            self.bump(&mut inner);
        }
    }

    /// Deliver a decision to a parked local approval. Returns true if a waiter
    /// was found (the id was pending).
    pub fn resolve(&self, id: &str, decision: Decision) -> bool {
        let tx = self
            .inner
            .lock()
            .expect("pending registry poisoned")
            .waiters
            .get(id)
            .map(|w| w.tx.clone());
        match tx {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Ids currently awaiting a local decision.
    pub fn pending_ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("pending registry poisoned")
            .waiters
            .keys()
            .cloned()
            .collect()
    }

    /// A snapshot of every parked request, for enumeration. Newest-first.
    pub fn snapshot(&self) -> Vec<PendingSnapshot> {
        let mut out: Vec<PendingSnapshot> = self
            .inner
            .lock()
            .expect("pending registry poisoned")
            .waiters
            .values()
            .map(|w| PendingSnapshot {
                ctx: w.ctx.clone(),
                queued_at_ms: w.queued_at_ms,
                timeout_ms: w.timeout_ms,
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.queued_at_ms));
        out
    }

    /// The current change version. A subscriber records this alongside a
    /// snapshot, then calls [`wait_for_change`](Self::wait_for_change) with it.
    pub fn version(&self) -> u64 {
        self.inner
            .lock()
            .expect("pending registry poisoned")
            .version
    }

    /// Block until the pending set changes from `since`, or `timeout` elapses.
    /// Returns the current version (equal to `since` only on timeout). The
    /// subscribe loop calls this, then re-snapshots when the version advances.
    pub fn wait_for_change(&self, since: u64, timeout: Duration) -> u64 {
        let inner = self.inner.lock().expect("pending registry poisoned");
        let (inner, _timeout) = self
            .changed
            .wait_timeout_while(inner, timeout, |i| i.version == since)
            .expect("pending registry poisoned");
        inner.version
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

/// The local approver: biometric unwrap, and — only when explicitly enabled —
/// the dev auto-approve switch and the control-socket park.
///
/// Both the dev switch and the control socket default to **off**. They are the
/// same-UID-forgeable paths from `docs/security-claims.md` residual #1, so the
/// daemon turns them on only under [`Factor::DevInsecure`](crate::factor::Factor);
/// with a biometric factor the unwrap is the sole gate and an unresolved
/// decision fails closed rather than parking on the socket.
pub struct LocalApprover {
    keystore: Arc<dyn Keystore>,
    pending: Arc<PendingRegistry>,
    timeout: Duration,
    dev: DevMode,
    /// When false, an unresolved local decision fails closed instead of parking
    /// on the control socket. Only `--dev-insecure` sets it true.
    allow_control_socket: bool,
}

impl LocalApprover {
    /// Build an approver with the forgeable paths off: no dev auto-approve and no
    /// control-socket fallback. The caller opts into either explicitly.
    pub fn new(keystore: Arc<dyn Keystore>, pending: Arc<PendingRegistry>) -> Self {
        Self {
            keystore,
            pending,
            timeout: DEFAULT_APPROVAL_TIMEOUT,
            dev: DevMode::Off,
            allow_control_socket: false,
        }
    }

    /// Override the local-decision timeout (tests use a short one).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the dev auto-approve mode explicitly. Only wired under
    /// `--dev-insecure`; never in a shipping factor.
    pub fn with_dev(mut self, dev: DevMode) -> Self {
        self.dev = dev;
        self
    }

    /// Enable the control-socket park (`latch approve|deny --local`). Only wired
    /// under `--dev-insecure`; off means an unresolved decision fails closed.
    pub fn with_control_socket(mut self, allow: bool) -> Self {
        self.allow_control_socket = allow;
        self
    }
}

/// An approver with no real factor: it denies every request, fail closed. Wired
/// under [`Factor::NoFactor`](crate::factor::Factor) so a daemon with no paired
/// phone and no biometric refuses to serve rather than being self-approvable.
pub struct NullApprover;

impl Approver for NullApprover {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        eprintln!(
            "latch daemon: no approving factor (no paired phone, no hardware biometric); \
             refusing '{}' for {}. Pair a phone, or start with --dev-insecure for local dev.",
            ctx.scope, ctx.account
        );
        ApprovalOutcome::local(Decision::Deny)
    }
}

impl Approver for LocalApprover {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        // The local approver never supplies a DEK; the daemon unwraps its own
        // key from the keystore once the decision is a grant.
        ApprovalOutcome::local(self.decide_local(ctx))
    }
}

impl LocalApprover {
    /// The local decision, without a DEK. Split out so [`Approver::decide`] just
    /// wraps it in a DEK-less [`ApprovalOutcome`].
    fn decide_local(&self, ctx: &ApprovalContext) -> Decision {
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

        // 3. Park until `latch approve|deny --local --id <ctx.id>` or timeout —
        //    but ONLY under --dev-insecure. The control socket is same-UID
        //    forgeable (residual #1), so without it the daemon fails closed here
        //    rather than offering a self-approvable gate.
        if !self.allow_control_socket {
            return Decision::Deny;
        }
        eprintln!(
            "latch daemon: approval required · {} · {}\n            approve: latch approve --local --id {}\n            deny:    latch deny --local --id {}",
            ctx.account, ctx.scope, ctx.id, ctx.id
        );
        let rx = self.pending.park(ctx, self.timeout);
        let decision = rx.recv_timeout(self.timeout).unwrap_or(Decision::Deny);
        self.pending.unpark(&ctx.id);
        decision
    }
}

/// A slot behind which coalesced requests wait for one outcome.
struct Slot {
    done: Mutex<Option<ApprovalOutcome>>,
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
    /// block on the shared slot and receive a clone of the same outcome
    /// (including the phone-delivered DEK, when present).
    pub fn decide(&self, key: [u8; 32], ctx: &ApprovalContext) -> ApprovalOutcome {
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
                let outcome = self.approver.decide(ctx);
                // Publish, wake followers, and clear the in-flight entry so the
                // next burst re-prompts.
                self.inflight.lock().expect("gate poisoned").remove(&key);
                *slot.done.lock().expect("slot poisoned") = Some(outcome.clone());
                slot.cv.notify_all();
                outcome
            }
            Role::Follower(slot) => {
                let mut done = slot.done.lock().expect("slot poisoned");
                while done.is_none() {
                    done = slot.cv.wait(done).expect("slot poisoned");
                }
                done.clone().expect("outcome published")
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
            command: vec!["op".into(), "read".into()],
            secret_refs: Vec::new(),
            kind: latch_proto::RequestKind::SecretRead,
            risk: latch_proto::RiskLevel::Routine,
            ssh: None,
            threshold: None,
        }
    }

    /// Counts calls and returns a fixed decision after a short delay so the
    /// coalescing window is real.
    struct Counting {
        calls: AtomicUsize,
        decision: Decision,
    }
    impl Approver for Counting {
        fn decide(&self, _ctx: &ApprovalContext) -> ApprovalOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(40));
            ApprovalOutcome::local(self.decision)
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
            fn decide(&self, c: &ApprovalContext) -> ApprovalOutcome {
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
                    .decision
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
            fn decide(&self, c: &ApprovalContext) -> ApprovalOutcome {
                self.0.decide(c)
            }
        }
        let gate = ApprovalGate::new(Box::new(Fwd(counting.clone())));
        assert_eq!(
            gate.decide([1u8; 32], &ctx("a", "s1")).decision,
            Decision::Deny
        );
        assert_eq!(
            gate.decide([2u8; 32], &ctx("b", "s2")).decision,
            Decision::Deny
        );
        assert_eq!(counting.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dev_autoapprove_grants_without_biometrics() {
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = LocalApprover::new(ks.clone(), Arc::new(PendingRegistry::new()))
            .with_dev(DevMode::Approve);
        assert_eq!(approver.decide(&ctx("x", "s")).decision, Decision::Approve);

        let lease = LocalApprover::new(ks, Arc::new(PendingRegistry::new()))
            .with_dev(DevMode::Lease(Duration::from_secs(60)));
        assert!(matches!(
            lease.decide(&ctx("x", "s")).decision,
            Decision::Lease(_)
        ));
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
            .with_control_socket(true)
            .with_timeout(Duration::from_secs(2));

        let approver = Arc::new(approver);
        let a2 = approver.clone();
        let handle = std::thread::spawn(move || a2.decide(&ctx("req-1", "read .env")).decision);

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
    fn snapshot_exposes_the_parked_request_context_for_pending() {
        // The `pending` verb reads this snapshot: a parked request must surface
        // its full context (command, kind, cwd) plus a queued time and timeout,
        // so the menubar can render it.
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = Arc::new(
            LocalApprover::new(ks, pending.clone())
                .with_control_socket(true)
                .with_timeout(Duration::from_secs(2)),
        );
        let a2 = approver.clone();
        let handle = std::thread::spawn(move || a2.decide(&ctx("req-snap", "read .env")).decision);

        let mut tries = 0;
        while pending.snapshot().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
            tries += 1;
            assert!(tries < 200, "request never parked");
        }
        let snap = pending.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ctx.id, "req-snap");
        assert_eq!(snap[0].ctx.command, vec!["op", "read"]);
        assert_eq!(snap[0].timeout_ms, 2000);
        assert!(snap[0].queued_at_ms > 0);

        assert!(pending.resolve("req-snap", Decision::Deny));
        assert_eq!(handle.join().unwrap(), Decision::Deny);
        // Once resolved and unparked, the snapshot is empty again.
        assert!(pending.snapshot().is_empty());
    }

    #[test]
    fn version_advances_and_wakes_a_waiter_on_change() {
        // The subscribe stream relies on: the version moves when the set changes,
        // and wait_for_change returns immediately if it already moved past `since`.
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = Arc::new(
            LocalApprover::new(ks, pending.clone())
                .with_control_socket(true)
                .with_timeout(Duration::from_secs(2)),
        );
        let v0 = pending.version();
        // A timeout with no change returns the same version.
        assert_eq!(pending.wait_for_change(v0, Duration::from_millis(20)), v0);

        // Parking a request advances the version.
        let a2 = approver.clone();
        let handle = std::thread::spawn(move || a2.decide(&ctx("req-v", "read .env")).decision);
        let v1 = pending.wait_for_change(v0, Duration::from_secs(2));
        assert_ne!(v1, v0, "park must advance the version");

        // Resolving (and the approver unparking) advances it again.
        assert!(pending.resolve("req-v", Decision::Deny));
        assert_eq!(handle.join().unwrap(), Decision::Deny);
        let v2 = pending.wait_for_change(v1, Duration::from_secs(2));
        assert_ne!(v2, v1, "unpark must advance the version");
    }

    #[test]
    fn local_timeout_fails_closed() {
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver = LocalApprover::new(ks, pending)
            .with_dev(DevMode::Off)
            .with_control_socket(true)
            .with_timeout(Duration::from_millis(30));
        assert_eq!(
            approver.decide(&ctx("req-2", "read .env")).decision,
            Decision::Deny
        );
    }

    #[test]
    fn without_control_socket_an_unresolved_decision_fails_closed_at_once() {
        // The shipping default: no dev switch, no control socket. A local
        // decision that no biometric can satisfy must deny immediately, never
        // park on the same-UID-forgeable control socket (residual #1).
        let pending = Arc::new(PendingRegistry::new());
        let ks: Arc<dyn Keystore> = Arc::new(crate::keystore::MemoryKeystore::new());
        let approver =
            LocalApprover::new(ks, pending.clone()).with_timeout(Duration::from_secs(30));
        let start = std::time::Instant::now();
        assert_eq!(
            approver.decide(&ctx("req-x", "read .env")).decision,
            Decision::Deny
        );
        // It denied on the spot, not after the 30s timeout, and never parked.
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(pending.pending_ids().is_empty());
    }

    #[test]
    fn null_approver_denies_every_request() {
        let outcome = NullApprover.decide(&ctx("req-n", "read .env"));
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.dek.is_none());
    }
}
