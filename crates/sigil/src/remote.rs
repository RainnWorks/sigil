//! The remote approver: satisfy an approval by asking a paired phone over a
//! [`Transport`], instead of a local Touch ID / control-socket decision.
//!
//! This is the path that makes the daemon inert at rest. The daemon holds no
//! DEK; on each request it:
//!
//! 1. builds an [`ApprovalRequest`] from the daemon-verified [`ApprovalContext`]
//!    (never anything the client claimed),
//! 2. seals it into an [`Envelope`] (signed by the daemon's pinned key, sealed
//!    to the phone's pinned agreement key) and sends it `ToPhone`,
//! 3. blocks up to a timeout for the phone's sealed [`ApprovalResponse`]
//!    `ToDaemon`, verifying + replay-checking + decrypting it, and
//! 4. on approve, hands the DEK the phone delivered back to the gate as an
//!    [`ApprovalOutcome`]; the daemon uses it to decrypt the one token and
//!    zeroizes it.
//!
//! Every failure — seal error, transport error, timeout, an unverifiable or
//! mis-correlated response, or an "approve" that carries no DEK — fails closed
//! to a `Deny` outcome. Only a well-formed, authenticated approve carrying a DEK
//! releases a secret.
//!
//! ## The idle registration listener
//!
//! The phone deposits its push token as a [`PushRegister`] on the ToDaemon
//! channel *the moment it arms*, not only alongside an approval. The relay holds
//! a deposit for a short TTL and then drops it, so unless a gated command happens
//! to fire within that window the token is gone before [`round_trip`] ever looks.
//! To catch the arm-time registration the daemon runs a persistent
//! [`run_registration_listener`](RemoteApprover::run_registration_listener): while
//! idle it owns the ToDaemon reads, records any [`PushRegister`] to the push
//! store, and drops anything else.
//!
//! The listener and an in-flight [`round_trip`] must never both hold a ToDaemon
//! read at once: the relay hands a fresh deposit to exactly one waiter, so a
//! concurrent listener could swallow the approval's own [`ApprovalResponse`] and
//! spuriously deny it. Exclusion is a single [`Mutex`] (`channel`) that BOTH paths
//! acquire around every ToDaemon read: `round_trip` holds it for its whole
//! deposit-and-wait, and the listener takes it only for one short poll at a time.
//! An `approval_active` flag is a fast-path hint so the listener yields (sleeps
//! rather than parking on the lock) while an approval runs, keeping shutdown
//! responsive; correctness rests on the mutex alone, never the flag. At most one
//! outstanding ToDaemon read exists at any instant.
//!
//! [`round_trip`]: RemoteApprover::round_trip

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use sigil_proto::envelope::Envelope;
use sigil_proto::identity::DeviceIdentity;
use sigil_proto::ReplayGuard;
use sigil_proto::{
    mailbox_id, now_ms, ApprovalRequest, ApprovalResponse, Decision as ProtoDecision, Direction,
    PeerIdentity, Provenance, PushHint, PushRegister, ToDaemonMessage, Transport,
};

use crate::approve::{ApprovalContext, ApprovalOutcome, Approver, Decision};
use crate::push_store::PushStore;

/// Default wait for a phone decision before failing closed.
pub const DEFAULT_REMOTE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long one idle-listener poll of the ToDaemon channel waits before it loops
/// to re-check the shutdown/approval flags. Short (not the relay's ~25s hold) so
/// that on a transport which honours the timeout (the in-process relay and the
/// tests) an approval that wants the channel waits at most one poll for the
/// listener to release the lock. On the network relay a single GET may hold for
/// the relay's own long-poll regardless (see the module note and residuals).
const LISTEN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The beat the listener sleeps when it yields the channel to an active approval
/// (or loses the race for the lock) before re-checking. Keeps the loop from
/// busy-spinning while staying responsive to a shutdown signal.
const LISTEN_YIELD: Duration = Duration::from_millis(50);

/// Backoff after a transport error in the listener, so a persistently failing
/// poll settles instead of spinning.
const LISTEN_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// An approver backed by a paired phone reachable over a [`Transport`].
pub struct RemoteApprover {
    transport: Arc<dyn Transport>,
    /// The daemon's own identity: signs requests, opens responses.
    identity: DeviceIdentity,
    /// The pinned phone identity: verifies requests it receives, is sealed to.
    phone: PeerIdentity,
    /// The shared mailbox both parties route on.
    pairing_id: [u8; 32],
    /// Daemon -> phone envelope counter (monotonic).
    counter: AtomicU64,
    /// Phone -> daemon replay guard. Guards EVERY inbound envelope on the
    /// ToDaemon channel, responses and push-registrations alike, since the phone
    /// counts them on one monotonic sequence (see [`Self::classify`]).
    guard: Mutex<ReplayGuard>,
    timeout: Duration,
    machine: String,
    /// Phone push registrations, keyed by mailbox. A registration arrives inline
    /// on the ToDaemon channel and is recorded here; the token is forwarded to the
    /// relay per deposit so the relay (not the daemon) rings the doorbell.
    push_store: Arc<PushStore>,
    /// The single-owner lock over ToDaemon reads. Both an approval [`round_trip`]
    /// (which holds it for the whole deposit-and-wait) and the idle registration
    /// listener (which takes it for one short poll at a time) acquire it, so at
    /// most one ToDaemon read is ever outstanding and the listener can never
    /// swallow an approval's response. This is the correctness guarantee; the
    /// [`approval_active`](Self::approval_active) flag is only a latency hint.
    ///
    /// [`round_trip`]: Self::round_trip
    channel: Mutex<()>,
    /// Set for the duration of an approval [`round_trip`](Self::round_trip). A
    /// pure fast-path hint: the listener reads it to yield the channel (sleep
    /// rather than park on `channel`) while an approval runs, which keeps the
    /// listener free to observe the shutdown flag instead of blocking behind a
    /// multi-minute approval. Exclusion never depends on it.
    approval_active: AtomicBool,
    /// How long one idle listener poll waits; a field only so tests can shrink it.
    listen_poll: Duration,
}

impl RemoteApprover {
    /// Wire an approver to `transport` for the pairing between `identity` (the
    /// daemon) and `phone` (the pinned approver). The mailbox is derived from the
    /// two pinned identities, matching what the phone computes.
    pub fn new(
        transport: Arc<dyn Transport>,
        identity: DeviceIdentity,
        phone: PeerIdentity,
    ) -> Self {
        let pairing_id = mailbox_id(&identity.peer_identity(), &phone);
        Self {
            transport,
            identity,
            phone,
            pairing_id,
            counter: AtomicU64::new(0),
            guard: Mutex::new(ReplayGuard::new()),
            timeout: DEFAULT_REMOTE_TIMEOUT,
            machine: hostname(),
            // Default to an in-memory registration store. The production daemon
            // replaces it via `with_push` with the disk-backed one; the
            // softphone/local test loop runs with this no-op and never touches the
            // filesystem.
            push_store: Arc::new(PushStore::ephemeral()),
            channel: Mutex::new(()),
            approval_active: AtomicBool::new(false),
            listen_poll: LISTEN_POLL_INTERVAL,
        }
    }

    /// Attach the persistent push registration store. The production `build_gate`
    /// wires the disk-backed one so a registered token survives a restart and is
    /// forwarded to the relay on each deposit.
    pub fn with_push(mut self, push_store: Arc<PushStore>) -> Self {
        self.push_store = push_store;
        self
    }

    /// Override the wait for a phone decision (tests use a short one).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The mailbox id the phone and daemon share for this pairing.
    pub fn mailbox(&self) -> [u8; 32] {
        self.pairing_id
    }

    /// Build the request from the daemon-verified context. Provider-blind: the
    /// command, secret refs, and display hint were prepared by the daemon's
    /// provider; this just packages them with the caller provenance.
    fn build_request(&self, ctx: &ApprovalContext) -> ApprovalRequest {
        let now = now_ms();
        let process_chain = ctx
            .provenance
            .split(" \u{2192} ")
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .collect();
        let timeout_ms = self.timeout.as_millis() as u64;
        ApprovalRequest {
            request_id: ctx.id.clone(),
            kind: ctx.kind,
            command: ctx.command.clone(),
            secrets: ctx.secret_refs.clone(),
            ssh: ctx.ssh.clone(),
            provenance: Provenance {
                process_chain,
                cwd: ctx.cwd.clone(),
                machine: self.machine.clone(),
                requested_at: now,
            },
            lease_policy: ctx.lease,
            reason: None,
            // A v2 account carries its threshold challenge to the phone; a v1
            // account leaves this absent and takes the DEK path.
            threshold: ctx.threshold.clone(),
            expires_at: now + timeout_ms,
            timeout_ms,
        }
    }

    /// The whole round trip, or `None` (fail closed) at the first misstep.
    ///
    /// The ToDaemon channel is shared: it carries the phone's approval responses
    /// AND unsolicited push-registrations. This method demultiplexes it. Any
    /// [`PushRegister`] it meets (buffered from an idle registration, or arriving
    /// mid-wait) is recorded and skipped; only the [`ApprovalResponse`] correlating
    /// to this request resolves the round trip. A registration can therefore never
    /// be mistaken for a failed response, which would deny a legitimate approval.
    fn round_trip(&self, ctx: &ApprovalContext) -> Option<ApprovalOutcome> {
        let req = self.build_request(ctx);

        // Take exclusive ownership of the ToDaemon channel for the entire round
        // trip. The flag is raised FIRST (so the idle listener stops taking new
        // polls while we wait for the lock), then we block on the lock until the
        // listener's current poll, if any, releases it. Only after we hold the
        // lock do we deposit the request; the phone therefore cannot answer while
        // any listener poll is outstanding, so the response can only come back to
        // us. Both guards are RAII: a panic or early return still clears the flag
        // and frees the channel. Concurrent approvals with different grant keys
        // serialise here too, which is what keeps "one outstanding ToDaemon read"
        // true and stops two waits stealing each other's responses.
        let _active = ApprovalActiveGuard::raise(&self.approval_active);
        let _channel = self.channel.lock().expect("remote channel poisoned");

        // Drain any registration the phone sent while we were idle, so the deposit
        // below carries the freshest token. Non-blocking.
        self.drain_pending();

        // Seal the request for the phone.
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let env = Envelope::seal(
            &req,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.phone,
        )
        .ok()?;

        // Deposit it to the relay, forwarding the phone's push token (if any) so
        // the RELAY rings a content-free doorbell. The token wakes the phone to
        // fetch the request; it is best-effort and never gates correctness (the
        // phone's poll backstop delivers regardless). The daemon signs no push.
        self.transport
            .deposit_to_phone(self.pairing_id, &env, self.push_hint())
            .ok()?;

        // Await the correlating response, handling any interleaved registration.
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None; // timed out: fail closed to deny
            }
            let env = self
                .transport
                .recv(self.pairing_id, Direction::ToDaemon, remaining)
                .ok()??;
            match self.classify(env) {
                Some(ToDaemonMessage::Push(pr)) => {
                    self.record_registration(&pr);
                    continue;
                }
                Some(ToDaemonMessage::Response(resp)) => {
                    // A response for a different request is stale (a prior wait
                    // timed out); skip it and keep waiting for ours.
                    if resp.request_id != req.request_id {
                        continue;
                    }
                    return self.outcome_for(&req, resp);
                }
                // An envelope that would not open/decode (tamper, wrong key, a
                // replayed counter) is dropped; keep waiting until the deadline.
                None => continue,
            }
        }
    }

    /// Consume everything already buffered on the ToDaemon channel without
    /// blocking, recording any registration. Used before a send so the doorbell
    /// sees a token the phone registered while the daemon was idle.
    fn drain_pending(&self) {
        while let Ok(Some(env)) =
            self.transport
                .recv(self.pairing_id, Direction::ToDaemon, Duration::ZERO)
        {
            match self.classify(env) {
                Some(ToDaemonMessage::Push(pr)) => self.record_registration(&pr),
                // A buffered response with no in-flight request to match is stale;
                // drop it.
                Some(ToDaemonMessage::Response(_)) | None => {}
            }
        }
    }

    /// Verify, replay-check, decrypt, and classify one inbound envelope. Returns
    /// `None` when it fails any of those (fail closed). The single [`ReplayGuard`]
    /// covers responses and registrations together, matching the phone's single
    /// monotonic outbound counter.
    fn classify(&self, env: Envelope) -> Option<ToDaemonMessage> {
        let value: serde_json::Value = {
            let mut guard = self.guard.lock().expect("remote guard poisoned");
            env.open(&self.phone, &self.identity.agreement, &mut guard)
                .ok()?
        };
        ToDaemonMessage::from_value(value).ok()
    }

    /// Turn a correlated [`ApprovalResponse`] into an [`ApprovalOutcome`], applying
    /// the same fail-closed rules as before: an approve must carry a DEK (v1) or a
    /// partial for this exact account (v2); a deny carries neither.
    fn outcome_for(
        &self,
        req: &ApprovalRequest,
        resp: ApprovalResponse,
    ) -> Option<ApprovalOutcome> {
        match resp.decision {
            ProtoDecision::Denied => Some(ApprovalOutcome::local(Decision::Deny)),
            ProtoDecision::Approved => {
                let decision = match &resp.lease {
                    Some(lease) => Decision::Lease(Duration::from_millis(lease.ttl_ms)),
                    None => Decision::Approve,
                };
                if let Some(challenge) = &req.threshold {
                    // v2 account: an approve MUST carry the phone's partial Z_F for
                    // this exact account. A missing/short partial, or one for a
                    // different account, fails closed rather than approving emptily.
                    let (account_id, zf) = resp.partial_zf()?;
                    if account_id != challenge.account_id {
                        return None;
                    }
                    Some(ApprovalOutcome::with_partial(decision, zf))
                } else {
                    // v1 account: an approve MUST carry the DEK.
                    let dek = resp.dek()?;
                    let dek = Zeroizing::new(*dek.as_bytes());
                    Some(ApprovalOutcome::with_dek(decision, dek))
                }
            }
        }
    }

    /// Record a phone push registration for this pairing, persisted so it survives
    /// a daemon restart. Re-registration overwrites (token rotation).
    fn record_registration(&self, pr: &PushRegister) {
        self.push_store
            .register(self.pairing_id, &pr.token, &pr.platform, now_ms());
    }

    /// The push doorbell hint to forward to the relay for this pairing: the phone's
    /// registered token and platform, if any. `None` means no token is on file, so
    /// the deposit carries no hint and the phone relies on its poll backstop. The
    /// daemon does not interpret the platform (the relay owns push): it forwards
    /// whatever the phone registered verbatim.
    fn push_hint(&self) -> Option<PushHint> {
        self.push_store.get(self.pairing_id).map(|reg| PushHint {
            token: reg.token,
            platform: reg.platform,
        })
    }

    /// Own the idle ToDaemon reads for the life of the daemon so an arm-time
    /// [`PushRegister`] is captured the instant it lands and persisted to the push
    /// store, rather than expiring in the relay before the next approval looks.
    ///
    /// Runs until `shutdown` is set. Each iteration either yields (an approval is
    /// active, or the channel lock is momentarily held) or takes the channel lock
    /// for exactly one short poll. A [`PushRegister`] is recorded; a stale
    /// response with no approval in flight, or an envelope that will not open, is
    /// dropped. Verify/replay semantics are identical to the approval path because
    /// both go through [`classify`](Self::classify) over the one shared
    /// [`ReplayGuard`]. The listener never grants anything and never touches a DEK.
    ///
    /// The mutual exclusion is the `channel` mutex, held around the poll: while an
    /// approval `round_trip` holds it, the listener parks on the flag instead of
    /// the lock (so it keeps checking `shutdown`), and after `round_trip` deposits
    /// no listener read can be outstanding. See the module note for the one
    /// residual: on the network relay a single poll may block for the relay's own
    /// long-poll hold, so an approval firing mid-poll can wait that long to take
    /// the channel; correctness is unaffected because the phone cannot answer
    /// until we deposit, which happens only once we hold the lock.
    pub fn run_registration_listener(&self, shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire) {
            // An approval owns the channel: yield without parking on the lock, so
            // we keep observing `shutdown` instead of blocking behind a possibly
            // multi-minute approval.
            if self.approval_active.load(Ordering::Acquire) {
                std::thread::sleep(LISTEN_YIELD);
                continue;
            }
            // Take the channel only if it is free right now; never queue behind an
            // approval that is about to raise the flag.
            let channel = match self.channel.try_lock() {
                Ok(g) => g,
                Err(_) => {
                    std::thread::sleep(LISTEN_YIELD);
                    continue;
                }
            };
            // Close the race where an approval raised the flag between our check
            // and the lock: if it is active now, release the lock unused and yield
            // so the approval acquires it and no listener read is ever outstanding
            // while a response could arrive.
            if self.approval_active.load(Ordering::Acquire) {
                drop(channel);
                std::thread::sleep(LISTEN_YIELD);
                continue;
            }
            match self
                .transport
                .recv(self.pairing_id, Direction::ToDaemon, self.listen_poll)
            {
                Ok(Some(env)) => match self.classify(env) {
                    Some(ToDaemonMessage::Push(pr)) => self.record_registration(&pr),
                    // A response with no approval in flight is stale (a prior wait
                    // timed out and moved on); an undecodable envelope failed verify
                    // or replay. Either way: drop it and keep listening.
                    Some(ToDaemonMessage::Response(_)) | None => {}
                },
                // The poll held for its interval with nothing to read: loop.
                Ok(None) => {}
                // A transport fault (the network relay only errors on an exhausted
                // retry budget or a poisoned buffer): back off so a persistent
                // failure does not spin, then retry. Release the lock first.
                Err(_) => {
                    drop(channel);
                    std::thread::sleep(LISTEN_ERROR_BACKOFF);
                }
            }
        }
    }

    /// Shrink the idle-listener poll interval so a test needn't wait the full
    /// [`LISTEN_POLL_INTERVAL`] for a poll to cycle.
    #[cfg(test)]
    fn with_listen_poll(mut self, interval: Duration) -> Self {
        self.listen_poll = interval;
        self
    }
}

/// RAII guard that flags an approval as active for its lifetime, clearing the
/// flag on drop so a panic or early return in [`RemoteApprover::round_trip`] still
/// resets it. The flag is only a listener latency hint (see the field docs);
/// exclusion is the `channel` mutex, so a lost race here is never a correctness
/// problem, only a wasted listener beat.
struct ApprovalActiveGuard<'a>(&'a AtomicBool);

impl<'a> ApprovalActiveGuard<'a> {
    fn raise(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);
        Self(flag)
    }
}

impl Drop for ApprovalActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Lets the daemon share one [`RemoteApprover`] between the approval gate (which
/// needs a `Box<dyn Approver>`) and the background registration listener (which
/// needs a live handle) by holding it in an [`Arc`] and cloning. The forwarding
/// dereferences to the inner approver rather than recursing.
impl Approver for Arc<RemoteApprover> {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        (**self).decide(ctx)
    }
}

impl Approver for RemoteApprover {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        self.round_trip(ctx)
            .unwrap_or_else(|| ApprovalOutcome::local(Decision::Deny))
    }
}

/// Best-effort machine name for the approval screen. Reads `$HOST`/`$HOSTNAME`,
/// falling back to a constant so the field is never empty.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "this-mac".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approve::ApprovalContext;
    use sigil_proto::{LeasePolicy, RequestKind, SecretRef};

    #[test]
    fn build_request_is_provider_blind() {
        // The approver copies the provider-prepared fields verbatim; it contains
        // no op-specific parsing.
        let transport = std::sync::Arc::new(sigil_proto::LocalRelay::new());
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let approver = RemoteApprover::new(transport, daemon, phone);

        let ctx = ApprovalContext {
            id: "req-1".into(),
            account: "Rowm".into(),
            scope: "read op://Engineering/.env/password".into(),
            grant_hex: "dead".into(),
            provenance: "zsh \u{2192} op".into(),
            cwd: "/p".into(),
            command: vec![
                "op".into(),
                "read".into(),
                "op://Engineering/.env/password".into(),
            ],
            secret_refs: vec![SecretRef {
                provider: "1password".into(),
                reference: "op://Engineering/.env/password".into(),
                segments: vec!["Engineering".into(), ".env".into(), "password".into()],
                label: ".env".into(),
            }],
            kind: RequestKind::SecretRead,
            lease: LeasePolicy::Leasable { max_secs: 900 },
            ssh: None,
            threshold: None,
        };
        let req = approver.build_request(&ctx);
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.kind, RequestKind::SecretRead);
        assert_eq!(
            req.lease_policy,
            LeasePolicy::Leasable { max_secs: 900 },
            "lease policy is threaded from the context"
        );
        assert_eq!(req.command, ctx.command);
        assert_eq!(req.secrets, ctx.secret_refs);
        assert_eq!(req.provenance.process_chain, vec!["zsh", "op"]);
    }

    use sigil_proto::{Dek, LocalRelay};

    /// Clone a device identity for a test (the approver takes ownership of one
    /// copy while the test keeps another to act as the phone's peer).
    fn clone_id(id: &DeviceIdentity) -> DeviceIdentity {
        DeviceIdentity {
            signing: id.signing.clone(),
            agreement: id.agreement.clone(),
        }
    }

    fn secret_ctx(id: &str) -> ApprovalContext {
        ApprovalContext {
            id: id.into(),
            account: "Rowm".into(),
            scope: "read op://Engineering/.env/password".into(),
            grant_hex: "dead".into(),
            provenance: "op".into(),
            cwd: "/p".into(),
            command: vec!["op".into(), "read".into()],
            secret_refs: vec![],
            kind: RequestKind::SecretRead,
            lease: LeasePolicy::RunOnce,
            ssh: None,
            threshold: None,
        }
    }

    /// The correctness-critical demux: a phone that (re)registers its push token
    /// on the same ToDaemon channel must not derail an approval. Here a
    /// PushRegister is buffered before the approval, and the approve response
    /// follows it; the daemon records the token AND still resolves the approval
    /// with the delivered DEK. Without the demux, the registration would be read
    /// as a malformed response and deny a legitimate request.
    #[test]
    fn push_register_interleaved_with_a_response_is_stored_and_does_not_break_approval() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);

        let store = Arc::new(PushStore::ephemeral());
        let approver = RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub)
            .with_push(store.clone())
            .with_timeout(Duration::from_secs(2));

        // The phone registers its push token first (counter 1, ToDaemon).
        let pr = PushRegister::new("cafef00d", "apns");
        let pr_env =
            Envelope::seal(&pr, mailbox, 1, &phone.signing, &daemon.peer_identity()).unwrap();
        relay.send(mailbox, Direction::ToDaemon, &pr_env).unwrap();

        // A phone thread waits for the request, then approves it (counter 2).
        let phone_thread = {
            let relay = relay.clone();
            let daemon_pub = daemon.peer_identity();
            std::thread::spawn(move || {
                let _req = relay
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the daemon sent a request");
                let resp = ApprovalResponse::approve("req-1", &Dek::from_bytes([9u8; 32]), 1);
                let env = Envelope::seal(&resp, mailbox, 2, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-1"));
        phone_thread.join().unwrap();

        assert!(
            outcome.decision.is_grant(),
            "the approval must still succeed"
        );
        assert!(outcome.dek.is_some(), "the delivered DEK reaches the gate");
        // The push token was recorded off the same channel.
        let reg = store.get(mailbox).expect("the registration was stored");
        assert_eq!(reg.token, "cafef00d");
        assert_eq!(reg.platform, "apns");
    }

    /// A registration that arrives while the daemon is idle (no approval waiting)
    /// is picked up by the next round trip's pre-drain, so its token is on file
    /// for the doorbell even though it never rode alongside a response.
    #[test]
    fn an_idle_registration_is_drained_on_the_next_round_trip() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone.peer_identity());

        let store = Arc::new(PushStore::ephemeral());
        let approver = RemoteApprover::new(
            Arc::new(relay.clone()),
            clone_id(&daemon),
            phone.peer_identity(),
        )
        .with_push(store.clone())
        // A short timeout: no response ever comes, so the approval denies, but
        // the pre-drain still records the buffered registration.
        .with_timeout(Duration::from_millis(80));

        let pr = PushRegister::new("beadfeed", "apns");
        let pr_env =
            Envelope::seal(&pr, mailbox, 1, &phone.signing, &daemon.peer_identity()).unwrap();
        relay.send(mailbox, Direction::ToDaemon, &pr_env).unwrap();

        let outcome = approver.decide(&secret_ctx("req-x"));
        assert!(
            !outcome.decision.is_grant(),
            "no response arrives, so it denies"
        );
        assert_eq!(
            store.get(mailbox).expect("registration drained").token,
            "beadfeed"
        );
    }

    /// The fix: a PushRegister the phone deposits while the daemon is idle (NO
    /// approval in flight, and no round trip about to run) is caught by the
    /// background listener and lands in the push store on its own. This is the
    /// arm-time path that used to be lost when the relay dropped the deposit
    /// before any command fired.
    #[test]
    fn the_idle_listener_captures_an_arm_time_registration() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone.peer_identity());

        let store = Arc::new(PushStore::ephemeral());
        let approver = Arc::new(
            RemoteApprover::new(
                Arc::new(relay.clone()),
                clone_id(&daemon),
                phone.peer_identity(),
            )
            .with_push(store.clone())
            .with_listen_poll(Duration::from_millis(20)),
        );

        // Start the listener; nothing is armed yet.
        let shutdown = Arc::new(AtomicBool::new(false));
        let listener = {
            let approver = approver.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || approver.run_registration_listener(&shutdown))
        };

        // The phone arms: it deposits its push token with no approval outstanding.
        let pr = PushRegister::new("d00dfeed", "apns");
        let pr_env =
            Envelope::seal(&pr, mailbox, 1, &phone.signing, &daemon.peer_identity()).unwrap();
        relay.send(mailbox, Direction::ToDaemon, &pr_env).unwrap();

        // The listener records it without any round trip ever running.
        let mut tries = 0;
        let reg = loop {
            if let Some(reg) = store.get(mailbox) {
                break reg;
            }
            tries += 1;
            assert!(tries < 200, "the listener never captured the registration");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(reg.token, "d00dfeed");
        assert_eq!(reg.platform, "apns");

        shutdown.store(true, Ordering::SeqCst);
        listener.join().unwrap();
    }

    /// The correctness constraint: with the background listener running, a
    /// concurrent approval must still receive its OWN response. The listener must
    /// not swallow the ApprovalResponse off the shared ToDaemon channel (which
    /// would deny a legitimate approval). Exclusion is the `channel` mutex.
    #[test]
    fn the_listener_never_steals_a_concurrent_approvals_response() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);

        let store = Arc::new(PushStore::ephemeral());
        let approver = Arc::new(
            RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub)
                .with_push(store.clone())
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20)),
        );

        // The listener runs for the whole test, contending for the same channel.
        let shutdown = Arc::new(AtomicBool::new(false));
        let listener = {
            let approver = approver.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || approver.run_registration_listener(&shutdown))
        };

        // The phone side: wait for the request, then approve it (counter 1).
        let phone_thread = {
            let relay = relay.clone();
            let daemon_pub = daemon.peer_identity();
            std::thread::spawn(move || {
                let _req = relay
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the daemon sent a request");
                let resp = ApprovalResponse::approve("req-live", &Dek::from_bytes([5u8; 32]), 1);
                let env = Envelope::seal(&resp, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-live"));
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        listener.join().unwrap();

        assert!(
            outcome.decision.is_grant(),
            "the approval must succeed; the listener must not have stolen its response"
        );
        assert!(outcome.dek.is_some(), "the delivered DEK reaches the gate");
    }
}
