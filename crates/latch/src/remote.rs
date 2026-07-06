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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use latch_proto::envelope::Envelope;
use latch_proto::identity::DeviceIdentity;
use latch_proto::ReplayGuard;
use latch_proto::{
    mailbox_id, now_ms, ApprovalRequest, ApprovalResponse, Decision as ProtoDecision, Direction,
    PeerIdentity, Provenance, PushHint, PushRegister, ToDaemonMessage, Transport,
};

use crate::approve::{ApprovalContext, ApprovalOutcome, Approver, Decision};
use crate::push_store::PushStore;

/// Default wait for a phone decision before failing closed.
pub const DEFAULT_REMOTE_TIMEOUT: Duration = Duration::from_secs(120);

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
            risk: ctx.risk,
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
    use latch_proto::{RequestKind, RiskLevel, SecretRef};

    #[test]
    fn build_request_is_provider_blind() {
        // The approver copies the provider-prepared fields verbatim; it contains
        // no op-specific parsing.
        let transport = std::sync::Arc::new(latch_proto::LocalRelay::new());
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
            risk: RiskLevel::Elevated,
            ssh: None,
            threshold: None,
        };
        let req = approver.build_request(&ctx);
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.kind, RequestKind::SecretRead);
        assert_eq!(
            req.risk,
            RiskLevel::Elevated,
            "risk is threaded from the context"
        );
        assert_eq!(req.command, ctx.command);
        assert_eq!(req.secrets, ctx.secret_refs);
        assert_eq!(req.provenance.process_chain, vec!["zsh", "op"]);
    }

    use latch_proto::{Dek, LocalRelay};

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
            risk: RiskLevel::Routine,
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
}
