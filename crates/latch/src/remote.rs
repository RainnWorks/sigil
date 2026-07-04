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
use std::time::Duration;

use zeroize::Zeroizing;

use latch_proto::envelope::Envelope;
use latch_proto::identity::DeviceIdentity;
use latch_proto::ReplayGuard;
use latch_proto::{
    mailbox_id, now_ms, ApprovalRequest, ApprovalResponse, Decision as ProtoDecision, Direction,
    PeerIdentity, Provenance, RiskLevel, Transport,
};

use crate::approve::{ApprovalContext, ApprovalOutcome, Approver, Decision};

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
    /// Phone -> daemon replay guard.
    guard: Mutex<ReplayGuard>,
    timeout: Duration,
    machine: String,
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
        }
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
            risk: RiskLevel::Routine,
            reason: None,
            expires_at: now + timeout_ms,
            timeout_ms,
        }
    }

    /// The whole round trip, or `None` (fail closed) at the first misstep.
    fn round_trip(&self, ctx: &ApprovalContext) -> Option<ApprovalOutcome> {
        let req = self.build_request(ctx);

        // Seal and send the request to the phone.
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let env = Envelope::seal(
            &req,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.phone,
        )
        .ok()?;
        self.transport
            .send(self.pairing_id, Direction::ToPhone, &env)
            .ok()?;

        // Await the sealed response.
        let resp_env = self
            .transport
            .recv(self.pairing_id, Direction::ToDaemon, self.timeout)
            .ok()??;
        let resp: ApprovalResponse = {
            let mut guard = self.guard.lock().expect("remote guard poisoned");
            resp_env
                .open(&self.phone, &self.identity.agreement, &mut guard)
                .ok()?
        };

        // Correlate: a response for a different request is not ours.
        if resp.request_id != req.request_id {
            return None;
        }

        match resp.decision {
            ProtoDecision::Denied => Some(ApprovalOutcome::local(Decision::Deny)),
            ProtoDecision::Approved => {
                // An approve MUST carry the DEK; without it we cannot serve the
                // token, so fail closed rather than approving emptily.
                let dek = resp.dek()?;
                let dek = Zeroizing::new(*dek.as_bytes());
                let decision = match &resp.lease {
                    Some(lease) => Decision::Lease(Duration::from_millis(lease.ttl_ms)),
                    None => Decision::Approve,
                };
                Some(ApprovalOutcome::with_dek(decision, dek))
            }
        }
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
    use latch_proto::{RequestKind, SecretRef};

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
            ssh: None,
        };
        let req = approver.build_request(&ctx);
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.kind, RequestKind::SecretRead);
        assert_eq!(req.command, ctx.command);
        assert_eq!(req.secrets, ctx.secret_refs);
        assert_eq!(req.provenance.process_chain, vec!["zsh", "op"]);
    }
}
