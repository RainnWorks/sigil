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
    PeerIdentity, Provenance, RequestKind, RiskLevel, SecretRef, Transport,
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

    /// Build the request from the daemon-verified context.
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
            kind: classify(&ctx.scope),
            account_label: ctx.account.clone(),
            secret: parse_secret_ref(&ctx.scope, &ctx.account),
            ssh: None,
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

/// Classify an op scope into a [`RequestKind`]. Best-effort from the verb.
fn classify(scope: &str) -> RequestKind {
    let s = scope.trim_start();
    if s.starts_with("item get") || s.starts_with("item ") {
        RequestKind::OpItemGet
    } else {
        // `read`, and anything else op-shaped, maps to a single-field read.
        RequestKind::OpRead
    }
}

/// Pull the `op://…` reference out of a scope into a [`SecretRef`] for display.
///
/// 1Password references are `op://<vault>/<item>/<field>` (optionally
/// `op://<account>/<vault>/<item>[/<section>]/<field>`). We parse loosely from
/// the right and fall back to the routed account label; this is display metadata
/// only (the token is never in scope here), so a partial parse is acceptable.
fn parse_secret_ref(scope: &str, account: &str) -> Option<SecretRef> {
    let start = scope.find("op://")?;
    let rest = &scope[start + "op://".len()..];
    // Stop at whitespace: the reference is one argv token.
    let reference = rest.split_whitespace().next().unwrap_or(rest);
    let parts: Vec<&str> = reference.split('/').filter(|p| !p.is_empty()).collect();
    let n = parts.len();
    let (account, vault, item, field) = match n {
        0 | 1 => return None,
        2 => (
            account.to_string(),
            parts[0].into(),
            parts[1].into(),
            String::new(),
        ),
        3 => (
            account.to_string(),
            parts[0].into(),
            parts[1].into(),
            parts[2].into(),
        ),
        // op://account/vault/item[/section]/field: account first, field last.
        _ => (
            parts[0].into(),
            parts[1].into(),
            parts[2].into(),
            parts[n - 1].into(),
        ),
    };
    Some(SecretRef {
        account,
        vault,
        item,
        field,
    })
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

    #[test]
    fn classify_reads_the_verb() {
        assert_eq!(
            classify("read op://Engineering/.env/pw"),
            RequestKind::OpRead
        );
        assert_eq!(
            classify("item get .env --vault Engineering"),
            RequestKind::OpItemGet
        );
    }

    #[test]
    fn parse_three_part_reference() {
        let r = parse_secret_ref("read op://Engineering/.env/password", "Rowm").unwrap();
        assert_eq!(r.account, "Rowm");
        assert_eq!(r.vault, "Engineering");
        assert_eq!(r.item, ".env");
        assert_eq!(r.field, "password");
    }

    #[test]
    fn parse_two_part_reference_has_empty_field() {
        let r = parse_secret_ref("read op://Engineering/.env", "Rowm").unwrap();
        assert_eq!(r.vault, "Engineering");
        assert_eq!(r.item, ".env");
        assert_eq!(r.field, "");
    }

    #[test]
    fn no_reference_is_none() {
        assert!(parse_secret_ref("vault list", "Rowm").is_none());
    }
}
