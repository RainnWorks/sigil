//! The softphone: a programmable, headless reference approver that speaks the
//! phone side of the Latch protocol.
//!
//! It exists to drive the full remote-approval loop with no device and no
//! network relay, so the daemon's end-to-end behaviour can be tested headlessly
//! and a human can exercise the protocol from a terminal. It does exactly what
//! the iOS approver does, minus the UI and the Secure Enclave:
//!
//! 1. **Pair.** [`Pairing::scan`] consumes a QR [`PairingPayload`], mints the
//!    phone identity, pins the daemon, and produces the [`PairingResponse`]. The
//!    human (or test) confirms the SAS words and feeds the daemon's sealed DEK
//!    envelope to [`Pairing::receive_dek`], yielding a [`Softphone`] that holds
//!    the DEK.
//! 2. **Approve.** Given a sealed [`ApprovalRequest`], the [`Softphone`] verifies
//!    and opens it, applies a scriptable [`Policy`], and seals an
//!    [`ApprovalResponse`] back. On approve the response carries the DEK the
//!    daemon needs to decrypt the one token for this request; on deny it carries
//!    nothing, so a denial can never release a secret.
//!
//! The DEK never leaves the softphone except, per approval, sealed inside an
//! envelope to the daemon's pinned key. This mirrors the product invariant: the
//! phone holds the key and releases it one request at a time.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use latch_proto::envelope::Envelope;
use latch_proto::identity::DeviceIdentity;
use latch_proto::pairing::{Dek, PairingResponse};
use latch_proto::{
    mailbox_id, now_ms, ApprovalRequest, ApprovalResponse, Direction, HandshakeError, InstallLease,
    OpenError, PairingError, PairingPayload, PeerIdentity, PhonePairing, ReplayGuard, SealError,
    Transport, TransportError,
};

#[derive(thiserror::Error, Debug)]
pub enum SoftphoneError {
    #[error("pairing payload: {0}")]
    Pairing(#[from] PairingError),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("opening request envelope: {0}")]
    Open(#[from] OpenError),
    #[error("sealing response envelope: {0}")]
    Seal(#[from] SealError),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
}

/// What a policy decides for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Approve,
    /// Approve and ask the daemon to install a session lease of this length.
    ApproveWithLease(Duration),
    Deny,
}

/// A scriptable approval policy. `Rule` runs arbitrary logic over the request
/// (e.g. deny anything touching a production vault), so tests and a human can
/// program the approver without touching its wiring.
#[derive(Clone)]
pub enum Policy {
    Approve,
    Deny,
    Lease(Duration),
    Rule(std::sync::Arc<dyn Fn(&ApprovalRequest) -> PolicyDecision + Send + Sync>),
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Policy::Approve => f.write_str("Policy::Approve"),
            Policy::Deny => f.write_str("Policy::Deny"),
            Policy::Lease(d) => write!(f, "Policy::Lease({d:?})"),
            Policy::Rule(_) => f.write_str("Policy::Rule(<fn>)"),
        }
    }
}

impl Policy {
    /// Build a rule policy from a closure.
    pub fn rule(f: impl Fn(&ApprovalRequest) -> PolicyDecision + Send + Sync + 'static) -> Self {
        Policy::Rule(std::sync::Arc::new(f))
    }

    fn decide(&self, req: &ApprovalRequest) -> PolicyDecision {
        match self {
            Policy::Approve => PolicyDecision::Approve,
            Policy::Deny => PolicyDecision::Deny,
            Policy::Lease(ttl) => PolicyDecision::ApproveWithLease(*ttl),
            Policy::Rule(f) => f(req),
        }
    }
}

/// Clone a device identity (its inner keys are `Clone`, but `DeviceIdentity`
/// itself is not, so we rebuild it). Used to keep the phone's identity after the
/// pairing driver consumes a copy.
fn clone_identity(id: &DeviceIdentity) -> DeviceIdentity {
    DeviceIdentity {
        signing: id.signing.clone(),
        agreement: id.agreement.clone(),
    }
}

/// A pairing in progress: the phone has scanned the QR and produced its
/// response, and is waiting for SAS confirmation and the DEK delivery.
pub struct Pairing {
    phone: PhonePairing,
    identity: DeviceIdentity,
    policy: Policy,
}

impl Pairing {
    /// Scan a base64url QR string, pin the daemon, and produce the response the
    /// daemon must verify. The `identity` is the phone's freshly minted device
    /// identity; a clone is retained for the resulting [`Softphone`].
    pub fn scan(
        identity: DeviceIdentity,
        qr: &str,
        now: u64,
        policy: Policy,
    ) -> Result<(Self, PairingResponse), SoftphoneError> {
        let payload = PairingPayload::from_qr_string(qr)?;
        Self::scan_payload(identity, payload, now, policy)
    }

    /// As [`scan`](Self::scan) but from an already-decoded payload (tests that
    /// hand the payload across in-process).
    pub fn scan_payload(
        identity: DeviceIdentity,
        payload: PairingPayload,
        now: u64,
        policy: Policy,
    ) -> Result<(Self, PairingResponse), SoftphoneError> {
        let retained = clone_identity(&identity);
        let mut phone = PhonePairing::scan(identity, payload, now)?;
        let response = phone.respond()?;
        Ok((
            Self {
                phone,
                identity: retained,
                policy,
            },
            response,
        ))
    }

    /// The six SAS words to compare against the daemon's screen.
    pub fn sas_words(&self) -> [&'static str; 6] {
        self.phone.sas_words()
    }

    /// Record that the human confirmed the SAS matched. Required before the DEK
    /// can be received (the proto state machine enforces it).
    pub fn confirm(&mut self) -> Result<(), SoftphoneError> {
        self.phone.confirm()?;
        Ok(())
    }

    /// Open the daemon's sealed DEK envelope and finish pairing.
    pub fn receive_dek(mut self, env: &Envelope) -> Result<Softphone, SoftphoneError> {
        let mut guard = ReplayGuard::new();
        let dek = self.phone.receive_dek(env, &mut guard)?;
        let daemon = self.phone.daemon();
        let phone_pub = self.phone.phone_identity();
        let pairing_id = mailbox_id(&daemon, &phone_pub);
        Ok(Softphone {
            identity: self.identity,
            daemon,
            pairing_id,
            dek,
            policy: self.policy,
            outbound_counter: AtomicU64::new(0),
            inbound_guard: Mutex::new(ReplayGuard::new()),
        })
    }
}

/// A paired softphone: holds the DEK and answers sealed approval requests.
pub struct Softphone {
    identity: DeviceIdentity,
    daemon: PeerIdentity,
    pairing_id: [u8; 32],
    dek: Dek,
    policy: Policy,
    /// phone -> daemon envelope counter (monotonic).
    outbound_counter: AtomicU64,
    /// daemon -> phone replay guard.
    inbound_guard: Mutex<ReplayGuard>,
}

impl Softphone {
    /// The mailbox (pairing) id both parties route on.
    pub fn mailbox(&self) -> [u8; 32] {
        self.pairing_id
    }

    /// The pinned daemon identity (the recipient the phone seals responses to
    /// and the sender it verifies requests from).
    pub fn daemon(&self) -> PeerIdentity {
        self.daemon
    }

    /// This phone's own public identity, which the daemon pins and uses to
    /// verify the phone's response signatures.
    pub fn phone_identity(&self) -> PeerIdentity {
        self.identity.peer_identity()
    }

    /// Replace the active policy.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// Verify, replay-check, and decrypt a sealed request envelope.
    pub fn open_request(&self, env: &Envelope) -> Result<ApprovalRequest, SoftphoneError> {
        let mut guard = self.inbound_guard.lock().expect("inbound guard poisoned");
        Ok(env.open(&self.daemon, &self.identity.agreement, &mut guard)?)
    }

    /// Decide `req` under the active policy and seal the response envelope. On
    /// approve the response carries the DEK; on deny it does not.
    pub fn respond(
        &self,
        req: &ApprovalRequest,
        now: u64,
    ) -> Result<(Envelope, PolicyDecision), SoftphoneError> {
        let decision = self.policy.decide(req);
        let resp = match decision {
            PolicyDecision::Deny => ApprovalResponse::deny(&req.request_id, now),
            PolicyDecision::Approve => ApprovalResponse::approve(&req.request_id, &self.dek, now),
            PolicyDecision::ApproveWithLease(ttl) => {
                ApprovalResponse::approve(&req.request_id, &self.dek, now).with_lease(
                    InstallLease {
                        // The daemon derives and trusts its own grant key; this field
                        // is echoed for display only.
                        grant_key: String::new(),
                        ttl_ms: ttl.as_millis() as u64,
                    },
                )
            }
        };
        let counter = self.outbound_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let env = Envelope::seal(
            &resp,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.daemon,
        )?;
        Ok((env, decision))
    }

    /// One full turn over a transport: receive the next request for our mailbox,
    /// decide it, and send the sealed response. Returns the request handled and
    /// the decision, or `None` if nothing arrived within `timeout`.
    pub fn serve_once(
        &self,
        transport: &dyn Transport,
        timeout: Duration,
    ) -> Result<Option<(ApprovalRequest, PolicyDecision)>, SoftphoneError> {
        let Some(env) = transport.recv(self.pairing_id, Direction::ToPhone, timeout)? else {
            return Ok(None);
        };
        let req = self.open_request(&env)?;
        let (resp_env, decision) = self.respond(&req, now_ms())?;
        transport.send(self.pairing_id, Direction::ToDaemon, &resp_env)?;
        Ok(Some((req, decision)))
    }

    /// Serve requests until `shutdown` is set, polling in `tick` slices. This is
    /// the loop the CLI runs to act as a live approver against a transport.
    pub fn serve(&self, transport: &dyn Transport, shutdown: &AtomicBool, tick: Duration) {
        while !shutdown.load(Ordering::SeqCst) {
            match self.serve_once(transport, tick) {
                Ok(_) => {}
                // A single malformed or unverifiable envelope must not take the
                // loop down; fail closed on that one and keep serving.
                Err(e) => eprintln!("softphone: dropped an envelope: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latch_proto::pairing::DaemonPairing;
    use latch_proto::{LocalRelay, RequestKind};

    const NOW: u64 = 1_720_000_000_000;

    fn endpoints() -> Vec<String> {
        vec!["lan://latch.local:4823".to_string()]
    }

    /// Run the pairing ceremony in-process and return a paired softphone plus
    /// the daemon driver (still holding what it needs to seal requests).
    fn paired(policy: Policy) -> (DaemonPairing, DeviceIdentity, Softphone, Dek) {
        let daemon_id = DeviceIdentity::generate();
        let daemon_id_retained = clone_identity(&daemon_id);
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);

        let phone_id = DeviceIdentity::generate();
        let (mut pairing, resp) =
            Pairing::scan_payload(phone_id, payload, NOW + 1_000, policy).unwrap();

        daemon.receive_response(&resp, NOW + 2_000).unwrap();
        assert_eq!(daemon.sas_words().unwrap(), pairing.sas_words());
        daemon.confirm().unwrap();
        pairing.confirm().unwrap();

        let dek = Dek::generate();
        let dek_copy = Dek::from_bytes(*dek.as_bytes());
        let env = daemon.deliver_dek(&dek, 1).unwrap();
        let phone = pairing.receive_dek(&env).unwrap();
        (daemon, daemon_id_retained, phone, dek_copy)
    }

    fn sample_request(id: &str) -> ApprovalRequest {
        use latch_proto::{Provenance, RiskLevel, SecretRef};
        ApprovalRequest {
            request_id: id.to_string(),
            kind: RequestKind::OpRead,
            account_label: "Rowm".into(),
            secret: Some(SecretRef {
                account: "Rowm".into(),
                vault: "Engineering".into(),
                item: ".env".into(),
                field: "password".into(),
            }),
            ssh: None,
            provenance: Provenance {
                process_chain: vec!["zsh".into(), "op".into()],
                cwd: "/p".into(),
                machine: "mac".into(),
                requested_at: NOW,
            },
            risk: RiskLevel::Routine,
            reason: None,
            expires_at: NOW + 90_000,
            timeout_ms: 90_000,
        }
    }

    #[test]
    fn approve_policy_returns_the_dek_over_the_transport() {
        let (daemon_driver, daemon_id, phone, dek) = paired(Policy::Approve);
        let _ = daemon_driver;
        let relay = LocalRelay::new();
        let mailbox = phone.mailbox();

        // Daemon seals a request and drops it in the phone's inbox.
        let req = sample_request("req-1");
        let env = Envelope::seal(&req, mailbox, 2, &daemon_id.signing, &phone_peer(&phone))
            .expect("seal request");
        relay.send(mailbox, Direction::ToPhone, &env).unwrap();

        // Phone serves one turn.
        let (handled, decision) = phone
            .serve_once(&relay, Duration::from_millis(100))
            .unwrap()
            .unwrap();
        assert_eq!(handled.request_id, "req-1");
        assert_eq!(decision, PolicyDecision::Approve);

        // Daemon reads the response and recovers the DEK.
        let resp_env = relay
            .recv(mailbox, Direction::ToDaemon, Duration::from_millis(100))
            .unwrap()
            .unwrap();
        let mut guard = ReplayGuard::new();
        let resp: ApprovalResponse = resp_env
            .open(&phone_peer(&phone), &daemon_id.agreement, &mut guard)
            .unwrap();
        assert_eq!(resp.decision, latch_proto::Decision::Approved);
        assert_eq!(resp.dek().unwrap().as_bytes(), dek.as_bytes());
    }

    #[test]
    fn deny_policy_carries_no_dek() {
        let (_d, daemon_id, phone, _dek) = paired(Policy::Deny);
        let mailbox = phone.mailbox();
        let req = sample_request("req-deny");
        let env =
            Envelope::seal(&req, mailbox, 2, &daemon_id.signing, &phone_peer(&phone)).unwrap();
        let got = phone.open_request(&env).unwrap();
        let (resp_env, decision) = phone.respond(&got, NOW).unwrap();
        assert_eq!(decision, PolicyDecision::Deny);
        let mut guard = ReplayGuard::new();
        let resp: ApprovalResponse = resp_env
            .open(&phone_peer(&phone), &daemon_id.agreement, &mut guard)
            .unwrap();
        assert_eq!(resp.decision, latch_proto::Decision::Denied);
        assert!(resp.dek().is_none());
    }

    #[test]
    fn rule_policy_denies_production_and_approves_others() {
        let policy = Policy::rule(|req| {
            let prod = req
                .secret
                .as_ref()
                .map(|s| s.vault.contains("Production"))
                .unwrap_or(false);
            if prod {
                PolicyDecision::Deny
            } else {
                PolicyDecision::Approve
            }
        });
        let (_d, _id, phone, _dek) = paired(policy);

        let mut prod = sample_request("prod");
        prod.secret.as_mut().unwrap().vault = "Production".into();
        assert_eq!(phone.policy.decide(&prod), PolicyDecision::Deny);

        let dev = sample_request("dev");
        assert_eq!(phone.policy.decide(&dev), PolicyDecision::Approve);
    }

    /// The phone's pinned public identity (recomputed from its retained secret).
    fn phone_peer(phone: &Softphone) -> PeerIdentity {
        phone.identity.peer_identity()
    }
}
