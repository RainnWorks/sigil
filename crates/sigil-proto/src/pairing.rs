//! The payload a Mac renders into a pairing QR code and a phone scans.
//!
//! It carries the daemon's public identity (so the phone can pin it), the
//! endpoints to reach the daemon on, a one-time pairing secret, and a
//! creation timestamp. The private halves never leave the daemon's keystore;
//! only the public identity travels here. The whole payload is serialised to
//! JSON and base64url-encoded so it fits a QR with no padding characters to
//! confuse scanners.

use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::{Blake2b512, Blake2bMac, Digest};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::fingerprint::fingerprint_words;
use crate::identity::{DeviceIdentity, PeerIdentity};

/// A one-time secret proving the QR was scanned in person, consumed at pairing.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret(pub [u8; 32]);

impl PairingSecret {
    /// Fresh secret from the platform CSPRNG.
    pub fn generate() -> Self {
        use rand_core::RngCore;
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Never leak secret bytes through Debug.
impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

/// Everything the phone needs to pin the daemon and open a channel to it.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairingPayload {
    /// The daemon's pinned public identity.
    pub daemon: PeerIdentity,
    /// Ordered endpoints to try: `lan://…`, `https://ddns…`, relay mailbox, etc.
    pub endpoints: Vec<String>,
    /// One-time pairing secret, consumed on first contact.
    pub secret: PairingSecret,
    /// Daemon wall clock at mint, unix ms; the phone rejects stale QRs.
    pub created_at: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum PairingError {
    #[error("pairing payload serialization failed")]
    Serialize,
    #[error("pairing payload is not valid base64url")]
    Base64,
    #[error("pairing payload deserialization failed")]
    Deserialize,
}

impl PairingPayload {
    /// Encode as the compact base64url string embedded in the QR.
    pub fn to_qr_string(&self) -> Result<String, PairingError> {
        let json = serde_json::to_vec(self).map_err(|_| PairingError::Serialize)?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }

    /// Decode a scanned QR string back into a payload.
    pub fn from_qr_string(s: &str) -> Result<Self, PairingError> {
        let json = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| PairingError::Base64)?;
        serde_json::from_slice(&json).map_err(|_| PairingError::Deserialize)
    }
}

// ===========================================================================
// The pairing handshake.
//
// The ceremony has one deliberate asymmetry. Message 0 (the `PairingPayload`
// above) travels Mac -> phone *optically*, through a QR code the human points a
// camera at. That channel is authenticated by physics: no network attacker sits
// between a screen and a lens, so the phone learns the daemon's real public
// keys with certainty and pins them.
//
// The return leg (`PairingResponse`, phone -> Mac) travels over the network,
// which we assume is fully hostile (see `tests/hostile_relay.rs`). Nothing
// physical protects it, so it must be authenticated cryptographically. The only
// shared secret established by the optical channel is the 256-bit
// `PairingSecret` inside the QR. The phone proves possession of that secret by
// MACing a transcript that binds the QR contents *and* its own freshly minted
// identity. A network man-in-the-middle who swaps the phone's keys cannot
// recompute the MAC (it lacks the secret), so key substitution on the return
// channel is detected and rejected. That is the whole game: the optical
// channel bootstraps a secret, and the secret closes the return channel.
//
// SAS (the six-word `fingerprint_words` over both pinned identities) is the
// human backstop: even if the secret leaked, both humans reading the same six
// words confirms both devices pinned the same key pair.
// ===========================================================================

/// Domain separation for everything the pairing handshake hashes or MACs.
const PAIRING_DOMAIN: &[u8] = b"sigil.pairing.v1";
/// Domain for the pairing rendezvous mailbox (message 1 and 3 transport).
const RENDEZVOUS_DOMAIN: &[u8] = b"sigil.pairing.rendezvous.v1";
/// Label deriving the confirmation-MAC subkey from the pairing secret. Distinct
/// label => distinct key => no key reuse across purposes.
const SUBKEY_CONFIRM_LABEL: &[u8] = b"confirm-tag";

/// Default lifetime of a pairing secret / QR, in milliseconds (600s). After
/// this the daemon refuses any response and the human re-mints the QR. Must
/// match the CLI's pairing wait (`response_timeout` in `cli.rs`'s
/// `run_pairing`/`run_pairing_json`, also 600s) or the QR looks alive on
/// screen for longer than the secret backing it actually is.
pub const PAIRING_SECRET_TTL_MS: u64 = 600_000;

/// A 32-byte keyed BLAKE2b, used both as the KDF and as the MAC.
///
/// Crypto choice, justified: this crate already depends on `blake2` (the
/// fingerprint and mailbox ids are BLAKE2b). BLAKE2b has a first-class keyed
/// mode that is a PRF, so it serves as both HKDF-Expand and HMAC without
/// pulling in `sha2` + `hkdf` + `hmac`. We skip HKDF-Extract deliberately: the
/// input keying material is a 256-bit CSPRNG output, already uniform, and
/// RFC 5869 s3.3 says extraction is unnecessary when the IKM is already a good
/// key. So `derive_subkey` is exactly HKDF-Expand with a one-block `info`.
type Mac32 = Blake2bMac<U32>;

/// Derive a purpose-specific 32-byte subkey from the pairing secret.
/// `K_purpose = BLAKE2bMac(key = secret, msg = domain || label)`.
fn derive_subkey(secret: &PairingSecret, label: &[u8]) -> [u8; 32] {
    let mut mac = <Mac32 as Mac>::new_from_slice(secret.as_bytes())
        .expect("32-byte pairing secret is a valid BLAKE2b key");
    mac.update(PAIRING_DOMAIN);
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// Length-prefix `field` into `hasher` so no two distinct field sequences can
/// share a transcript (the same trick the envelope's `canonical_bytes` uses).
fn absorb(hasher: &mut Blake2b512, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// The transcript both sides bind the confirmation MAC to.
///
/// It commits to every field of the QR payload *except the secret* (the secret
/// is the MAC key, not part of the signed message) plus the phone's identity
/// and a fresh nonce. Binding the daemon identity stops a response being
/// replayed against a different pairing; binding the phone identity stops a
/// network attacker swapping the phone key; the nonce makes each response
/// unique. The result is a public value safe to hand a reviewer: it reveals
/// nothing about the secret.
fn pairing_transcript(
    daemon: &PeerIdentity,
    endpoints: &[String],
    created_at: u64,
    phone: &PeerIdentity,
    nonce: &[u8; 32],
    se_share_pub: Option<&str>,
) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(PAIRING_DOMAIN);
    absorb(&mut h, &daemon.verifying);
    absorb(&mut h, &daemon.agreement);
    h.update((endpoints.len() as u64).to_be_bytes());
    for e in endpoints {
        absorb(&mut h, e.as_bytes());
    }
    h.update(created_at.to_be_bytes());
    absorb(&mut h, &phone.verifying);
    absorb(&mut h, &phone.agreement);
    absorb(&mut h, nonce);
    // v2: bind the phone's Secure-Enclave threshold share `F` into the same MAC
    // that pins the phone's identity, so a relay can neither substitute nor strip
    // it without breaking the tag (it lacks the pairing secret). Absorbed ONLY
    // when present, so a v1 response (no share) hashes byte-identically to before.
    // The base64 string is bound verbatim; on-curve validation happens at pin.
    if let Some(share) = se_share_pub {
        absorb(&mut h, share.as_bytes());
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// The bootstrap mailbox both parties route the pairing messages on, before the
/// phone's key is pinned and the steady-state [`mailbox_id`](crate::mailbox_id)
/// can be computed.
///
/// It is derived from the daemon's pinned identity and the one-time pairing
/// secret, both carried in the QR, so only a party holding the scanned QR can
/// compute it. The relay sees an opaque 32-byte id and learns nothing about the
/// pairing. It is distinct from the steady-state mailbox (different domain), so
/// pairing traffic and approval traffic never share a queue.
pub fn rendezvous_mailbox(daemon: &PeerIdentity, secret: &PairingSecret) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(RENDEZVOUS_DOMAIN);
    absorb(&mut h, &daemon.verifying);
    absorb(&mut h, &daemon.agreement);
    absorb(&mut h, secret.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// `tag = BLAKE2bMac(key = K_confirm, msg = transcript)`.
fn confirmation_tag(k_confirm: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <Mac32 as Mac>::new_from_slice(k_confirm).expect("32-byte subkey is a valid BLAKE2b key");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// Compute the confirmation transcript and tag for FIXED inputs, including a
/// caller-supplied `nonce` (production always mints a fresh CSPRNG one via
/// [`PairingResponse::create`]/[`PairingResponse::create_with_share`], so this
/// path is never used for a real pairing). Exists solely so `export-vectors`
/// (and the phone's TS mirror, `pairingTranscript`/`deriveSubkey`/
/// `confirmationTag` in `pairing-handshake.ts`) can pin this exact
/// construction byte-for-byte across languages: fixed inputs in, the same
/// transcript and tag out, every time, on both sides. This is the piece that
/// was NOT locked when the `seSharePub`/`se_share_pub` camelCase wire mismatch
/// shipped -- the daemon and phone each computed a transcript the other could
/// not reproduce, and nothing caught it before a real device did.
///
/// Returns `(transcript, tag)`.
pub fn pairing_confirmation_vector(
    secret: &PairingSecret,
    daemon: &PeerIdentity,
    endpoints: &[String],
    created_at: u64,
    phone: &PeerIdentity,
    nonce: &[u8; 32],
    se_share_pub: Option<&str>,
) -> ([u8; 32], [u8; 32]) {
    let k_confirm = derive_subkey(secret, SUBKEY_CONFIRM_LABEL);
    let transcript = pairing_transcript(daemon, endpoints, created_at, phone, nonce, se_share_pub);
    let tag = confirmation_tag(&k_confirm, &transcript);
    (transcript, tag)
}

/// Decode and on-curve-validate a phone threshold share `F` (standard base64 of
/// the 65-byte ANSI X9.63 uncompressed P-256 point). Rejects wrong lengths and
/// off-curve/twist points via the shared [`crate::threshold::P256Point`]
/// validator (the same one the daemon uses at account-add), so an invalid `F`
/// never gets pinned. Returns the canonical 65-byte encoding.
fn validate_se_share(b64: &str) -> Result<[u8; 65], HandshakeError> {
    let bytes = B64_STD
        .decode(b64)
        .map_err(|_| HandshakeError::BadThresholdShare)?;
    let point = crate::threshold::P256Point::from_x963(&bytes)
        .map_err(|_| HandshakeError::BadThresholdShare)?;
    Ok(*point.as_x963())
}

/// Constant-time verification of a confirmation tag. `Mac::verify_slice`
/// compares in constant time, so a wrong tag leaks no timing signal about how
/// many leading bytes matched.
fn verify_confirmation_tag(k_confirm: &[u8; 32], transcript: &[u8; 32], tag: &[u8; 32]) -> bool {
    let mut mac =
        <Mac32 as Mac>::new_from_slice(k_confirm).expect("32-byte subkey is a valid BLAKE2b key");
    mac.update(transcript);
    mac.verify_slice(tag).is_ok()
}

/// The phone's authenticated reply to a scanned QR (message 1, phone -> Mac).
///
/// Carries the phone's freshly minted public identity and a MAC proving the
/// sender held the pairing secret and is binding *this* identity to *this* QR.
/// The `nonce` makes the reply one-shot and unique.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PairingResponse {
    /// The phone's public identity, to be pinned by the daemon.
    pub phone: PeerIdentity,
    /// Fresh per-response nonce, bound into the transcript.
    pub nonce: [u8; 32],
    /// BLAKE2b-keyed confirmation tag over the transcript.
    pub tag: [u8; 32],
    /// The phone's v2 threshold share `F = f·G`, ANSI X9.63 uncompressed (65
    /// bytes), **standard base64**. Present only for a v2 pairing; a v1 phone
    /// omits it (`#[serde(default)]`, so old responses still parse). Bound into
    /// the confirmation [`tag`](Self::tag), so a relay cannot swap or strip it,
    /// and validated on-curve by the daemon when it pins it (see
    /// [`DaemonPairing::receive_response`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub se_share_pub: Option<String>,
}

impl PairingResponse {
    /// Build a response from decomposed QR fields plus the phone identity, and an
    /// optional v2 threshold share `F` (standard base64 x963) to pin.
    fn build(
        daemon: &PeerIdentity,
        endpoints: &[String],
        created_at: u64,
        phone: &PeerIdentity,
        secret: &PairingSecret,
        se_share_pub: Option<&str>,
    ) -> Self {
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let k_confirm = derive_subkey(secret, SUBKEY_CONFIRM_LABEL);
        let transcript =
            pairing_transcript(daemon, endpoints, created_at, phone, &nonce, se_share_pub);
        let tag = confirmation_tag(&k_confirm, &transcript);
        Self {
            phone: *phone,
            nonce,
            tag,
            se_share_pub: se_share_pub.map(str::to_string),
        }
    }

    /// Phone side (v1): build the authenticated response to a scanned `payload`,
    /// carrying no threshold share.
    pub fn create(payload: &PairingPayload, phone: &PeerIdentity) -> Self {
        Self::build(
            &payload.daemon,
            &payload.endpoints,
            payload.created_at,
            phone,
            &payload.secret,
            None,
        )
    }

    /// Phone side (v2): build the authenticated response and pin the phone's
    /// Secure-Enclave threshold share `F` (`se_share_pub`, standard base64 of the
    /// 65-byte ANSI X9.63 public point). `F` is bound into the confirmation tag.
    pub fn create_with_share(
        payload: &PairingPayload,
        phone: &PeerIdentity,
        se_share_pub: &str,
    ) -> Self {
        Self::build(
            &payload.daemon,
            &payload.endpoints,
            payload.created_at,
            phone,
            &payload.secret,
            Some(se_share_pub),
        )
    }

    /// Daemon side: verify the tag against the daemon's own view of the QR it
    /// minted. Returns `true` only if the sender held the secret and bound
    /// exactly `self.phone` (and any `self.se_share_pub`) to exactly this pairing.
    pub fn verify(
        &self,
        daemon: &PeerIdentity,
        endpoints: &[String],
        created_at: u64,
        secret: &PairingSecret,
    ) -> bool {
        let k_confirm = derive_subkey(secret, SUBKEY_CONFIRM_LABEL);
        let transcript = pairing_transcript(
            daemon,
            endpoints,
            created_at,
            &self.phone,
            &self.nonce,
            self.se_share_pub.as_deref(),
        );
        verify_confirmation_tag(&k_confirm, &transcript, &self.tag)
    }
}

/// The step both peers have reached in the ceremony. The two driver types
/// (`DaemonPairing`, `PhonePairing`) share this vocabulary; each enforces its
/// own legal transitions.
///
/// The ceremony pins keys (and, for v2, the phone's threshold share `F`); it
/// carries no secret handoff of its own. At-rest secrets are threshold-sealed
/// and opened per-request with the phone's partial, so there is no key to
/// deliver at pairing.
///
/// ```text
/// daemon:  Init ------------> ResponseReceived --> Confirmed
/// phone:   Scanned ---------> (respond sent) ----> Confirmed
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairingState {
    /// Daemon: QR minted, waiting for a response.
    Init,
    /// Phone: QR scanned, identity pinned, ready to respond.
    Scanned,
    /// Daemon: a valid response arrived; the phone key is now pinned.
    ResponseReceived,
    /// Both: the six-word SAS matched on both screens. Terminal.
    Confirmed,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("illegal transition: expected state {expected:?}, was {actual:?}")]
    WrongState {
        expected: PairingState,
        actual: PairingState,
    },
    #[error("pairing secret expired: age {age_ms}ms exceeds limit {limit_ms}ms")]
    SecretExpired { age_ms: u64, limit_ms: u64 },
    #[error("pairing secret already consumed by an accepted response")]
    SecretConsumed,
    #[error("confirmation tag did not verify: wrong secret or substituted phone key")]
    BadTag,
    #[error("the phone's v2 threshold share F is malformed or off-curve")]
    BadThresholdShare,
    #[error("SAS mismatch: the two devices did not pin the same keys")]
    SasMismatch,
}

/// Daemon-side driver for the handshake. Owns the daemon's private identity, the
/// pairing secret, and the pinned phone key once known.
pub struct DaemonPairing {
    state: PairingState,
    daemon_pub: PeerIdentity,
    endpoints: Vec<String>,
    secret: PairingSecret,
    created_at: u64,
    secret_ttl_ms: u64,
    consumed: bool,
    phone: Option<PeerIdentity>,
    /// The phone's v2 threshold share `F` (ANSI X9.63, 65 bytes), pinned from an
    /// accepted response after on-curve validation. `None` for a v1 pairing.
    phone_se_share: Option<[u8; 65]>,
}

impl DaemonPairing {
    /// Mint a fresh pairing: generate the one-time secret, build the QR payload,
    /// and enter [`PairingState::Init`]. `now` is unix ms at mint time.
    pub fn mint(
        identity: DeviceIdentity,
        endpoints: Vec<String>,
        now: u64,
    ) -> (Self, PairingPayload) {
        let secret = PairingSecret::generate();
        let daemon_pub = identity.peer_identity();
        let payload = PairingPayload {
            daemon: daemon_pub,
            endpoints: endpoints.clone(),
            secret: secret.clone(),
            created_at: now,
        };
        let driver = Self {
            state: PairingState::Init,
            daemon_pub,
            endpoints,
            secret,
            created_at: now,
            secret_ttl_ms: PAIRING_SECRET_TTL_MS,
            consumed: false,
            phone: None,
            phone_se_share: None,
        };
        (driver, payload)
    }

    /// Override the default secret lifetime (mainly for expiry tests).
    pub fn with_secret_ttl(mut self, ttl_ms: u64) -> Self {
        self.secret_ttl_ms = ttl_ms;
        self
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn phone(&self) -> Option<PeerIdentity> {
        self.phone
    }

    /// Consume a phone response: enforce one-time use, freshness, and the tag.
    ///
    /// Order is load-bearing. The consumed check is first so a second accepted
    /// response is refused as [`HandshakeError::SecretConsumed`] rather than
    /// slipping through. Expiry is checked before the MAC. Only a
    /// cryptographically valid response burns the secret, so a network attacker
    /// spraying garbage responses cannot exhaust it. On success the phone key is
    /// pinned and the state advances to `ResponseReceived`.
    pub fn receive_response(
        &mut self,
        resp: &PairingResponse,
        now: u64,
    ) -> Result<PeerIdentity, HandshakeError> {
        if self.consumed {
            return Err(HandshakeError::SecretConsumed);
        }
        self.expect(PairingState::Init)?;
        let age = now.saturating_sub(self.created_at);
        if age > self.secret_ttl_ms {
            return Err(HandshakeError::SecretExpired {
                age_ms: age,
                limit_ms: self.secret_ttl_ms,
            });
        }
        if !resp.verify(
            &self.daemon_pub,
            &self.endpoints,
            self.created_at,
            &self.secret,
        ) {
            return Err(HandshakeError::BadTag);
        }
        // v2: the response may pin the phone's threshold share F. The tag already
        // proved it was not swapped/stripped (F is bound into the transcript);
        // now validate it decodes to an on-curve P-256 point before pinning it
        // (lesser R2). A malformed share fails the whole response closed.
        let phone_se_share = match &resp.se_share_pub {
            Some(b64) => Some(validate_se_share(b64)?),
            None => None,
        };
        self.consumed = true;
        self.phone = Some(resp.phone);
        self.phone_se_share = phone_se_share;
        self.state = PairingState::ResponseReceived;
        Ok(resp.phone)
    }

    /// The phone's pinned v2 threshold share `F` (ANSI X9.63, 65 bytes), if the
    /// accepted response carried one. `None` for a v1 pairing. Available once a
    /// response has been received.
    pub fn phone_se_share(&self) -> Option<[u8; 65]> {
        self.phone_se_share
    }

    /// The six SAS words for this pairing, to be read aloud and matched against
    /// the phone's screen. Available once the phone is pinned.
    pub fn sas_words(&self) -> Result<[&'static str; 6], HandshakeError> {
        let phone = self.phone.ok_or(HandshakeError::WrongState {
            expected: PairingState::ResponseReceived,
            actual: self.state,
        })?;
        Ok(fingerprint_words(&self.daemon_pub, &phone))
    }

    /// Record that the human confirmed the SAS matched on both screens. This is
    /// the terminal state of the ceremony: the phone identity (and any v2
    /// threshold share `F`) are now pinned, and there is no secret to hand off.
    pub fn confirm(&mut self) -> Result<(), HandshakeError> {
        self.expect(PairingState::ResponseReceived)?;
        self.state = PairingState::Confirmed;
        Ok(())
    }

    fn expect(&self, want: PairingState) -> Result<(), HandshakeError> {
        if self.state == want {
            Ok(())
        } else {
            Err(HandshakeError::WrongState {
                expected: want,
                actual: self.state,
            })
        }
    }
}

/// Phone-side driver for the handshake. Owns the phone's private identity, pins
/// the daemon from the QR, and holds the secret only long enough to produce the
/// single response.
pub struct PhonePairing {
    state: PairingState,
    phone_pub: PeerIdentity,
    daemon: PeerIdentity,
    endpoints: Vec<String>,
    created_at: u64,
    /// Taken (and thus zeroized) the moment the one response is produced.
    secret: Option<PairingSecret>,
    qr_ttl_ms: u64,
    /// The phone's v2 threshold share `F` to pin at pairing (standard base64
    /// x963), set via [`Self::with_se_share`] before [`Self::respond`]. `None`
    /// keeps the v1 (no-share) response.
    se_share_pub: Option<String>,
}

impl PhonePairing {
    /// Scan a QR: pin the daemon identity and enter [`PairingState::Scanned`].
    /// Rejects a QR older than the secret lifetime. `now` is unix ms.
    pub fn scan(
        identity: DeviceIdentity,
        payload: PairingPayload,
        now: u64,
    ) -> Result<Self, HandshakeError> {
        let age = now.saturating_sub(payload.created_at);
        if age > PAIRING_SECRET_TTL_MS {
            return Err(HandshakeError::SecretExpired {
                age_ms: age,
                limit_ms: PAIRING_SECRET_TTL_MS,
            });
        }
        let phone_pub = identity.peer_identity();
        Ok(Self {
            state: PairingState::Scanned,
            phone_pub,
            daemon: payload.daemon,
            endpoints: payload.endpoints,
            created_at: payload.created_at,
            secret: Some(payload.secret),
            qr_ttl_ms: PAIRING_SECRET_TTL_MS,
            se_share_pub: None,
        })
    }

    /// Override the QR freshness limit (mainly for tests).
    pub fn with_qr_ttl(mut self, ttl_ms: u64) -> Self {
        self.qr_ttl_ms = ttl_ms;
        self
    }

    /// Pin the phone's v2 Secure-Enclave threshold share `F` (standard base64 of
    /// the 65-byte ANSI X9.63 point) so the next [`respond`](Self::respond)
    /// carries it, bound into the confirmation tag. Call before `respond`.
    pub fn with_se_share(mut self, se_share_pub: &str) -> Self {
        self.se_share_pub = Some(se_share_pub.to_string());
        self
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    /// Produce the single authenticated response. Consumes the phone's copy of
    /// the secret (zeroized as it drops at the end of this call), so the phone
    /// too can respond only once.
    pub fn respond(&mut self) -> Result<PairingResponse, HandshakeError> {
        self.expect(PairingState::Scanned)?;
        let secret = self.secret.take().ok_or(HandshakeError::SecretConsumed)?;
        Ok(PairingResponse::build(
            &self.daemon,
            &self.endpoints,
            self.created_at,
            &self.phone_pub,
            &secret,
            self.se_share_pub.as_deref(),
        ))
    }

    /// The six SAS words for this pairing, to match against the Mac's screen.
    pub fn sas_words(&self) -> [&'static str; 6] {
        fingerprint_words(&self.daemon, &self.phone_pub)
    }

    /// Record that the human confirmed the SAS matched on both screens. Terminal:
    /// the daemon identity (and any v2 threshold share) are pinned and there is no
    /// secret handoff to await.
    pub fn confirm(&mut self) -> Result<(), HandshakeError> {
        self.expect(PairingState::Scanned)?;
        self.state = PairingState::Confirmed;
        Ok(())
    }

    pub fn daemon(&self) -> PeerIdentity {
        self.daemon
    }

    pub fn phone_identity(&self) -> PeerIdentity {
        self.phone_pub
    }

    fn expect(&self, want: PairingState) -> Result<(), HandshakeError> {
        if self.state == want {
            Ok(())
        } else {
            Err(HandshakeError::WrongState {
                expected: want,
                actual: self.state,
            })
        }
    }
}

/// The SAS backstop as a pure check: recompute the six words over the two
/// pinned identities and compare to what the other device displayed. Because
/// [`fingerprint_words`] is order-independent, both devices produce the same
/// words iff they pinned the same key pair.
pub fn verify_sas(daemon: &PeerIdentity, phone: &PeerIdentity, displayed: &[&str; 6]) -> bool {
    &fingerprint_words(daemon, phone) == displayed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn sample() -> PairingPayload {
        PairingPayload {
            daemon: DeviceIdentity::generate().peer_identity(),
            endpoints: vec![
                "lan://sigil.local:4823".to_string(),
                "https://tide.example.net:4823".to_string(),
            ],
            secret: PairingSecret::generate(),
            created_at: 1_720_000_000_000,
        }
    }

    #[test]
    fn qr_roundtrip_preserves_payload() {
        let p = sample();
        let encoded = p.to_qr_string().unwrap();
        let back = PairingPayload::from_qr_string(&encoded).unwrap();
        assert_eq!(back.daemon, p.daemon);
        assert_eq!(back.endpoints, p.endpoints);
        assert_eq!(back.secret.as_bytes(), p.secret.as_bytes());
        assert_eq!(back.created_at, p.created_at);
    }

    #[test]
    fn qr_string_is_padding_free() {
        let encoded = sample().to_qr_string().unwrap();
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(PairingPayload::from_qr_string("not valid base64 !!!").is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let s = PairingSecret([7u8; 32]);
        assert_eq!(format!("{s:?}"), "PairingSecret(<redacted>)");
    }

    // --- handshake ---------------------------------------------------------

    const NOW: u64 = 1_720_000_000_000;

    fn endpoints() -> Vec<String> {
        vec![
            "lan://sigil.local:4823".to_string(),
            "https://tide.example.net:4823".to_string(),
        ]
    }

    /// Run the full ceremony through SAS confirmation and return the two drivers,
    /// so individual tests can assert on any stage. The ceremony has no secret
    /// handoff of its own: at-rest secrets are threshold-sealed and opened
    /// per-request with the phone's partial, so pairing only pins keys.
    fn full_ceremony() -> (DaemonPairing, PhonePairing) {
        let daemon_id = DeviceIdentity::generate();
        let phone_id = DeviceIdentity::generate();

        // 0. Mac mints the QR.
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        assert_eq!(daemon.state(), PairingState::Init);

        // The QR survives a real round-trip through the QR string.
        let qr = payload.to_qr_string().unwrap();
        let payload = PairingPayload::from_qr_string(&qr).unwrap();

        // 1. Phone scans and responds.
        let mut phone = PhonePairing::scan(phone_id, payload, NOW + 1_000).unwrap();
        assert_eq!(phone.state(), PairingState::Scanned);
        let resp = phone.respond().unwrap();

        // 2. Mac verifies and pins the phone.
        let pinned = daemon.receive_response(&resp, NOW + 2_000).unwrap();
        assert_eq!(pinned, phone.phone_identity());
        assert_eq!(daemon.state(), PairingState::ResponseReceived);

        // 3. SAS matches on both screens (order-independent). Terminal.
        let daemon_words = daemon.sas_words().unwrap();
        let phone_words = phone.sas_words();
        assert_eq!(daemon_words, phone_words);
        daemon.confirm().unwrap();
        phone.confirm().unwrap();
        assert_eq!(daemon.state(), PairingState::Confirmed);
        assert_eq!(phone.state(), PairingState::Confirmed);

        (daemon, phone)
    }

    #[test]
    fn both_sides_derive_the_same_fingerprint() {
        let (daemon, phone) = full_ceremony();
        assert_eq!(daemon.sas_words().unwrap(), phone.sas_words());
    }

    #[test]
    fn tag_rejected_when_phone_key_substituted() {
        // Honest phone builds a response; a network MITM swaps in its own key.
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let phone_id = DeviceIdentity::generate();
        let mut phone = PhonePairing::scan(phone_id, payload, NOW).unwrap();
        let mut resp = phone.respond().unwrap();

        let attacker = DeviceIdentity::generate().peer_identity();
        resp.phone = attacker; // tag was computed over the real phone key.

        assert_eq!(
            daemon.receive_response(&resp, NOW),
            Err(HandshakeError::BadTag)
        );
        // The secret is not burned by a failed attempt.
        assert_eq!(daemon.state(), PairingState::Init);
    }

    /// A valid on-curve F in standard base64, plus its 65 raw bytes.
    fn sample_share() -> (String, [u8; 65]) {
        let f = crate::threshold::MacShare::generate();
        let raw = *f.public_point().as_x963();
        (B64_STD.encode(raw), raw)
    }

    #[test]
    fn v2_threshold_share_round_trips_and_is_pinned() {
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let (share_b64, share_raw) = sample_share();
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW)
            .unwrap()
            .with_se_share(&share_b64);
        let resp = phone.respond().unwrap();
        assert_eq!(resp.se_share_pub.as_deref(), Some(share_b64.as_str()));

        daemon.receive_response(&resp, NOW).unwrap();
        // The daemon pinned exactly the F the phone sent, on-curve validated.
        assert_eq!(daemon.phone_se_share(), Some(share_raw));
    }

    #[test]
    fn a_swapped_or_stripped_share_breaks_the_tag() {
        // F is bound into the confirmation tag, so a relay that swaps it for
        // another valid F' (to seal future tokens to a key it controls) or strips
        // it (to downgrade) is caught by the MAC, not silently accepted.
        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let (share_b64, _) = sample_share();
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW)
            .unwrap()
            .with_se_share(&share_b64);
        let good = phone.respond().unwrap();

        // Swap F for a different valid on-curve F'.
        let (other_b64, _) = sample_share();
        let mut swapped = good.clone();
        swapped.se_share_pub = Some(other_b64);
        assert_eq!(
            daemon.receive_response(&swapped, NOW),
            Err(HandshakeError::BadTag)
        );

        // Strip F entirely (downgrade attempt).
        let mut stripped = good.clone();
        stripped.se_share_pub = None;
        assert_eq!(
            daemon.receive_response(&stripped, NOW),
            Err(HandshakeError::BadTag)
        );

        // The genuine response still verifies (secret not burned by the failures).
        assert_eq!(daemon.receive_response(&good, NOW).unwrap(), good.phone);
        let _ = daemon_pub;
    }

    #[test]
    fn an_off_curve_share_is_rejected_even_with_a_valid_tag() {
        // The tag can be honestly computed over a malformed F (the phone controls
        // the string it MACs); the daemon must still refuse to pin an off-curve
        // point (lesser R2), failing the whole response closed.
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        // 65 bytes that are not a valid point.
        let bad = B64_STD.encode([0x04u8; 65]);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW)
            .unwrap()
            .with_se_share(&bad);
        let resp = phone.respond().unwrap();
        assert_eq!(
            daemon.receive_response(&resp, NOW),
            Err(HandshakeError::BadThresholdShare)
        );
    }

    #[test]
    fn a_v1_response_without_a_share_is_unchanged() {
        // No share => the transcript and wire bytes are byte-identical to v1, and
        // nothing is pinned. This is what keeps the live v1 demo working.
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        let resp = phone.respond().unwrap();
        assert!(resp.se_share_pub.is_none());
        assert!(!serde_json::to_string(&resp).unwrap().contains("seSharePub"));
        daemon.receive_response(&resp, NOW).unwrap();
        assert_eq!(daemon.phone_se_share(), None);
    }

    #[test]
    fn tag_rejected_under_wrong_secret() {
        // The daemon's stored secret differs from the one the response used.
        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let (mut daemon, _payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);

        // A phone that scanned a *different* QR (different secret) for the same
        // daemon identity and endpoints.
        let wrong_secret = PairingSecret::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let resp =
            PairingResponse::build(&daemon_pub, &endpoints(), NOW, &phone, &wrong_secret, None);

        assert_eq!(
            daemon.receive_response(&resp, NOW),
            Err(HandshakeError::BadTag)
        );
    }

    #[test]
    fn response_replayed_against_fresh_pairing_is_rejected() {
        // A response captured from pairing A is presented to a freshly minted
        // pairing B. Different daemon identity and different secret both fail it.
        let (_daemon_a, payload_a) =
            DaemonPairing::mint(DeviceIdentity::generate(), endpoints(), NOW);
        let mut phone_a = PhonePairing::scan(DeviceIdentity::generate(), payload_a, NOW).unwrap();
        let resp_a = phone_a.respond().unwrap();

        let (mut daemon_b, _payload_b) =
            DaemonPairing::mint(DeviceIdentity::generate(), endpoints(), NOW);
        assert_eq!(
            daemon_b.receive_response(&resp_a, NOW),
            Err(HandshakeError::BadTag)
        );
    }

    #[test]
    fn expired_secret_is_rejected() {
        // Tight, self-contained expiry test: the daemon's own valid response,
        // delivered late, is refused for expiry (not tag).
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW)
            .unwrap()
            .with_qr_ttl(u64::MAX);
        let resp = phone.respond().unwrap();
        let late = NOW + PAIRING_SECRET_TTL_MS + 1;
        assert_eq!(
            daemon.receive_response(&resp, late),
            Err(HandshakeError::SecretExpired {
                age_ms: PAIRING_SECRET_TTL_MS + 1,
                limit_ms: PAIRING_SECRET_TTL_MS,
            })
        );
    }

    #[test]
    fn one_time_secret_double_use_is_rejected() {
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);

        // Two phones both scanned the same QR (same secret). The first valid
        // response burns the secret; the second is refused even though its tag
        // is perfectly valid.
        let mut phone_a =
            PhonePairing::scan(DeviceIdentity::generate(), payload.clone(), NOW).unwrap();
        let mut phone_b = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        let resp_a = phone_a.respond().unwrap();
        let resp_b = phone_b.respond().unwrap();

        assert!(daemon.receive_response(&resp_a, NOW).is_ok());
        assert_eq!(
            daemon.receive_response(&resp_b, NOW),
            Err(HandshakeError::SecretConsumed)
        );
    }

    #[test]
    fn phone_responds_only_once() {
        let (_d, payload) = DaemonPairing::mint(DeviceIdentity::generate(), endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        assert!(phone.respond().is_ok());
        assert!(matches!(
            phone.respond(),
            Err(HandshakeError::SecretConsumed)
        ));
    }

    #[test]
    fn sas_mismatch_when_keys_differ() {
        // The phone pinned daemon A, but the human is comparing against a
        // different daemon B's screen: the six words diverge.
        let daemon_a = DeviceIdentity::generate().peer_identity();
        let daemon_b = DeviceIdentity::generate().peer_identity();
        let phone = DeviceIdentity::generate().peer_identity();

        let a_words = fingerprint_words(&daemon_a, &phone);
        let b_words = fingerprint_words(&daemon_b, &phone);
        assert_ne!(a_words, b_words);
        assert!(!verify_sas(&daemon_b, &phone, &a_words));
        assert!(verify_sas(&daemon_a, &phone, &a_words));
    }

    // --- confirmation transcript known-answer vectors -----------------------
    //
    // Pins `pairing_transcript`/`confirmation_tag` (via the exported
    // `pairing_confirmation_vector` seam) byte-for-byte over fixed inputs, so a
    // future change to either side's field ordering, length-prefixing, or
    // domain string is caught here rather than only by an end-to-end pairing
    // over real devices -- which is how the `seSharePub`/`se_share_pub`
    // camelCase wire mismatch shipped. `export-vectors` emits the same two
    // cases (v1, no share; v2, with `se_share_pub`) for the phone's TS mirror
    // to reproduce.

    fn fixed_peer(seed: u8) -> PeerIdentity {
        PeerIdentity {
            verifying: fixed32(seed),
            agreement: fixed32(seed.wrapping_add(1)),
        }
    }

    /// A deterministic 32-byte pattern from a seed, matching `export-vectors`'s
    /// helper of the same name so the two stay trivially comparable.
    fn fixed32(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1))
    }

    /// A deterministic, on-curve P-256 X9.63 point (standard base64), for a
    /// realistic `se_share_pub` value. `pairing_transcript` only ever hashes
    /// this as opaque string bytes -- on-curve validation happens elsewhere,
    /// at pin time -- but a real-shaped value keeps the vector honest.
    fn fixed_se_share_b64() -> String {
        use crate::threshold::MacShare;
        use base64::engine::general_purpose::STANDARD;
        let bytes: [u8; 32] =
            std::array::from_fn(|i| (0x44u8).wrapping_add(i as u8).wrapping_mul(3) | 1);
        let share =
            MacShare::from_scalar_bytes(&bytes).expect("fixed seed is a valid P-256 scalar");
        STANDARD.encode(share.public_point().as_x963())
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn pairing_confirmation_transcript_matches_the_known_answer_v1() {
        let secret = PairingSecret(fixed32(50));
        let daemon = fixed_peer(100);
        let endpoints = vec![
            "lan://sigil.local:4823".to_string(),
            "https://tide.example.net:4823".to_string(),
        ];
        let phone = fixed_peer(150);
        let nonce = fixed32(60);

        let (transcript, tag) = pairing_confirmation_vector(
            &secret,
            &daemon,
            &endpoints,
            1_720_000_000_000,
            &phone,
            &nonce,
            None,
        );

        assert_eq!(
            hex32(&transcript),
            "f1a8f19e2002b71a0fdca390517b2cc3c05234eda904f16f2ec1377b0ba07b94"
        );
        assert_eq!(
            hex32(&tag),
            "ef0eb993b98128976025b3c7c321cdb406ad4b98551855bf16f640eded4b4062"
        );
    }

    #[test]
    fn pairing_confirmation_transcript_matches_the_known_answer_v2_with_se_share() {
        let secret = PairingSecret(fixed32(50));
        let daemon = fixed_peer(100);
        let endpoints = vec![
            "lan://sigil.local:4823".to_string(),
            "https://tide.example.net:4823".to_string(),
        ];
        let phone = fixed_peer(150);
        let nonce = fixed32(60);
        let se_share = fixed_se_share_b64();

        let (transcript, tag) = pairing_confirmation_vector(
            &secret,
            &daemon,
            &endpoints,
            1_720_000_000_000,
            &phone,
            &nonce,
            Some(&se_share),
        );

        // With a share bound in, both the transcript and the tag must differ
        // from the v1 (no-share) case above -- proof `se_share_pub` actually
        // changes what gets signed, not just that the field exists.
        let (v1_transcript, v1_tag) = pairing_confirmation_vector(
            &secret,
            &daemon,
            &endpoints,
            1_720_000_000_000,
            &phone,
            &nonce,
            None,
        );
        assert_ne!(transcript, v1_transcript);
        assert_ne!(tag, v1_tag);

        assert_eq!(
            hex32(&transcript),
            "e435b82a46fe6c627352176d0fe1a049cc972c621bb3b34f07710b0637f8fba4"
        );
        assert_eq!(
            hex32(&tag),
            "350d87be9991f987497bd1c3dd2cbcb8ab4f226608b95bee7718a3966c58f53d"
        );
    }
}
