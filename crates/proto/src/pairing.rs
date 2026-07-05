//! The payload a Mac renders into a pairing QR code and a phone scans.
//!
//! It carries the daemon's public identity (so the phone can pin it), the
//! endpoints to reach the daemon on, a one-time pairing secret, and a
//! creation timestamp. The private halves never leave the daemon's keystore;
//! only the public identity travels here. The whole payload is serialised to
//! JSON and base64url-encoded so it fits a QR with no padding characters to
//! confuse scanners.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::{Blake2b512, Blake2bMac, Digest};
use crypto_box::SecretKey as BoxSecretKey;
use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::envelope::{Envelope, OpenError, SealError};
use crate::fingerprint::{fingerprint_words, mailbox_id};
use crate::identity::{DeviceIdentity, PeerIdentity};
use crate::replay::ReplayGuard;

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
const PAIRING_DOMAIN: &[u8] = b"latch.pairing.v1";
/// Domain for the pairing rendezvous mailbox (message 1 and 3 transport).
const RENDEZVOUS_DOMAIN: &[u8] = b"latch.pairing.rendezvous.v1";
/// Label deriving the confirmation-MAC subkey from the pairing secret. Distinct
/// label => distinct key => no key reuse across purposes.
const SUBKEY_CONFIRM_LABEL: &[u8] = b"confirm-tag";

/// Default lifetime of a pairing secret / QR, in milliseconds (180s). After
/// this the daemon refuses any response and the human re-mints the QR.
pub const PAIRING_SECRET_TTL_MS: u64 = 180_000;

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
pub struct PairingResponse {
    /// The phone's public identity, to be pinned by the daemon.
    pub phone: PeerIdentity,
    /// Fresh per-response nonce, bound into the transcript.
    pub nonce: [u8; 32],
    /// BLAKE2b-keyed confirmation tag over the transcript.
    pub tag: [u8; 32],
}

/// The v2 pairing message that delivers the phone's public Secure-Enclave
/// threshold share `F` to the Mac (`docs/design/threshold-v2.md` §5/§7).
///
/// Sent phone->Mac **after SAS Confirmed**, sealed in a standard [`Envelope`]
/// (signed by the phone's pinned identity, sealed to the daemon's pinned
/// agreement key) and submitted to the rendezvous mailbox — the same
/// authenticated, replay-guarded transport as the DEK handoff, reversed. The
/// private `f` never leaves the enclave; only `F` (a public point) travels.
///
/// Serializes `camelCase` to match the phone's TypeScript
/// (`apps/phone/src/protocol/threshold.ts` `ThresholdShare`): `seKeyId`,
/// `fX963` (standard base64 of the 65-byte ANSI X9.63 point), `ecdhAlgo`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdShare {
    /// The phone's SE key id; the daemon pins it and echoes it per request.
    pub se_key_id: String,
    /// `F = f·G`, ANSI X9.63 uncompressed (65 bytes), standard base64. Validated
    /// on-curve by the daemon before it is pinned.
    pub f_x963: String,
    /// Which SE ECDH output shape this key's partials take (NV-2), e.g. `raw-x`.
    pub ecdh_algo: crate::threshold::EcdhAlgo,
}

impl PairingResponse {
    /// Build a response from decomposed QR fields plus the phone identity.
    fn build(
        daemon: &PeerIdentity,
        endpoints: &[String],
        created_at: u64,
        phone: &PeerIdentity,
        secret: &PairingSecret,
    ) -> Self {
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let k_confirm = derive_subkey(secret, SUBKEY_CONFIRM_LABEL);
        let transcript = pairing_transcript(daemon, endpoints, created_at, phone, &nonce);
        let tag = confirmation_tag(&k_confirm, &transcript);
        Self {
            phone: *phone,
            nonce,
            tag,
        }
    }

    /// Phone side: build the authenticated response to a scanned `payload`. The
    /// phone's v2 threshold share `F`, when present, is delivered separately as a
    /// sealed [`ThresholdShare`] after SAS, not on this message.
    pub fn create(payload: &PairingPayload, phone: &PeerIdentity) -> Self {
        Self::build(
            &payload.daemon,
            &payload.endpoints,
            payload.created_at,
            phone,
            &payload.secret,
        )
    }

    /// Daemon side: verify the tag against the daemon's own view of the QR it
    /// minted. Returns `true` only if the sender held the secret and bound
    /// exactly `self.phone` to exactly this pairing.
    pub fn verify(
        &self,
        daemon: &PeerIdentity,
        endpoints: &[String],
        created_at: u64,
        secret: &PairingSecret,
    ) -> bool {
        let k_confirm = derive_subkey(secret, SUBKEY_CONFIRM_LABEL);
        let transcript =
            pairing_transcript(daemon, endpoints, created_at, &self.phone, &self.nonce);
        verify_confirmation_tag(&k_confirm, &transcript, &self.tag)
    }
}

/// The 256-bit data-encryption key: the missing half of the daemon's crypto.
///
/// Zeroized on drop. Delivered to the phone once, at pairing, sealed inside an
/// [`Envelope`] (X25519); optionally wrapped a second time to the Mac's Secure
/// Enclave (P-256 ECIES, see [`crate::se_ecies`]) for local Touch ID approvals;
/// then erased from the daemon.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; 32]);

impl Dek {
    /// Fresh DEK from the platform CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// Seal the DEK to `recipient`'s pinned X25519 key, signed by `daemon_signing`.
///
/// This is the whole DEK-handoff primitive. Delivering to the phone and
/// wrapping a second copy to the Mac Secure Enclave are the same call with a
/// different recipient, so both reuse the envelope's sealing, signing, and
/// replay machinery unchanged.
pub fn seal_dek(
    dek: &Dek,
    pairing_id: [u8; 32],
    counter: u64,
    daemon_signing: &SigningKey,
    recipient: &PeerIdentity,
) -> Result<Envelope, SealError> {
    Envelope::seal(dek, pairing_id, counter, daemon_signing, recipient)
}

/// Open a sealed DEK: verify the daemon signature, replay-check, and decrypt
/// against `recipient_agreement`. The recovered DEK is zeroized on drop.
pub fn open_dek(
    env: &Envelope,
    daemon: &PeerIdentity,
    recipient_agreement: &BoxSecretKey,
    guard: &mut ReplayGuard,
) -> Result<Dek, OpenError> {
    env.open(daemon, recipient_agreement, guard)
}

/// The step both peers have reached in the ceremony. The two driver types
/// (`DaemonPairing`, `PhonePairing`) share this vocabulary; each enforces its
/// own legal transitions.
///
/// ```text
/// daemon:  Init ------------> ResponseReceived --> Confirmed --> DekDelivered
/// phone:   Scanned ---------> (respond sent) ----> Confirmed --> DekDelivered
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairingState {
    /// Daemon: QR minted, waiting for a response.
    Init,
    /// Phone: QR scanned, identity pinned, ready to respond.
    Scanned,
    /// Daemon: a valid response arrived; the phone key is now pinned.
    ResponseReceived,
    /// Both: the six-word SAS matched on both screens.
    Confirmed,
    /// Both: the DEK has been sealed to the phone (and erased from the daemon).
    DekDelivered,
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
    #[error("SAS mismatch: the two devices did not pin the same keys")]
    SasMismatch,
    #[error("sealing the DEK failed: {0}")]
    Seal(#[from] SealError),
    #[error("opening the DEK failed: {0}")]
    Open(#[from] OpenError),
    #[error("wrapping the DEK to the Mac Secure Enclave failed: {0}")]
    SeEcies(#[from] crate::se_ecies::SeEciesError),
}

/// Daemon-side driver for the handshake. Owns the daemon's private identity, the
/// pairing secret, and the pinned phone key once known.
pub struct DaemonPairing {
    state: PairingState,
    identity: DeviceIdentity,
    daemon_pub: PeerIdentity,
    endpoints: Vec<String>,
    secret: PairingSecret,
    created_at: u64,
    secret_ttl_ms: u64,
    consumed: bool,
    phone: Option<PeerIdentity>,
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
            identity,
            daemon_pub,
            endpoints,
            secret,
            created_at: now,
            secret_ttl_ms: PAIRING_SECRET_TTL_MS,
            consumed: false,
            phone: None,
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
        self.consumed = true;
        self.phone = Some(resp.phone);
        self.state = PairingState::ResponseReceived;
        Ok(resp.phone)
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

    /// Record that the human confirmed the SAS matched on both screens.
    pub fn confirm(&mut self) -> Result<(), HandshakeError> {
        self.expect(PairingState::ResponseReceived)?;
        self.state = PairingState::Confirmed;
        Ok(())
    }

    /// Seal the DEK to the pinned phone. Requires SAS confirmation first, so a
    /// key never confirmed by a human never receives the DEK. Advances to
    /// `DekDelivered`.
    pub fn deliver_dek(&mut self, dek: &Dek, counter: u64) -> Result<Envelope, HandshakeError> {
        self.expect(PairingState::Confirmed)?;
        let phone = self.phone.expect("phone pinned before Confirmed");
        let pairing_id = mailbox_id(&self.daemon_pub, &phone);
        let env = seal_dek(dek, pairing_id, counter, &self.identity.signing, &phone)?;
        self.state = PairingState::DekDelivered;
        Ok(env)
    }

    /// Wrap a second copy of the DEK to another **X25519** recipient (e.g. a
    /// second phone or backup approver) inside a standard [`Envelope`]. Available
    /// once the SAS is confirmed. Does not change state: it is an extra copy, not
    /// the phone delivery.
    ///
    /// This is NOT the Mac Secure Enclave path: the SE holds only P-256 keys and
    /// cannot open an X25519 envelope, so the Mac-SE wrap uses
    /// [`wrap_dek_for_se_p256`](Self::wrap_dek_for_se_p256) instead.
    pub fn wrap_dek_for(
        &self,
        dek: &Dek,
        recipient: &PeerIdentity,
        counter: u64,
    ) -> Result<Envelope, HandshakeError> {
        if self.state != PairingState::Confirmed && self.state != PairingState::DekDelivered {
            return Err(HandshakeError::WrongState {
                expected: PairingState::Confirmed,
                actual: self.state,
            });
        }
        let pairing_id = mailbox_id(&self.daemon_pub, recipient);
        Ok(seal_dek(
            dek,
            pairing_id,
            counter,
            &self.identity.signing,
            recipient,
        )?)
    }

    /// Wrap the DEK to the Mac's Secure Enclave P-256 key for local Touch ID
    /// approvals. `se_pub_x963` is the SE public key in ANSI X9.63 uncompressed
    /// form, exported by the Mac app at "Enable Mac approvals" time. Returns the
    /// Apple-compatible ECIES blob the SE opens under Touch ID (see
    /// [`crate::se_ecies`]).
    ///
    /// This is the P-256 sibling of [`wrap_dek_for`](Self::wrap_dek_for): the
    /// Secure Enclave holds only P-256 keys, so the Mac-SE wrap cannot reuse the
    /// phone's X25519 envelope. It is a second, independent wrap of the same DEK,
    /// gated on the same SAS confirmation, and does not change state.
    pub fn wrap_dek_for_se_p256(
        &self,
        dek: &Dek,
        se_pub_x963: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if self.state != PairingState::Confirmed && self.state != PairingState::DekDelivered {
            return Err(HandshakeError::WrongState {
                expected: PairingState::Confirmed,
                actual: self.state,
            });
        }
        Ok(crate::se_ecies::wrap_dek_p256(dek, se_pub_x963)?)
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
    identity: DeviceIdentity,
    phone_pub: PeerIdentity,
    daemon: PeerIdentity,
    endpoints: Vec<String>,
    created_at: u64,
    /// Taken (and thus zeroized) the moment the one response is produced.
    secret: Option<PairingSecret>,
    qr_ttl_ms: u64,
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
            identity,
            phone_pub,
            daemon: payload.daemon,
            endpoints: payload.endpoints,
            created_at: payload.created_at,
            secret: Some(payload.secret),
            qr_ttl_ms: PAIRING_SECRET_TTL_MS,
        })
    }

    /// Override the QR freshness limit (mainly for tests).
    pub fn with_qr_ttl(mut self, ttl_ms: u64) -> Self {
        self.qr_ttl_ms = ttl_ms;
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
        ))
    }

    /// The six SAS words for this pairing, to match against the Mac's screen.
    pub fn sas_words(&self) -> [&'static str; 6] {
        fingerprint_words(&self.daemon, &self.phone_pub)
    }

    /// Record that the human confirmed the SAS matched on both screens.
    pub fn confirm(&mut self) -> Result<(), HandshakeError> {
        self.expect(PairingState::Scanned)?;
        self.state = PairingState::Confirmed;
        Ok(())
    }

    /// Open the DEK sealed by the daemon. Requires prior SAS confirmation.
    /// Advances to `DekDelivered`.
    pub fn receive_dek(
        &mut self,
        env: &Envelope,
        guard: &mut ReplayGuard,
    ) -> Result<Dek, HandshakeError> {
        self.expect(PairingState::Confirmed)?;
        let dek = open_dek(env, &self.daemon, &self.identity.agreement, guard)?;
        self.state = PairingState::DekDelivered;
        Ok(dek)
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
    use base64::engine::general_purpose::STANDARD as B64_STD;

    fn sample() -> PairingPayload {
        PairingPayload {
            daemon: DeviceIdentity::generate().peer_identity(),
            endpoints: vec![
                "lan://latch.local:4823".to_string(),
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
            "lan://latch.local:4823".to_string(),
            "https://tide.example.net:4823".to_string(),
        ]
    }

    /// Run the full ceremony and return the two drivers plus the delivered DEK,
    /// so individual tests can assert on any stage.
    fn full_ceremony() -> (DaemonPairing, PhonePairing, Dek, Dek) {
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

        // 3. SAS matches on both screens (order-independent).
        let daemon_words = daemon.sas_words().unwrap();
        let phone_words = phone.sas_words();
        assert_eq!(daemon_words, phone_words);
        daemon.confirm().unwrap();
        phone.confirm().unwrap();
        assert_eq!(daemon.state(), PairingState::Confirmed);
        assert_eq!(phone.state(), PairingState::Confirmed);

        // 4. DEK handoff.
        let dek = Dek::generate();
        let env = daemon.deliver_dek(&dek, 1).unwrap();
        assert_eq!(daemon.state(), PairingState::DekDelivered);
        let mut guard = ReplayGuard::new();
        let recovered = phone.receive_dek(&env, &mut guard).unwrap();
        assert_eq!(phone.state(), PairingState::DekDelivered);

        let original = Dek::from_bytes(*dek.as_bytes());
        (daemon, phone, original, recovered)
    }

    #[test]
    fn full_ceremony_delivers_the_dek() {
        let (_daemon, _phone, original, recovered) = full_ceremony();
        assert_eq!(recovered.as_bytes(), original.as_bytes());
    }

    #[test]
    fn both_sides_derive_the_same_fingerprint() {
        let (daemon, phone, _o, _r) = full_ceremony();
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

    #[test]
    fn threshold_share_serializes_camel_case_to_match_the_phone() {
        // The v2 ThresholdShare wire must match apps/phone's `ThresholdShare`
        // byte-for-byte: camelCase keys, F as standard base64, ecdhAlgo as its tag.
        let f = crate::threshold::MacShare::generate();
        let f_b64 = B64_STD.encode(f.public_point().as_x963());
        let share = ThresholdShare {
            se_key_id: "latch-se-abc".into(),
            f_x963: f_b64.clone(),
            ecdh_algo: crate::threshold::EcdhAlgo::RawX,
        };
        let json = serde_json::to_string(&share).unwrap();
        assert!(json.contains("\"seKeyId\":\"latch-se-abc\""));
        assert!(json.contains(&format!("\"fX963\":\"{f_b64}\"")));
        assert!(json.contains("\"ecdhAlgo\":\"raw-x\""));
        let back: ThresholdShare = serde_json::from_str(&json).unwrap();
        assert_eq!(back, share);
    }

    #[test]
    fn threshold_share_rides_a_sealed_envelope_phone_to_daemon() {
        // The phone seals the share to the pinned daemon and signs it; the daemon
        // opens it exactly like any other envelope (sig + replay + decrypt), the
        // same audited path as the DEK handoff, reversed.
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let f = crate::threshold::MacShare::generate();
        let share = ThresholdShare {
            se_key_id: "latch-se-1".into(),
            f_x963: B64_STD.encode(f.public_point().as_x963()),
            ecdh_algo: crate::threshold::EcdhAlgo::RawX,
        };
        let pairing_id = mailbox_id(&phone.peer_identity(), &daemon.peer_identity());
        let env = Envelope::seal(
            &share,
            pairing_id,
            1,
            &phone.signing,
            &daemon.peer_identity(),
        )
        .unwrap();

        let mut guard = ReplayGuard::new();
        let opened: ThresholdShare = env
            .open(&phone.peer_identity(), &daemon.agreement, &mut guard)
            .unwrap();
        assert_eq!(opened, share);

        // A wrong sender key fails the signature (a relay cannot forge it).
        let imposter = DeviceIdentity::generate().peer_identity();
        let mut guard = ReplayGuard::new();
        assert!(env
            .open::<ThresholdShare>(&imposter, &daemon.agreement, &mut guard)
            .is_err());
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
        let resp = PairingResponse::build(&daemon_pub, &endpoints(), NOW, &phone, &wrong_secret);

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

    #[test]
    fn dek_not_delivered_before_confirmation() {
        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        let resp = phone.respond().unwrap();
        daemon.receive_response(&resp, NOW).unwrap();
        // Skipping confirm(): deliver_dek must refuse.
        let dek = Dek::generate();
        assert!(matches!(
            daemon.deliver_dek(&dek, 1),
            Err(HandshakeError::WrongState {
                expected: PairingState::Confirmed,
                actual: PairingState::ResponseReceived,
            })
        ));
    }

    #[test]
    fn second_recipient_wrap_recovers_the_same_dek() {
        // After confirmation the daemon wraps a second copy of the DEK to another
        // X25519 recipient (a second phone / backup approver); that recipient
        // recovers the same key, and a wrong sender key is rejected on the
        // signature. (The Mac Secure Enclave path is P-256, tested separately in
        // `se_p256_wrap_is_gated_on_confirmation_and_round_trips`.)
        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        let resp = phone.respond().unwrap();
        daemon.receive_response(&resp, NOW).unwrap();
        daemon.confirm().unwrap();

        let dek = Dek::generate();
        let se = DeviceIdentity::generate();
        let env = daemon.wrap_dek_for(&dek, &se.peer_identity(), 1).unwrap();

        // A wrong sender key fails the signature.
        let mut guard = ReplayGuard::new();
        let imposter = DeviceIdentity::generate().peer_identity();
        assert!(matches!(
            open_dek(&env, &imposter, &se.agreement, &mut guard),
            Err(OpenError::BadSignature)
        ));

        // The real daemon identity recovers the same DEK.
        let mut guard = ReplayGuard::new();
        let recovered = open_dek(&env, &daemon_pub, &se.agreement, &mut guard).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn dek_debug_does_not_leak() {
        let d = Dek::from_bytes([9u8; 32]);
        assert_eq!(format!("{d:?}"), "Dek(<redacted>)");
    }

    #[test]
    fn se_p256_wrap_is_gated_on_confirmation_and_round_trips() {
        use crate::se_ecies::unwrap_dek_p256;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        // A stand-in Secure Enclave P-256 key (software here; on the Mac the
        // private half never leaves the enclave).
        let se_secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let se_pub = se_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let daemon_id = DeviceIdentity::generate();
        let (mut daemon, payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);
        let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
        let resp = phone.respond().unwrap();
        daemon.receive_response(&resp, NOW).unwrap();

        let dek = Dek::generate();

        // Before SAS confirmation the SE wrap is refused, exactly like the phone
        // wrap: no DEK material is produced for a key no human confirmed.
        assert!(matches!(
            daemon.wrap_dek_for_se_p256(&dek, &se_pub),
            Err(HandshakeError::WrongState {
                expected: PairingState::Confirmed,
                actual: PairingState::ResponseReceived,
            })
        ));

        daemon.confirm().unwrap();

        // After confirmation the SE (via its P-256 secret) recovers the same DEK.
        let sealed = daemon.wrap_dek_for_se_p256(&dek, &se_pub).unwrap();
        let recovered = unwrap_dek_p256(&sealed, &se_secret).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }
}
