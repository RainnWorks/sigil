//! Latch protocol core.
//!
//! Everything that crosses a network hop in Latch is an [`Envelope`]: sealed
//! with crypto_box (X25519 + XSalsa20-Poly1305) to the pinned recipient key,
//! signed with Ed25519 by the pinned sender key, and replay-protected by a
//! single-use uuidv7 request id, a per-pairing monotonic counter, and a
//! timestamp window. The transport (unix socket, LAN, owned endpoint, blind
//! relay) is never the security layer; this crate is.

pub mod envelope;
pub mod fingerprint;
pub mod identity;
pub mod pairing;
pub mod replay;
pub mod request;
pub mod se_ecies;
pub mod threshold;
pub mod transport;

pub use envelope::{Envelope, OpenError, SealError};
pub use fingerprint::{fingerprint_words, mailbox_id};
pub use identity::{DeviceIdentity, PeerIdentity};
pub use pairing::{
    open_dek, rendezvous_mailbox, seal_dek, verify_sas, DaemonPairing, Dek, HandshakeError,
    PairingError, PairingPayload, PairingResponse, PairingSecret, PairingState, PhonePairing,
    PAIRING_SECRET_TTL_MS,
};
pub use replay::{ReplayError, ReplayGuard};
pub use request::{
    ApprovalRequest, ApprovalResponse, BlockDirective, Decision, InstallLease, Provenance,
    PushRegister, RequestKind, RiskLevel, SecretRef, SshChallenge, ThresholdChallenge,
    ThresholdPartial, ToDaemonMessage,
};
pub use se_ecies::{unwrap_dek_p256, wrap_dek_p256, SeEciesError};
pub use threshold::{
    aead_open, aead_seal, all_ephemerals_unique, combine, decode_partial, EcdhAlgo, MacShare,
    P256Point, ThresholdError, ThresholdRecord, KDF_ALGO_ID, THRESHOLD_DOMAIN,
    THRESHOLD_RECORD_VERSION,
};
pub use transport::{Direction, LocalRelay, PushHint, Transport, TransportError};

/// Maximum allowed clock skew between sender and receiver, in milliseconds.
pub const REPLAY_WINDOW_MS: u64 = 90_000;

/// Wall-clock now in unix milliseconds.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}
