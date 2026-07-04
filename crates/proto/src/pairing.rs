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
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::PeerIdentity;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

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
}
