//! Device identities: an Ed25519 signing key plus an X25519 agreement key.
//!
//! Generated on-device at pairing, private halves live in the platform
//! keystore (Secure Enclave / StrongBox / Keychain seam); this crate only
//! defines the shapes and the in-memory operations.

use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The full identity of the local device. Private material; never serialized
/// in full by this crate.
pub struct DeviceIdentity {
    pub signing: SigningKey,
    pub agreement: BoxSecretKey,
}

impl DeviceIdentity {
    /// Generate a fresh identity from the platform CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
            agreement: BoxSecretKey::generate(&mut rng),
        }
    }

    /// The shareable half, exchanged at pairing and pinned by the peer.
    pub fn peer_identity(&self) -> PeerIdentity {
        PeerIdentity {
            verifying: self.signing.verifying_key().to_bytes(),
            agreement: *self.agreement.public_key().as_bytes(),
        }
    }

    /// The 64-byte secret encoding of this identity: Ed25519 signing seed (32)
    /// followed by the X25519 agreement secret (32). This is the ONLY full
    /// serialization of the private material, and it exists solely so a device
    /// can seal its own long-term identity into the platform keystore seam
    /// (Secure Enclave / Keychain) and reload it across restarts. These bytes
    /// must never be written anywhere but that keystore. The buffer is
    /// `Zeroizing`, so it is wiped when the caller drops it.
    pub fn to_secret_bytes(&self) -> zeroize::Zeroizing<[u8; 64]> {
        let mut out = zeroize::Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.agreement.to_bytes());
        out
    }

    /// Reconstruct an identity from [`to_secret_bytes`]. Returns `None` if the
    /// input is not exactly 64 bytes, so a truncated or corrupt keystore blob
    /// fails closed rather than yielding a partial key.
    pub fn from_secret_bytes(bytes: &[u8]) -> Option<Self> {
        use zeroize::Zeroize;
        if bytes.len() != 64 {
            return None;
        }
        let mut seed = [0u8; 32];
        let mut agree = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        agree.copy_from_slice(&bytes[32..]);
        let id = Self {
            signing: SigningKey::from_bytes(&seed),
            agreement: BoxSecretKey::from_bytes(agree),
        };
        seed.zeroize();
        agree.zeroize();
        Some(id)
    }
}

/// The pinned public identity of a paired peer.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PeerIdentity {
    /// Ed25519 verifying key bytes.
    pub verifying: [u8; 32],
    /// X25519 public key bytes.
    pub agreement: [u8; 32],
}

impl PeerIdentity {
    pub fn verifying_key(&self) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(&self.verifying)
    }

    pub fn agreement_key(&self) -> BoxPublicKey {
        BoxPublicKey::from(self.agreement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_round_trip_preserves_the_public_identity() {
        let id = DeviceIdentity::generate();
        let bytes = id.to_secret_bytes();
        assert_eq!(bytes.len(), 64);
        let back = DeviceIdentity::from_secret_bytes(&bytes[..]).unwrap();
        // The reconstructed identity yields the same pinned public halves, so a
        // peer that pinned the original still verifies and seals to the reload.
        assert_eq!(back.peer_identity(), id.peer_identity());
    }

    #[test]
    fn from_secret_bytes_rejects_a_wrong_length_blob() {
        assert!(DeviceIdentity::from_secret_bytes(&[0u8; 32]).is_none());
        assert!(DeviceIdentity::from_secret_bytes(&[0u8; 65]).is_none());
        assert!(DeviceIdentity::from_secret_bytes(&[]).is_none());
    }
}
