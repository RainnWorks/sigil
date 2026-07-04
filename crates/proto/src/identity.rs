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
