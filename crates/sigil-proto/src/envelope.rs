//! The sealed, signed envelope: the only thing Sigil ever puts on a wire.

use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::PeerIdentity;
use crate::replay::ReplayGuard;
use crate::{now_ms, REPLAY_WINDOW_MS};

/// Wire envelope. Everything a relay (or any hop) ever sees.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Envelope {
    /// Mailbox / pairing identifier. Routing only; carries no identity.
    pub pairing_id: [u8; 32],
    /// Single-use uuidv7. Terminal once answered or expired.
    pub request_id: Uuid,
    /// Per-pairing, per-direction monotonic counter.
    pub counter: u64,
    /// Sender wall clock, unix ms. Bounded by [`REPLAY_WINDOW_MS`].
    pub ts: u64,
    /// Fresh X25519 ephemeral public key for this envelope (forward secrecy).
    pub ephemeral_pub: [u8; 32],
    /// crypto_box nonce.
    pub nonce: [u8; 24],
    /// crypto_box ciphertext of the payload.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature by the sender's pinned identity over the canonical bytes.
    #[serde(with = "sig_bytes")]
    pub sig: [u8; 64],
}

/// serde support for the 64-byte signature: serde's blanket array impls stop
/// at length 32, so the fixed signature needs a hand-written (de)serializer.
mod sig_bytes {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(sig: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        let mut tup = ser.serialize_tuple(64)?;
        for byte in sig {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 64-byte ed25519 signature")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        de.deserialize_tuple(64, SigVisitor)
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SealError {
    #[error("payload serialization failed")]
    Serialize,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum OpenError {
    #[error("signature invalid for pinned sender")]
    BadSignature,
    #[error("replay rejected: {0}")]
    Replay(#[from] crate::replay::ReplayError),
    #[error("decryption failed")]
    Decrypt,
    #[error("payload deserialization failed")]
    Deserialize,
}

/// Canonical byte string the signature covers. Length-prefixed fields so no
/// two distinct envelopes can share a canonical form.
fn canonical_bytes(e: &Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 16 + 8 + 8 + 32 + 24 + 8 + e.ciphertext.len());
    out.extend_from_slice(&e.pairing_id);
    out.extend_from_slice(e.request_id.as_bytes());
    out.extend_from_slice(&e.counter.to_be_bytes());
    out.extend_from_slice(&e.ts.to_be_bytes());
    out.extend_from_slice(&e.ephemeral_pub);
    out.extend_from_slice(&e.nonce);
    out.extend_from_slice(&(e.ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(&e.ciphertext);
    out
}

impl Envelope {
    /// The canonical byte string the signature covers: length-prefixed fields
    /// in a fixed order, so no two distinct envelopes share a canonical form.
    /// Exposed for the shared Rust<->TS test vectors, which pin this encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(self)
    }

    /// Seal `payload` for the pinned `recipient`, signed by `sender_signing`.
    ///
    /// A fresh ephemeral X25519 key is generated per envelope; the recipient
    /// decrypts against it, so compromise of a long-term agreement key does
    /// not open past traffic.
    pub fn seal<T: Serialize>(
        payload: &T,
        pairing_id: [u8; 32],
        counter: u64,
        sender_signing: &SigningKey,
        recipient: &PeerIdentity,
    ) -> Result<Envelope, SealError> {
        let mut rng = rand_core::OsRng;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(payload).map_err(|_| SealError::Serialize)?);

        let ephemeral = BoxSecretKey::generate(&mut rng);
        let ephemeral_pub = *ephemeral.public_key().as_bytes();
        let nonce_ga = SalsaBox::generate_nonce(&mut rng);
        let sealer = SalsaBox::new(&recipient.agreement_key(), &ephemeral);
        let ciphertext = sealer
            .encrypt(&nonce_ga, plaintext.as_slice())
            .map_err(|_| SealError::Serialize)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_ga.as_slice());

        let mut envelope = Envelope {
            pairing_id,
            request_id: Uuid::now_v7(),
            counter,
            ts: now_ms(),
            ephemeral_pub,
            nonce,
            ciphertext,
            sig: [0u8; 64],
        };
        let sig = sender_signing.sign(&canonical_bytes(&envelope));
        envelope.sig = sig.to_bytes();
        Ok(envelope)
    }

    /// Verify, replay-check, and decrypt an envelope from the pinned `sender`.
    ///
    /// Order matters and is load-bearing: signature first (cheap, rejects
    /// forgeries), then replay (marks the id as seen only for authentic
    /// envelopes), then decryption.
    pub fn open<T: for<'de> Deserialize<'de>>(
        &self,
        sender: &PeerIdentity,
        recipient_agreement: &BoxSecretKey,
        guard: &mut ReplayGuard,
    ) -> Result<T, OpenError> {
        // 1. Authenticity.
        let verifying = sender
            .verifying_key()
            .map_err(|_| OpenError::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig);
        verifying
            .verify(&canonical_bytes(self), &sig)
            .map_err(|_| OpenError::BadSignature)?;

        // 2. Freshness and single use.
        guard.check_and_record(
            self.request_id,
            self.counter,
            self.ts,
            now_ms(),
            REPLAY_WINDOW_MS,
        )?;

        // 3. Confidentiality.
        let ephemeral_pub = BoxPublicKey::from(self.ephemeral_pub);
        let opener = SalsaBox::new(&ephemeral_pub, recipient_agreement);
        let plaintext = Zeroizing::new(
            opener
                .decrypt((&self.nonce).into(), self.ciphertext.as_slice())
                .map_err(|_| OpenError::Decrypt)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| OpenError::Deserialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::replay::ReplayError;

    // A sender (e.g. the phone) and a recipient (e.g. the daemon).
    struct Link {
        sender: DeviceIdentity,
        recipient: DeviceIdentity,
        pairing_id: [u8; 32],
    }

    fn link() -> Link {
        Link {
            sender: DeviceIdentity::generate(),
            recipient: DeviceIdentity::generate(),
            pairing_id: [7u8; 32],
        }
    }

    fn seal_at(link: &Link, counter: u64, msg: &str) -> Envelope {
        Envelope::seal(
            &msg.to_string(),
            link.pairing_id,
            counter,
            &link.sender.signing,
            &link.recipient.peer_identity(),
        )
        .expect("seal")
    }

    fn open(link: &Link, env: &Envelope, guard: &mut ReplayGuard) -> Result<String, OpenError> {
        env.open(
            &link.sender.peer_identity(),
            &link.recipient.agreement,
            guard,
        )
    }

    #[test]
    fn roundtrip_delivers_the_payload() {
        let link = link();
        let env = seal_at(&link, 1, "unlock Engineering/.env");
        let mut guard = ReplayGuard::new();
        assert_eq!(
            open(&link, &env, &mut guard).unwrap(),
            "unlock Engineering/.env"
        );
    }

    #[test]
    fn wrong_sender_key_is_rejected() {
        let link = link();
        let env = seal_at(&link, 1, "hi");
        let impostor = DeviceIdentity::generate().peer_identity();
        let mut guard = ReplayGuard::new();
        let got = env.open::<String>(&impostor, &link.recipient.agreement, &mut guard);
        assert_eq!(got, Err(OpenError::BadSignature));
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let link = link();
        let env = seal_at(&link, 1, "hi");
        // Signature is the sender's, so it verifies; only decryption fails.
        let stranger = DeviceIdentity::generate();
        let mut guard = ReplayGuard::new();
        let got = env.open::<String>(
            &link.sender.peer_identity(),
            &stranger.agreement,
            &mut guard,
        );
        assert_eq!(got, Err(OpenError::Decrypt));
    }

    #[test]
    fn any_field_tamper_breaks_the_signature() {
        let link = link();
        let base = seal_at(&link, 1, "hi");

        type Tamper = fn(&mut Envelope);
        let mutations: [(&str, Tamper); 7] = [
            ("pairing_id", |e| e.pairing_id[0] ^= 1),
            ("counter", |e| e.counter ^= 1),
            ("ts", |e| e.ts ^= 1),
            ("ephemeral_pub", |e| e.ephemeral_pub[0] ^= 1),
            ("nonce", |e| e.nonce[0] ^= 1),
            ("ciphertext", |e| e.ciphertext[0] ^= 1),
            ("sig", |e| e.sig[0] ^= 1),
        ];

        for (field, mutate) in mutations {
            let mut env = base.clone();
            mutate(&mut env);
            let mut guard = ReplayGuard::new();
            assert_eq!(
                open(&link, &env, &mut guard),
                Err(OpenError::BadSignature),
                "tampering {field} should be caught by the signature"
            );
        }
    }

    #[test]
    fn exact_replay_is_rejected() {
        let link = link();
        let env = seal_at(&link, 1, "hi");
        let mut guard = ReplayGuard::new();
        assert!(open(&link, &env, &mut guard).is_ok());
        assert_eq!(
            open(&link, &env, &mut guard),
            Err(OpenError::Replay(ReplayError::DuplicateRequest))
        );
    }

    #[test]
    fn lower_counter_with_fresh_ts_and_new_id_is_accepted() {
        // The counter no longer gates acceptance. A genuine second envelope that
        // rides a lower (e.g. restarted) counter but carries a fresh timestamp
        // and a new request id must open, not be dropped as a false replay. It is
        // still a distinct signed envelope with its own uuidv7, so replay of the
        // *first* one remains caught by the single-use id (see exact_replay).
        let link = link();
        let mut guard = ReplayGuard::new();
        let high = seal_at(&link, 5, "first");
        assert!(open(&link, &high, &mut guard).is_ok());
        let low = seal_at(&link, 3, "second");
        assert_eq!(open(&link, &low, &mut guard).unwrap(), "second");
    }
}
