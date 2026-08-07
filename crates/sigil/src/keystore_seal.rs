//! The Secure-Enclave-wrapped keystore file (v2): format, digest, and the
//! adoption state a daemon resolves once at startup.
//!
//! # What v2 buys, stated exactly
//!
//! v1 is the plaintext `keystore.json` this daemon has always written: a 0600
//! JSON file holding the daemon identity key and the Mac threshold share `m`.
//! v2 replaces its bytes with a ciphertext only the signed Sigil app's Secure
//! Enclave key can open, and the app hands the plaintext back over the local
//! socket at runtime.
//!
//! The delta is **at-rest exfiltration**, and nothing else. A Time Machine
//! snapshot, a cloud backup, a stolen or resold disk, a stray `cp -r ~` into a
//! synced folder: that whole offline class stops yielding usable material,
//! because the ciphertext is worthless without an enclave that stayed on the
//! machine. What v2 does NOT do is protect a live machine: the daemon holds the
//! material in ordinary RAM while it runs, that RAM is readable by anything
//! running as the same user, and the daemon is unsigned by design. A same-UID
//! attacker on a running machine is exactly as capable as before. Any claim
//! beyond "offline copies are now useless" would be false.
//!
//! # The file
//!
//! ```json
//! {"v":2,"pub_digest":"<hex>","se_pub":"<base64 SPKI DER>","ciphertext":"<base64>"}
//! ```
//!
//! There is no `se_wrapped` flag: `"v":2` IS the statement that the file is
//! wrapped, and a second field that could disagree with it is a bug waiting to
//! be exploited. Contradictory shapes (a v2 carrying plaintext `blobs`, a v1
//! carrying a `ciphertext`) are refused rather than guessed at.
//!
//! # The digest
//!
//! `pub_digest` commits to what was wrapped, so a provisioned daemon can tell
//! "the app handed me the material this file names" from "the app handed me
//! something else":
//!
//! ```text
//! BLAKE2b-256( "sigil.keystore.v2"
//!            || u64le(len(se_pub))  || se_pub
//!            || u64le(len(material)) || material )
//! ```
//!
//! `material` is the v1 file's exact serialized bytes, treated as an opaque
//! blob. It is deliberately NOT a canonicalized re-encoding of the blob map:
//! canonical forms need both sides to agree on ordering, escaping, and
//! whitespace forever, and any drift there becomes a mysterious digest
//! mismatch. Committing to the exact bytes that were wrapped is well defined
//! with no such agreement, and it is also the thing that actually matters (the
//! daemon parses those bytes, so those bytes are what must be authentic).
//!
//! The wrapping key's public half is bound in so a wrong-key state is
//! diagnosable as a wrong key rather than surfacing as generic corruption.
//! Every field is length-prefixed, the same discipline as
//! [`crate::lease::grant_key`], so no two different inputs can serialize to one
//! byte string.
//!
//! **Not bound (recorded, not built):** the pairing container's device-id set.
//! An attacker who can write files could pair the daemon's material with an
//! older `pairing.json`. That is a file-write adversary, who under v2 can also
//! substitute a wholesale new keystore, so it changes no threat class; it is a
//! follow-up, not a hole this format closes.
//!
//! # Downgrade
//!
//! The defence against "swap the v2 file for a plaintext v1 and watch the
//! daemon happily adopt it" cannot live inside the file being swapped. It lives
//! in a separate marker ([`adopted_marker_path`]) the daemon writes when it
//! first serves a v2 store. Seeing v1 while that marker is present is a
//! downgrade: the daemon refuses to serve and says so loudly.
//!
//! Honest residual: the marker is a same-UID file, so the same attacker who
//! swaps the keystore can delete the marker. It stops accidents and unsigned
//! opportunists, not a determined local attacker. The independent alarm is on
//! the app side, whose Secure Enclave key still exists and whose UI can say the
//! store is no longer wrapped.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use zeroize::Zeroizing;

type Blake2b256 = Blake2b<U32>;

/// Domain tag for [`digest`]. Both sides of the contract hash this exact string.
const DIGEST_DOMAIN: &[u8] = b"sigil.keystore.v2";

/// The wrapped keystore has exactly two states a human ever sees, and they are
/// worded identically on every surface: the `sigil status` row, `sigil keystore
/// status`, and the Mac app's pill. Naming them here rather than spelling them
/// per surface is what stops the drift a reader has to reconcile ("sealed" in one
/// place, "sealed, not open" in another, a third phrasing in the app).
///
/// The distinction they carry is the only one that matters operationally: OPEN
/// means everything works, NOT OPEN means every gated command fails closed until
/// the app is running.
pub const STATE_OPEN: &str = "Sealed, open";
pub const STATE_NOT_OPEN: &str = "Sealed, not open";

/// The wrapped-file version. `1` is the historical plaintext form, which carries
/// no `v` field at all.
const V2: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("keystore file is not valid JSON: {0}")]
    Json(String),
    #[error("keystore file is v{0}, which this build does not understand")]
    Version(u32),
    #[error("keystore file is self-contradictory ({0}); refusing to guess")]
    Contradictory(&'static str),
    #[error("keystore field {0} is not valid base64")]
    Base64(&'static str),
    #[error("keystore pub_digest is not 32 bytes of hex")]
    Digest,
    #[error("keystore io: {0}")]
    Io(#[from] std::io::Error),
}

/// `BLAKE2b-256("sigil.keystore.v2" || len||se_pub || len||material)`.
///
/// See the module docs for why `material` is the exact wrapped bytes rather than
/// a canonicalized encoding.
pub fn digest(se_pub: &[u8], material: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(DIGEST_DOMAIN);
    h.update((se_pub.len() as u64).to_le_bytes());
    h.update(se_pub);
    h.update((material.len() as u64).to_le_bytes());
    h.update(material);
    h.finalize().into()
}

/// Lowercase hex of a digest.
pub fn digest_hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse 32 bytes from lowercase-or-uppercase hex.
fn digest_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Constant-time equality for digests. A digest comparison is an authentication
/// check, so it must not leak how far it matched through timing.
pub fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The on-disk keystore, as read once at startup.
pub enum KeystoreFile {
    /// The historical plaintext form. The bytes are the material itself.
    V1(Zeroizing<Vec<u8>>),
    /// The wrapped form. Holds no material: only the app can open `ciphertext`,
    /// and the daemon waits to be handed the plaintext at runtime.
    V2 {
        /// What the material must digest to once provisioned.
        pub_digest: [u8; 32],
        /// The wrapping key's public half (SPKI DER), bound into the digest.
        se_pub: Vec<u8>,
        /// The wrapped material. Opaque to the daemon.
        ciphertext: Vec<u8>,
    },
    /// No keystore file at all (a fresh install).
    Absent,
}

impl KeystoreFile {
    /// Read and classify the keystore at `path`. A missing file is
    /// [`KeystoreFile::Absent`], not an error: that is a fresh install.
    pub fn read(path: &Path) -> Result<Self, SealError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => Zeroizing::new(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(e) => return Err(SealError::Io(e)),
        };
        Self::parse(bytes)
    }

    /// Classify already-read bytes. Split out so the format is testable without
    /// touching a filesystem.
    pub fn parse(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SealError> {
        /// Just enough of the file to classify it.
        ///
        /// Deliberately NOT `serde_json::Value`: a full parse of a v1 file
        /// materializes every blob's base64 into `String`s that are dropped
        /// un-zeroized, and classification only needs to know which keys are
        /// present. `IgnoredAny` skips the blob map without allocating it. The
        /// wrapped fields are small and public (a digest, a public key, a
        /// ciphertext), so holding those as strings costs nothing.
        #[derive(serde::Deserialize)]
        struct Shape {
            v: Option<u64>,
            blobs: Option<serde::de::IgnoredAny>,
            ciphertext: Option<String>,
            pub_digest: Option<String>,
            se_pub: Option<String>,
        }

        let shape: Shape =
            serde_json::from_slice(&bytes).map_err(|e| SealError::Json(e.to_string()))?;

        let version = shape.v;
        let has_blobs = shape.blobs.is_some();
        let has_ct = shape.ciphertext.is_some();

        match version {
            // Wrapped. Must carry the wrapped fields and must NOT carry plaintext.
            Some(2) => {
                if has_blobs {
                    return Err(SealError::Contradictory(
                        "a wrapped file also carries plaintext blobs",
                    ));
                }
                let pub_digest = shape
                    .pub_digest
                    .as_deref()
                    .and_then(digest_from_hex)
                    .ok_or(SealError::Digest)?;
                let b64 = base64::engine::general_purpose::STANDARD;
                let se_pub = shape
                    .se_pub
                    .as_deref()
                    .ok_or(SealError::Base64("se_pub"))
                    .and_then(|s| b64.decode(s).map_err(|_| SealError::Base64("se_pub")))?;
                let ciphertext = shape
                    .ciphertext
                    .as_deref()
                    .ok_or(SealError::Base64("ciphertext"))
                    .and_then(|s| b64.decode(s).map_err(|_| SealError::Base64("ciphertext")))?;
                Ok(Self::V2 {
                    pub_digest,
                    se_pub,
                    ciphertext,
                })
            }
            // Plaintext, whether or not it says so. It must not carry wrapped
            // fields: a file claiming both is refused rather than guessed at.
            None | Some(1) => {
                if has_ct || shape.pub_digest.is_some() {
                    return Err(SealError::Contradictory(
                        "a plaintext file also carries wrapped fields",
                    ));
                }
                if !has_blobs {
                    return Err(SealError::Contradictory("no blobs and no wrapping"));
                }
                Ok(Self::V1(bytes))
            }
            Some(other) => Err(SealError::Version(other as u32)),
        }
    }

    /// True for the wrapped form.
    pub fn is_wrapped(&self) -> bool {
        matches!(self, Self::V2 { .. })
    }
}

/// Serialize a v2 file body. The daemon never writes one (S1: while wrapped,
/// only the app writes the keystore); this exists for tests and for the
/// unwrap/adopt round trip's assertions.
pub fn render_v2(pub_digest: &[u8; 32], se_pub: &[u8], ciphertext: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({
        "v": V2,
        "pub_digest": digest_hex(pub_digest),
        "se_pub": b64.encode(se_pub),
        "ciphertext": b64.encode(ciphertext),
    })
    .to_string()
}

/// `~/.sigil/adopted`: present exactly when this machine has served a wrapped
/// keystore. See the module docs for what it defends and what it does not.
pub fn adopted_marker_path() -> Option<PathBuf> {
    crate::paths::sigil_home().map(|h| h.join("adopted"))
}

/// Whether the adoption marker is present.
pub fn is_adopted() -> bool {
    adopted_marker_path().map(|p| p.exists()).unwrap_or(false)
}

/// What the adoption marker recorded when this machine first served a wrapped
/// store: which Enclave key the store was wrapped to, and when.
///
/// The `se_pub` is the load-bearing field. Without comparing it, "this machine is
/// adopted" only says a wrapped file is expected, not WHICH one, and a file
/// re-wrapped to somebody else's Enclave key satisfies that just as well as the
/// real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionMarker {
    pub se_pub: Vec<u8>,
    pub adopted_at_ms: u64,
}

/// Read the adoption marker, or `None` when this machine has never served a
/// wrapped store.
///
/// A marker that exists but cannot be parsed returns `Some` with an EMPTY
/// `se_pub`, deliberately: "adopted, key unknown" must not decay into "never
/// adopted", or corrupting one small file would be a way to clear the downgrade
/// tripwire. An empty recorded key compares unequal to any real one, so it
/// resolves to a refusal rather than to silent acceptance.
pub fn read_adoption_marker() -> Option<AdoptionMarker> {
    let path = adopted_marker_path()?;
    let bytes = std::fs::read(&path).ok()?;
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
    let se_pub = parsed
        .as_ref()
        .and_then(|v| v.get("se_pub"))
        .and_then(serde_json::Value::as_str)
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .unwrap_or_default();
    let adopted_at_ms = parsed
        .as_ref()
        .and_then(|v| v.get("adopted_at_ms"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    Some(AdoptionMarker {
        se_pub,
        adopted_at_ms,
    })
}

/// Record that this machine serves a wrapped keystore. Written after a
/// successful provision, so a later plaintext file is recognizable as a
/// downgrade. Best effort: a failure is logged by the caller and does not stop
/// the daemon (the marker is a tripwire, not a gate).
pub fn set_adopted(se_pub: &[u8]) -> Result<(), SealError> {
    let Some(path) = adopted_marker_path() else {
        return Ok(());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = serde_json::json!({
        "adopted_at_ms": sigil_proto::now_ms(),
        "se_pub": b64.encode(se_pub),
    })
    .to_string();
    write_private(&path, body.as_bytes())
}

/// Remove the adoption marker. Only the sanctioned de-adoption path calls this,
/// atomically with the plaintext write (see `unwrap`).
pub fn clear_adopted() -> Result<(), SealError> {
    let Some(path) = adopted_marker_path() else {
        return Ok(());
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SealError::Io(e)),
    }
}

/// Write `bytes` to `path` 0600, durably: a temp file in the same directory,
/// fsynced, then renamed over the target. The rename is atomic, so a crash
/// leaves either the old file or the new one, never a truncated one.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SealError> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "sigil".into()),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(bytes)?;
        // Durability before visibility: the bytes must be on the platter before
        // anything (a rename, a deletion of the source) depends on them.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// What the daemon resolved about its keystore at startup, held for the process
/// lifetime. Read ONCE, before the control socket listens, and never refreshed:
/// re-reading would let a file swapped mid-run become authoritative, and every
/// later question (status, doctor, a provision's digest check) must be answered
/// from the same snapshot the daemon armed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealState {
    /// A plaintext store (or a fresh install), never adopted. Business as usual.
    Plain,
    /// A wrapped store. The daemon serves nothing until the app provisions it.
    Sealed { expected: [u8; 32], se_pub: Vec<u8> },
    /// A plaintext store on a machine that has served a wrapped one. Treated as
    /// an attack until a human says otherwise: the daemon refuses to serve.
    Downgraded,
    /// A wrapped store, but wrapped to a DIFFERENT Enclave key than the one this
    /// machine adopted. The file is well formed and an app somewhere can open it;
    /// the point is that it is not the app this machine agreed to.
    ///
    /// Without this, substituting a keystore wrapped to an attacker's key is
    /// indistinguishable from the real one: it resolves `Sealed` with the
    /// attacker's digest, their app provisions it, and the daemon comes up paired
    /// to their phone with nothing anywhere reporting a change. The evidence to
    /// catch it was already on disk (the marker records the key), so refusing to
    /// compare it was the whole gap.
    KeyChanged,
}

impl SealState {
    /// Classify `file` against the adoption marker.
    ///
    /// `marker` is `None` when this machine has never served a wrapped store.
    /// When it is present, its recorded `se_pub` is what a wrapped file must be
    /// wrapped to; anything else is [`SealState::KeyChanged`].
    pub fn resolve(file: &KeystoreFile, marker: Option<&AdoptionMarker>) -> Self {
        match (file, marker) {
            (
                KeystoreFile::V2 {
                    pub_digest, se_pub, ..
                },
                Some(m),
            ) => {
                if se_pub == &m.se_pub {
                    SealState::Sealed {
                        expected: *pub_digest,
                        se_pub: se_pub.clone(),
                    }
                } else {
                    SealState::KeyChanged
                }
            }
            // Wrapped, and this machine has adopted nothing yet: the ordinary
            // first-run state (the app wraps, then provisions, then the marker is
            // written). There is no recorded key to compare against, and the
            // digest check on provision still stands.
            (
                KeystoreFile::V2 {
                    pub_digest, se_pub, ..
                },
                None,
            ) => SealState::Sealed {
                expected: *pub_digest,
                se_pub: se_pub.clone(),
            },
            // Plaintext where wrapped was promised.
            (KeystoreFile::V1(_) | KeystoreFile::Absent, Some(_)) => SealState::Downgraded,
            (KeystoreFile::V1(_) | KeystoreFile::Absent, None) => SealState::Plain,
        }
    }

    /// True when the daemon must refuse to serve gated work: a sealed store that
    /// has not been provisioned, or a downgrade.
    pub fn blocks_serving(&self, provisioned: bool) -> bool {
        match self {
            SealState::Plain => false,
            SealState::Sealed { .. } => !provisioned,
            SealState::Downgraded | SealState::KeyChanged => true,
        }
    }

    /// The one line `status`, `doctor`, and the daemon log all use, so the
    /// explanation never drifts between surfaces. Deliberately never says
    /// anything resembling "no pairing" or "re-pair": under a sealed store the
    /// pairing is intact and untouched, and telling a human to re-pair here
    /// would destroy a working pairing to fix a running-app problem.
    pub fn explain(&self, provisioned: bool) -> Option<&'static str> {
        match self {
            SealState::Plain => None,
            SealState::Sealed { .. } if provisioned => None,
            SealState::Sealed { .. } => Some(
                "keystore sealed; the Sigil app must be running to open it. \
                 Your pairing is intact: nothing here needs re-pairing.",
            ),
            SealState::Downgraded => Some(
                "keystore downgraded: this machine served a sealed keystore and now \
                 finds a plaintext one. Refusing to serve. If you de-adopted on \
                 purpose, run: sigil keystore unwrap --confirm",
            ),
            SealState::KeyChanged => Some(
                "keystore sealed to a DIFFERENT Secure Enclave key than this machine \
                 adopted. Refusing to serve. Nothing legitimate re-wraps a keystore \
                 to another key; treat this as a substituted keystore file until you \
                 know otherwise.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_bytes() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(br#"{"blobs":{"pairing.daemon-identity.v1":"AAAA"}}"#.to_vec())
    }

    #[test]
    fn the_digest_is_domain_separated_and_length_prefixed() {
        let a = digest(b"pubkey", b"material");
        // The domain tag is in the hash, so this is not a bare BLAKE2b.
        let bare: [u8; 32] = Blake2b256::digest(b"pubkeymaterial").into();
        assert_ne!(a, bare);

        // Length prefixing: no shifting of the boundary between the two fields
        // can produce the same input. Without prefixes these two would collide.
        assert_ne!(
            digest(b"pub", b"keymaterial"),
            digest(b"pubkey", b"material")
        );

        // Both fields matter, and the function is deterministic.
        assert_eq!(a, digest(b"pubkey", b"material"));
        assert_ne!(a, digest(b"other", b"material"));
        assert_ne!(a, digest(b"pubkey", b"other"));
    }

    #[test]
    fn digest_hex_round_trips_and_compares_in_constant_time() {
        let d = digest(b"k", b"m");
        let hex = digest_hex(&d);
        assert_eq!(hex.len(), 64);
        assert_eq!(digest_from_hex(&hex), Some(d));
        assert!(digests_equal(&d, &d));
        let mut other = d;
        other[31] ^= 1;
        assert!(!digests_equal(&d, &other));
        // A malformed hex string is refused, never truncated into a short key.
        assert_eq!(digest_from_hex("abc"), None);
        assert_eq!(digest_from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn a_v1_file_parses_as_plaintext_material() {
        let f = KeystoreFile::parse(v1_bytes()).unwrap();
        match &f {
            KeystoreFile::V1(bytes) => assert!(bytes.starts_with(b"{\"blobs\"")),
            _ => panic!("expected v1"),
        }
        assert!(!f.is_wrapped());
    }

    #[test]
    fn a_v2_file_parses_and_carries_no_material() {
        let d = digest(b"spki", b"material");
        let body = render_v2(&d, b"spki", b"ciphertext-bytes");
        let f = KeystoreFile::parse(Zeroizing::new(body.into_bytes())).unwrap();
        match f {
            KeystoreFile::V2 {
                pub_digest,
                se_pub,
                ciphertext,
            } => {
                assert_eq!(pub_digest, d);
                assert_eq!(se_pub, b"spki");
                assert_eq!(ciphertext, b"ciphertext-bytes");
            }
            _ => panic!("expected v2"),
        }
        // No `se_wrapped` field exists to disagree with the version.
        let rendered = render_v2(&d, b"spki", b"ct");
        assert!(!rendered.contains("se_wrapped"));
    }

    #[test]
    fn contradictory_files_are_refused_rather_than_guessed_at() {
        let cases: [&str; 4] = [
            // Wrapped, but also carrying plaintext.
            r#"{"v":2,"pub_digest":"00","se_pub":"","ciphertext":"","blobs":{}}"#,
            // Plaintext, but also carrying wrapped fields.
            r#"{"blobs":{},"ciphertext":"AA"}"#,
            // Neither.
            r#"{"something":1}"#,
            // A version from the future.
            r#"{"v":9,"blobs":{}}"#,
        ];
        for body in cases {
            // Matched rather than `expect_err`: `KeystoreFile` deliberately has
            // no `Debug`, because its v1 arm holds the material itself and a
            // derived Debug is one stray `{:?}` away from logging a secret.
            let err = match KeystoreFile::parse(Zeroizing::new(body.as_bytes().to_vec())) {
                Err(e) => e,
                Ok(_) => panic!("must refuse: {body}"),
            };
            assert!(
                matches!(
                    err,
                    SealError::Contradictory(_) | SealError::Version(_) | SealError::Digest
                ),
                "unexpected error for {body}: {err}"
            );
        }
    }

    #[test]
    fn a_malformed_wrapped_file_fails_closed() {
        // A short digest, bad base64, and outright garbage must all error, never
        // parse into a partially-trusted state.
        for body in [
            r#"{"v":2,"pub_digest":"nothex","se_pub":"AA==","ciphertext":"AA=="}"#,
            r#"{"v":2,"pub_digest":"aa","se_pub":"AA==","ciphertext":"AA=="}"#,
            r#"{"v":2,"se_pub":"AA==","ciphertext":"AA=="}"#,
            "not json at all",
        ] {
            assert!(KeystoreFile::parse(Zeroizing::new(body.as_bytes().to_vec())).is_err());
        }
    }

    /// A marker recording adoption to `key`.
    fn marker(key: &[u8]) -> AdoptionMarker {
        AdoptionMarker {
            se_pub: key.to_vec(),
            adopted_at_ms: 1,
        }
    }

    #[test]
    fn seal_state_reads_the_file_and_the_marker_together() {
        let d = [7u8; 32];
        let wrapped = KeystoreFile::V2 {
            pub_digest: d,
            se_pub: b"spki".to_vec(),
            ciphertext: b"ct".to_vec(),
        };
        // First run: wrapped, nothing adopted yet. This is the ordinary state
        // between the app wrapping the file and the daemon writing the marker.
        assert_eq!(
            SealState::resolve(&wrapped, None),
            SealState::Sealed {
                expected: d,
                se_pub: b"spki".to_vec()
            }
        );
        // Adopted to the SAME key: still the healthy sealed state.
        assert!(matches!(
            SealState::resolve(&wrapped, Some(&marker(b"spki"))),
            SealState::Sealed { .. }
        ));

        // Plaintext is normal until this machine has served a wrapped store.
        let plain = KeystoreFile::V1(v1_bytes());
        assert_eq!(SealState::resolve(&plain, None), SealState::Plain);
        assert_eq!(
            SealState::resolve(&plain, Some(&marker(b"spki"))),
            SealState::Downgraded
        );
        // And a file that VANISHED while adopted is a downgrade too, not a
        // fresh install: "no keystore" must not become a way to reset the gate.
        assert_eq!(
            SealState::resolve(&KeystoreFile::Absent, Some(&marker(b"spki"))),
            SealState::Downgraded
        );
        assert_eq!(
            SealState::resolve(&KeystoreFile::Absent, None),
            SealState::Plain
        );
    }

    #[test]
    fn a_keystore_wrapped_to_another_enclave_key_is_refused() {
        // The substitution this catches: a well-formed v2 file wrapped to an
        // ATTACKER's Enclave key. Its digest is internally consistent, their app
        // can open it, and provisioning would succeed, so nothing downstream
        // notices. The only evidence is that it is not the key this machine
        // adopted, and the marker has been recording that all along.
        let theirs = KeystoreFile::V2 {
            pub_digest: [9u8; 32],
            se_pub: b"attacker-spki".to_vec(),
            ciphertext: b"ct".to_vec(),
        };
        let state = SealState::resolve(&theirs, Some(&marker(b"our-spki")));
        assert_eq!(state, SealState::KeyChanged);
        assert!(
            state.blocks_serving(true),
            "a substituted keystore must serve nothing, provisioned or not"
        );
        let why = state.explain(true).expect("it explains itself");
        assert!(why.contains("DIFFERENT Secure Enclave key"), "{why}");
        assert!(why.contains("Refusing to serve"), "{why}");
        // And it must not read as the ordinary not-open state, which would send
        // someone to launch the app rather than look at the file.
        assert!(!why.contains("must be running"), "{why}");

        // An unparseable marker records adoption with an empty key, which cannot
        // equal any real one: corrupting that file is not a way to clear the gate.
        assert_eq!(
            SealState::resolve(&theirs, Some(&marker(b""))),
            SealState::KeyChanged
        );
    }

    #[test]
    fn only_a_provisioned_seal_serves_and_a_downgrade_never_does() {
        assert!(!SealState::Plain.blocks_serving(false));
        let sealed = SealState::Sealed {
            expected: [0u8; 32],
            se_pub: Vec::new(),
        };
        assert!(
            sealed.blocks_serving(false),
            "unprovisioned seal serves nothing"
        );
        assert!(!sealed.blocks_serving(true), "provisioned seal serves");
        assert!(
            SealState::Downgraded.blocks_serving(true),
            "a downgrade never serves"
        );
    }

    #[test]
    fn the_sealed_explanation_never_tells_anyone_to_re_pair() {
        // The failure mode this wording exists to prevent: a human whose app is
        // simply not running being told their pairing is gone, and destroying a
        // working pairing to "fix" it.
        let sealed = SealState::Sealed {
            expected: [0u8; 32],
            se_pub: Vec::new(),
        };
        let msg = sealed
            .explain(false)
            .expect("an unprovisioned seal explains itself");
        assert!(msg.contains("keystore sealed"));
        assert!(msg.contains("Sigil app must be running"));
        assert!(
            !msg.to_lowercase().contains("re-pair")
                || msg.contains("nothing here needs re-pairing")
        );
        assert!(!msg.to_lowercase().contains("no pairing"));
        assert!(
            sealed.explain(true).is_none(),
            "a provisioned seal is quiet"
        );
        assert!(SealState::Plain.explain(false).is_none());

        let down = SealState::Downgraded.explain(true).unwrap();
        assert!(down.contains("downgraded"));
        assert!(down.contains("sigil keystore unwrap"));
    }

    #[test]
    fn write_private_is_atomic_and_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sigil-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thing.json");
        write_private(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // Replacing leaves no temp file behind and no partial content.
        write_private(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "the temp file is renamed, never left");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }
}
