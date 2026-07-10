//! The DEK and service-account token model, plus the account store.
//!
//! A single 256-bit data-encryption key (DEK) protects every service-account
//! token at rest. Tokens are AES-256-GCM ciphertext; the DEK lives only inside
//! the keystore seam (Secure Enclave on macOS, the phone in the full product)
//! and is unwrapped per-approval, used, and zeroized. This module owns the pure
//! crypto (DEK generation, encrypt/decrypt) and the on-disk account catalogue
//! (`~/.sigil/sigil.db`), which holds token *ciphertext* and the plaintext
//! vault-routing list only. No plaintext token is ever written to disk, and
//! every decrypted buffer is `Zeroizing`.

use std::path::PathBuf;
use std::process::Command;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A 256-bit data-encryption key. Wrapped so the plaintext key is wiped on drop
/// no matter which path holds it.
pub type Dek = Zeroizing<[u8; 32]>;

/// A decrypted service-account token. Wiped on drop; never serialized.
pub type Token = Zeroizing<Vec<u8>>;

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// AEAD seal/open failed. For `decrypt` this means a wrong DEK or tampered
    /// ciphertext; the message never carries plaintext.
    #[error("aead operation failed (wrong key or tampered ciphertext)")]
    Aead,
    /// Stored ciphertext is shorter than the nonce prefix.
    #[error("token ciphertext truncated")]
    Truncated,
    #[error("account store io: {0}")]
    Io(#[from] std::io::Error),
    #[error("account store json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("no account routes vault {0:?}; add one with `sigil account add`")]
    NoRoute(String),
    #[error("no accounts configured; run `sigil account add`")]
    NoAccounts,
    #[error("account {0:?} already exists")]
    Duplicate(String),
    #[error("HOME is not set")]
    NoHome,
}

/// Generate a fresh 256-bit DEK from the platform CSPRNG.
pub fn generate_dek() -> Dek {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut key[..]);
    key
}

/// AES-256-GCM seal a token under `dek`. Output is `nonce || ciphertext||tag`;
/// the nonce is random per call. The returned bytes are ciphertext and are safe
/// to persist.
pub fn encrypt_token(dek: &Dek, plaintext: &[u8]) -> Result<Vec<u8>, SecretsError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek[..]));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| SecretsError::Aead)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM open a token sealed by [`encrypt_token`]. The plaintext lands in
/// a `Zeroizing` buffer so it is wiped on drop.
pub fn decrypt_token(dek: &Dek, blob: &[u8]) -> Result<Token, SecretsError> {
    if blob.len() < NONCE_LEN {
        return Err(SecretsError::Truncated);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek[..]));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| SecretsError::Aead)?;
    Ok(Zeroizing::new(pt))
}

/// One 1Password service account: a label, its token ciphertext, and the
/// plaintext list of vaults it can route (used to pick the account for a
/// request without ever touching the token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub label: String,
    /// `nonce || ciphertext` from [`encrypt_token`], base64 for JSON.
    pub token_b64: String,
    /// Vault names this account can serve. Plaintext by design: routing must
    /// work while the daemon is inert.
    #[serde(default)]
    pub vaults: Vec<String>,
}

impl Account {
    /// The raw token ciphertext bytes.
    pub fn ciphertext(&self) -> Result<Vec<u8>, SecretsError> {
        Ok(B64.decode(self.token_b64.as_bytes())?)
    }
}

/// One inline-`env` source's sealed values. The KEY *names* live in the config
/// (`config.json`, public) and drive the zero-knowledge readout; only the
/// **values** live here, and only as ciphertext. `blob` is `nonce || ciphertext`
/// from [`encrypt_token`] over the serialized `{KEY: VALUE}` map (see
/// `provider::encode_env_pairs`), base64 for JSON — sealed under the very same
/// DEK a service-account token is, so the daemon-at-rest holds no plaintext value
/// (invariant #1). Keyed by the source's `name`, mirroring an account's `label`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnv {
    /// The [`crate::config::Source::name`] this blob backs.
    pub name: String,
    /// `nonce || ciphertext` from [`encrypt_token`], base64 for JSON.
    pub blob_b64: String,
}

impl SealedEnv {
    /// The raw sealed blob bytes (`nonce || ciphertext`).
    pub fn ciphertext(&self) -> Result<Vec<u8>, SecretsError> {
        Ok(B64.decode(self.blob_b64.as_bytes())?)
    }
}

/// The account catalogue persisted at `~/.sigil/sigil.db` as JSON. It also holds
/// the inline-`env` sources' sealed value blobs ([`SealedEnv`]) — the same
/// encrypted store the tokens use, reused rather than a parallel one, so both the
/// token and the inline-env at-rest guarantees are enforced by one DEK.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountStore {
    #[serde(default)]
    pub accounts: Vec<Account>,
    /// Inline-`env` sealed value blobs, keyed by source name. Ciphertext only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_sources: Vec<SealedEnv>,
}

impl AccountStore {
    /// `~/.sigil/sigil.db`, or `$SIGIL_HOME/sigil.db` when set (tests).
    pub fn path() -> Result<PathBuf, SecretsError> {
        if let Some(dir) = std::env::var_os("SIGIL_HOME") {
            return Ok(PathBuf::from(dir).join("sigil.db"));
        }
        let home = std::env::var_os("HOME").ok_or(SecretsError::NoHome)?;
        Ok(PathBuf::from(home).join(".sigil").join("sigil.db"))
    }

    /// Load the store, returning an empty one if the file does not exist.
    pub fn load() -> Result<Self, SecretsError> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the store, creating the parent dir 0700 and the file 0600.
    pub fn save(&self) -> Result<(), SecretsError> {
        use std::os::unix::fs::PermissionsExt;
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, json)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Encrypt `token` under `dek` and add it as `label`. Rejects duplicates.
    pub fn add(
        &mut self,
        label: &str,
        dek: &Dek,
        token: &[u8],
        vaults: Vec<String>,
    ) -> Result<(), SecretsError> {
        if self.accounts.iter().any(|a| a.label == label) {
            return Err(SecretsError::Duplicate(label.to_string()));
        }
        let ct = encrypt_token(dek, token)?;
        self.accounts.push(Account {
            label: label.to_string(),
            token_b64: B64.encode(ct),
            vaults,
        });
        Ok(())
    }

    /// Re-encrypt `token` under `dek` for the existing account `label`,
    /// replacing its ciphertext and (when non-empty) its probed vault routing.
    /// Errors if no account has that label.
    pub fn rotate(
        &mut self,
        label: &str,
        dek: &Dek,
        token: &[u8],
        vaults: Vec<String>,
    ) -> Result<(), SecretsError> {
        let ct = encrypt_token(dek, token)?;
        let acct = self
            .accounts
            .iter_mut()
            .find(|a| a.label == label)
            .ok_or_else(|| SecretsError::NoRoute(label.to_string()))?;
        acct.token_b64 = B64.encode(ct);
        if !vaults.is_empty() {
            acct.vaults = vaults;
        }
        Ok(())
    }

    /// Remove the account with `label`. Returns true if one was removed.
    pub fn remove(&mut self, label: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.label != label);
        self.accounts.len() != before
    }

    /// Seal `ciphertext` (already `nonce || ciphertext` from [`encrypt_token`])
    /// as the inline-`env` blob for source `name`, replacing any existing one.
    /// The caller does the encrypt (it holds the DEK); this store only ever holds
    /// the sealed bytes, never a plaintext value.
    pub fn set_env_blob(&mut self, name: &str, ciphertext: &[u8]) {
        let blob_b64 = B64.encode(ciphertext);
        if let Some(existing) = self.env_sources.iter_mut().find(|e| e.name == name) {
            existing.blob_b64 = blob_b64;
        } else {
            self.env_sources.push(SealedEnv {
                name: name.to_string(),
                blob_b64,
            });
        }
    }

    /// The sealed blob bytes for inline-`env` source `name`, if one is stored.
    /// `Some(Err(..))` only on a corrupt (non-base64) record. The daemon decrypts
    /// this after approval; nothing here is ever plaintext.
    pub fn env_blob(&self, name: &str) -> Option<Result<Vec<u8>, SecretsError>> {
        self.env_sources
            .iter()
            .find(|e| e.name == name)
            .map(SealedEnv::ciphertext)
    }

    /// Remove the sealed blob for inline-`env` source `name`. Returns true if one
    /// was removed. Called when a key is unset to empty, or the source is removed,
    /// so no orphaned secret ciphertext outlives its source.
    pub fn remove_env_blob(&mut self, name: &str) -> bool {
        let before = self.env_sources.len();
        self.env_sources.retain(|e| e.name != name);
        self.env_sources.len() != before
    }

    /// Pick the account for a routing `hint`. The hint is a source's configured
    /// account label or a vault name: an account matches when its **label** or
    /// one of its **vaults** equals the hint (config now routes by the source's
    /// account label, not by argv archaeology; a vault name still works so a
    /// migrated store keeps routing). With one account and no hint, that account
    /// is used; otherwise a hint must match.
    pub fn route(&self, hint: Option<&str>) -> Result<&Account, SecretsError> {
        if self.accounts.is_empty() {
            return Err(SecretsError::NoAccounts);
        }
        match hint {
            Some(v) => self
                .accounts
                .iter()
                .find(|a| a.label == v || a.vaults.iter().any(|x| x == v))
                .or_else(|| {
                    // Fall back to the sole account so a vault we have not yet
                    // catalogued still routes rather than failing closed here;
                    // the approval itself remains the gate.
                    (self.accounts.len() == 1).then(|| &self.accounts[0])
                })
                .ok_or_else(|| SecretsError::NoRoute(v.to_string())),
            None if self.accounts.len() == 1 => Ok(&self.accounts[0]),
            None => Ok(&self.accounts[0]),
        }
    }
}

/// Vaults 1Password reports for a service-account `token`, via `op vault list`
/// with the token in the child env. Service accounts cannot see the built-in
/// Personal/Shared vaults (a platform limit), so an empty list means the token
/// can serve nothing useful yet.
///
/// NEEDS-VERIFICATION: requires a live `op` and network. Exercised by
/// `sigil account add` and the ignored `probe_vaults_live` test; confirm with
///   OP_SERVICE_ACCOUNT_TOKEN=… cargo test -p sigil probe_vaults_live -- --ignored --nocapture
pub fn probe_vaults(op: &std::path::Path, token: &[u8]) -> Result<Vec<String>, SecretsError> {
    #[derive(Deserialize)]
    struct VaultRow {
        name: String,
    }
    let out = Command::new(op)
        .args(["vault", "list", "--format=json"])
        .env(
            "OP_SERVICE_ACCOUNT_TOKEN",
            String::from_utf8_lossy(token).as_ref(),
        )
        .output()?;
    if !out.status.success() {
        // Surface no vaults rather than the token-bearing stderr.
        return Ok(Vec::new());
    }
    let rows: Vec<VaultRow> = serde_json::from_slice(&out.stdout).unwrap_or_default();
    Ok(rows.into_iter().map(|r| r.name).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dek_is_random_each_call() {
        let a = generate_dek();
        let b = generate_dek();
        assert_ne!(*a, *b, "two DEKs collided (broken CSPRNG)");
    }

    #[test]
    fn encrypt_decrypt_roundtrips() {
        let dek = generate_dek();
        let token = b"ops_eyJzaWduSW5BZGRyZXNzIjoi.example.token";
        let ct = encrypt_token(&dek, token).unwrap();
        assert_ne!(&ct[NONCE_LEN..], token, "ciphertext equals plaintext");
        let pt = decrypt_token(&dek, &ct).unwrap();
        assert_eq!(&pt[..], token);
    }

    #[test]
    fn nonce_is_unique_so_ciphertext_differs() {
        let dek = generate_dek();
        let a = encrypt_token(&dek, b"same").unwrap();
        let b = encrypt_token(&dek, b"same").unwrap();
        assert_ne!(
            a, b,
            "nonce reuse: identical ciphertext for identical input"
        );
    }

    #[test]
    fn wrong_dek_fails_to_decrypt() {
        let ct = encrypt_token(&generate_dek(), b"secret").unwrap();
        let err = decrypt_token(&generate_dek(), &ct).unwrap_err();
        assert!(matches!(err, SecretsError::Aead));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let dek = generate_dek();
        let mut ct = encrypt_token(&dek, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            decrypt_token(&dek, &ct).unwrap_err(),
            SecretsError::Aead
        ));
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let dek = generate_dek();
        assert!(matches!(
            decrypt_token(&dek, &[0u8; 4]).unwrap_err(),
            SecretsError::Truncated
        ));
    }

    #[test]
    fn store_add_route_and_reject_duplicate() {
        let dek = generate_dek();
        let mut store = AccountStore::default();
        store
            .add("Rowm work", &dek, b"tok-rowm", vec!["Engineering".into()])
            .unwrap();
        store
            .add("Personal", &dek, b"tok-personal", vec!["Private".into()])
            .unwrap();

        // Route by vault.
        let acct = store.route(Some("Engineering")).unwrap();
        assert_eq!(acct.label, "Rowm work");
        let pt = decrypt_token(&dek, &acct.ciphertext().unwrap()).unwrap();
        assert_eq!(&pt[..], b"tok-rowm");

        // Duplicate label rejected.
        assert!(matches!(
            store.add("Personal", &dek, b"x", vec![]).unwrap_err(),
            SecretsError::Duplicate(_)
        ));

        // Unknown vault with multiple accounts fails closed on routing.
        assert!(matches!(
            store.route(Some("Nope")).unwrap_err(),
            SecretsError::NoRoute(_)
        ));
    }

    #[test]
    fn rotate_replaces_ciphertext_and_remove_drops_the_account() {
        let dek = generate_dek();
        let mut store = AccountStore::default();
        store
            .add("Rowm", &dek, b"old-token", vec!["Engineering".into()])
            .unwrap();

        // Rotate installs a new token; the old vault routing is kept when the
        // rotate passes an empty probe.
        store.rotate("Rowm", &dek, b"new-token", vec![]).unwrap();
        let acct = store.route(Some("Engineering")).unwrap();
        let pt = decrypt_token(&dek, &acct.ciphertext().unwrap()).unwrap();
        assert_eq!(&pt[..], b"new-token");
        assert_eq!(acct.vaults, vec!["Engineering".to_string()]);

        // Rotating an unknown account is an error.
        assert!(matches!(
            store.rotate("Nope", &dek, b"x", vec![]).unwrap_err(),
            SecretsError::NoRoute(_)
        ));

        // Remove drops it; a second remove is a no-op.
        assert!(store.remove("Rowm"));
        assert!(!store.remove("Rowm"));
        assert!(store.accounts.is_empty());
    }

    #[test]
    fn store_persists_ciphertext_only() {
        // Serialize with the other SIGIL_HOME-mutating tests (parallel by default).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("sigil-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("SIGIL_HOME", &tmp);

        let dek = generate_dek();
        let mut store = AccountStore::default();
        store
            .add(
                "Rowm work",
                &dek,
                b"super-secret-token",
                vec!["Engineering".into()],
            )
            .unwrap();
        store.save().unwrap();

        // The plaintext token must not appear on disk.
        let raw = std::fs::read(AccountStore::path().unwrap()).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("super-secret-token"),
            "plaintext token leaked into the account store"
        );

        let loaded = AccountStore::load().unwrap();
        let acct = loaded.route(Some("Engineering")).unwrap();
        let pt = decrypt_token(&dek, &acct.ciphertext().unwrap()).unwrap();
        assert_eq!(&pt[..], b"super-secret-token");

        std::env::remove_var("SIGIL_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn env_blob_is_ciphertext_at_rest_and_round_trips() {
        // The inline-env sealed blob must persist as ciphertext keyed by the
        // source name: the VALUE never appears on disk, only the (public) name and
        // the sealed bytes, and it decrypts+decodes back to the exact pairs.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("sigil-envblob-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("SIGIL_HOME", &tmp);

        let dek = generate_dek();
        let pairs = vec![
            (
                "API_KEY".to_string(),
                Zeroizing::new("super-secret-value-xyz".to_string()),
            ),
            ("REGION".to_string(), Zeroizing::new("eu".to_string())),
        ];
        let encoded = crate::provider::encode_env_pairs(&pairs);
        let ct = encrypt_token(&dek, &encoded).unwrap();
        let mut store = AccountStore::default();
        store.set_env_blob("deploy", &ct);
        store.save().unwrap();

        // At rest: the sealed VALUE must not appear; the source NAME (public) may.
        let raw = std::fs::read(AccountStore::path().unwrap()).unwrap();
        let raw = String::from_utf8_lossy(&raw);
        assert!(
            !raw.contains("super-secret-value-xyz"),
            "plaintext inline-env value leaked into the store"
        );
        assert!(raw.contains("deploy"), "the source name should be present");

        // Round-trip: load, open, decode, exact pairs back.
        let mut loaded = AccountStore::load().unwrap();
        let ct2 = loaded.env_blob("deploy").expect("blob present").unwrap();
        let plain = decrypt_token(&dek, &ct2).unwrap();
        let back = crate::provider::decode_env_pairs(&plain).unwrap();
        let map: std::collections::HashMap<_, _> = back
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        assert_eq!(map.get("API_KEY").unwrap(), "super-secret-value-xyz");
        assert_eq!(map.get("REGION").unwrap(), "eu");

        // Remove leaves no orphan.
        assert!(loaded.remove_env_blob("deploy"));
        assert!(loaded.env_blob("deploy").is_none());
        assert!(
            !loaded.remove_env_blob("deploy"),
            "second remove is a no-op"
        );

        std::env::remove_var("SIGIL_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
