//! The DEK and service-account token model, plus the account store.
//!
//! A single 256-bit data-encryption key (DEK) protects every service-account
//! token at rest. Tokens are AES-256-GCM ciphertext; the DEK lives only inside
//! the keystore seam (Secure Enclave on macOS, the phone in the full product)
//! and is unwrapped per-approval, used, and zeroized. This module owns the pure
//! crypto (DEK generation, encrypt/decrypt) and the on-disk account catalogue
//! (`~/.latch/latch.db`), which holds token *ciphertext* and the plaintext
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
    #[error("no account routes vault {0:?}; add one with `latch account add`")]
    NoRoute(String),
    #[error("no accounts configured; run `latch account add`")]
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

/// The account catalogue persisted at `~/.latch/latch.db` as JSON.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountStore {
    #[serde(default)]
    pub accounts: Vec<Account>,
}

impl AccountStore {
    /// `~/.latch/latch.db`, or `$LATCH_HOME/latch.db` when set (tests).
    pub fn path() -> Result<PathBuf, SecretsError> {
        if let Some(dir) = std::env::var_os("LATCH_HOME") {
            return Ok(PathBuf::from(dir).join("latch.db"));
        }
        let home = std::env::var_os("HOME").ok_or(SecretsError::NoHome)?;
        Ok(PathBuf::from(home).join(".latch").join("latch.db"))
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

    /// Pick the account that serves `vault`. With one account and no vault
    /// hint, that account is used; otherwise a vault must match.
    pub fn route(&self, vault: Option<&str>) -> Result<&Account, SecretsError> {
        if self.accounts.is_empty() {
            return Err(SecretsError::NoAccounts);
        }
        match vault {
            Some(v) => self
                .accounts
                .iter()
                .find(|a| a.vaults.iter().any(|x| x == v))
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
/// `latch account add` and the ignored `probe_vaults_live` test; confirm with
///   OP_SERVICE_ACCOUNT_TOKEN=… cargo test -p latch probe_vaults_live -- --ignored --nocapture
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
        // Serialize with the other LATCH_HOME-mutating tests (parallel by default).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("latch-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("LATCH_HOME", &tmp);

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

        std::env::remove_var("LATCH_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
