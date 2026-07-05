//! The daemon (Mac) side of v2 threshold decryption: the Mac share `m`, the
//! pinned phone Secure-Enclave share `F`, the versioned v2 account store, and the
//! per-request combine that opens a token from `m` plus the phone's partial
//! `Z_F`. The shared crypto core (the combiner, the record format, the on-curve
//! validator) lives in [`latch_proto::threshold`]; this module is the daemon's
//! custody, persistence, and residency layer around it.
//!
//! Full design and the independent review (R1-R5) are in
//! `docs/design/threshold-v2.md`. The load-bearing daemon-side properties:
//!
//! * **`m` never leaves secure handling.** It is sealed in the platform keystore
//!   (login Keychain on macOS), and each request loads it into an mlock'd,
//!   zeroize-on-drop buffer for exactly one scalar multiplication, then drops it.
//!   It is never placed in a lease, never written to the plaintext config, and
//!   never assembled with `f` into a full private key.
//! * **`e` is destroyed at account-add.** [`seal_account`] mints a fresh unique
//!   `E = e·G` per account (R4), derives `K`, seals the token, and drops `e`
//!   (zeroized) as it returns. After that `Z_F = x(f·E)` is computable only by
//!   the phone's Secure Enclave (CDH).
//! * **The decrypt path is chosen by the at-rest record version (R3),** never by
//!   any field the phone or a relay supplied. A v2 account is only ever opened by
//!   the concatenative combiner; there is no DEK to downgrade to.
//! * **`K` is mlock'd and zeroized.** [`decrypt`] combines `Z_M` and `Z_F` into a
//!   page-locked `K`, opens the token, and wipes `K` immediately.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use latch_proto::threshold::{
    aead_open, all_ephemerals_unique, combine, EcdhAlgo, MacShare, P256Point, ThresholdError,
    ThresholdRecord, TOKEN_NONCE_LEN, XCOORD_LEN,
};

/// Keystore blob label under which the Mac share `m` (a 32-byte P-256 scalar) is
/// sealed. Versioned so a future key-format change can migrate cleanly.
pub const MAC_SHARE_LABEL: &str = "threshold.mac-share.v2";

/// The wire tag for an [`EcdhAlgo`], as the per-request challenge carries it to
/// the phone. Matches the serde `rename`s in [`latch_proto::threshold::EcdhAlgo`].
pub fn ecdh_algo_tag(algo: EcdhAlgo) -> &'static str {
    match algo {
        EcdhAlgo::RawX => "raw-x",
        EcdhAlgo::X963Sha256 => "x963-sha256",
    }
}

/// The default ECDH-output shape for a fresh v2 account. Raw X-coordinate is the
/// recommended Secure-Enclave output (design §3, NV-2); on hardware that refuses
/// raw key-agreement, account-add can pin [`EcdhAlgo::X963Sha256`] instead
/// (NV-7). The shape is stored per record, so the default only picks the initial
/// value, never the decrypt path.
pub const DEFAULT_ECDH_ALGO: EcdhAlgo = EcdhAlgo::RawX;

#[derive(Debug, thiserror::Error)]
pub enum ThresholdStoreError {
    #[error("threshold store io: {0}")]
    Io(#[from] std::io::Error),
    #[error("threshold store json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("keystore: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
    #[error("the stored Mac share is not a valid P-256 scalar; re-run v2 setup")]
    CorruptMacShare,
    #[error("no v2 account routes vault {0:?}; add one with `latch account add --threshold`")]
    NoRoute(String),
    #[error("v2 account {0:?} already exists")]
    Duplicate(String),
    #[error("a duplicate ephemeral base E across accounts breaks account separation (R4)")]
    DuplicateEphemeral,
    #[error("threshold crypto: {0}")]
    Crypto(#[from] ThresholdError),
    #[error("HOME is not set")]
    NoHome,
}

// ===========================================================================
// mlock: keep the Mac share and the combined key off swap and out of a core
// dump for the brief window they live in RAM.
//
// NV-9: mlock can fail under a tight `RLIMIT_MEMLOCK`. We degrade LOUDLY (an
// eprintln), never silently to un-pinned memory, and never fail the operation
// on it: the zeroize-on-drop guarantee still holds, mlock is defence in depth.
// ===========================================================================

/// A best-effort `mlock` over a byte region, released (`munlock`) on drop. The
/// region is the buffer the guard borrows; the caller keeps that buffer alive
/// for the guard's lifetime.
struct MlockGuard {
    ptr: *mut libc::c_void,
    len: usize,
    locked: bool,
}

impl MlockGuard {
    /// Lock the pages backing `buf`. Best effort: on failure it logs once and
    /// yields an inert guard (nothing to unlock), so callers need no branch.
    fn lock(buf: &[u8]) -> Self {
        if buf.is_empty() {
            return Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                locked: false,
            };
        }
        let ptr = buf.as_ptr() as *mut libc::c_void;
        let len = buf.len();
        // SAFETY: `ptr`/`len` describe a live borrow held for the guard's life.
        let rc = unsafe { libc::mlock(ptr, len) };
        if rc != 0 {
            eprintln!(
                "latch daemon: mlock of {len} bytes of threshold key material failed \
                 (RLIMIT_MEMLOCK?); the buffer is still zeroized on drop but not page-locked"
            );
            Self {
                ptr,
                len,
                locked: false,
            }
        } else {
            Self {
                ptr,
                len,
                locked: true,
            }
        }
    }
}

impl Drop for MlockGuard {
    fn drop(&mut self) {
        if self.locked {
            // SAFETY: same region we locked; the borrowed buffer is still alive.
            unsafe {
                libc::munlock(self.ptr, self.len);
            }
        }
    }
}

// ===========================================================================
// The Mac share m.
// ===========================================================================

/// Load the Mac share `m` from the keystore into an mlock'd, zeroize-on-drop
/// buffer, or `Ok(None)` if v2 setup has never run on this daemon. The scalar
/// bytes are page-locked for the moment they exist and wiped as this returns
/// (the [`MacShare`] keeps its own zeroize-on-drop copy).
pub fn load_mac_share(
    ks: &dyn crate::keystore::Keystore,
) -> Result<Option<MacShare>, ThresholdStoreError> {
    let Some(blob) = ks.load_blob(MAC_SHARE_LABEL)? else {
        return Ok(None);
    };
    let scalar = Zeroizing::new(blob);
    let _lock = MlockGuard::lock(&scalar);
    let m =
        MacShare::from_scalar_bytes(&scalar).map_err(|_| ThresholdStoreError::CorruptMacShare)?;
    Ok(Some(m))
}

/// Load the Mac share, generating and sealing a fresh one if absent (v2 setup /
/// first v2 account-add). Idempotent: an existing share is never rotated here.
/// The freshly minted scalar is mlock'd while it is written to the keystore.
pub fn load_or_create_mac_share(
    ks: &dyn crate::keystore::Keystore,
) -> Result<MacShare, ThresholdStoreError> {
    if let Some(m) = load_mac_share(ks)? {
        return Ok(m);
    }
    let m = MacShare::generate();
    let scalar = m.scalar_bytes();
    let _lock = MlockGuard::lock(&scalar[..]);
    ks.store_blob(MAC_SHARE_LABEL, &scalar[..])?;
    Ok(m)
}

/// True once the Mac share has been provisioned.
pub fn has_mac_share(ks: &dyn crate::keystore::Keystore) -> bool {
    matches!(ks.load_blob(MAC_SHARE_LABEL), Ok(Some(_)))
}

// ===========================================================================
// The pinned phone Secure-Enclave share F.
// ===========================================================================

/// The phone's Secure-Enclave key-agreement public key `F = f·G`, pinned at
/// pairing. `f` is non-exportable inside the phone's Secure Enclave; only `F` (a
/// public point) ever crosses the wire, and the Mac validates it on-curve (R2)
/// before persisting or using it. The account-add step wraps a token to this
/// point so only the holder of `f` can later produce `Z_F`.
#[derive(Clone, Debug)]
pub struct PhoneShare {
    /// Which SE key this is (a phone may hold more than one over re-pairs). Echoed
    /// into the per-request challenge so the phone selects the matching key.
    pub se_key_id: String,
    /// The validated on-curve point `F`.
    pub point: P256Point,
    /// Which SE ECDH output shape the phone will emit for this key (NV-2/NV-7).
    pub ecdh_algo: EcdhAlgo,
}

impl PhoneShare {
    /// Validate and pin a phone share from the ANSI X9.63 (65-byte) `F` the phone
    /// sent at pairing. Rejects an off-curve / malformed point (R2).
    pub fn from_x963(
        se_key_id: &str,
        f_x963: &[u8],
        ecdh_algo: EcdhAlgo,
    ) -> Result<Self, ThresholdError> {
        Ok(Self {
            se_key_id: se_key_id.to_string(),
            point: P256Point::from_x963(f_x963)?,
            ecdh_algo,
        })
    }
}

// ===========================================================================
// The versioned v2 account store.
// ===========================================================================

/// One v2 account: the sealed [`ThresholdRecord`] plus the plaintext vault
/// routing (the same routing model as v1's [`crate::secrets::Account`], so the
/// daemon can pick the account while inert). `record.account_id` is the label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdAccount {
    #[serde(flatten)]
    pub record: ThresholdRecord,
    /// Vault names this account can serve. Plaintext by design, exactly as v1.
    #[serde(default)]
    pub vaults: Vec<String>,
}

impl ThresholdAccount {
    /// The account label (its stable id, folded into the KDF).
    pub fn label(&self) -> &str {
        &self.record.account_id
    }
}

/// The v2 account catalogue, persisted at `~/.latch/threshold.db` as JSON. It
/// holds token *ciphertext* and the plaintext routing only; no `K`, no `Z_M`, no
/// `Z_F`, and crucially no `e`. It coexists with the v1
/// [`AccountStore`](crate::secrets::AccountStore): the two share the AES-256-GCM
/// token format and differ only in where the key comes from.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ThresholdStore {
    #[serde(default)]
    pub accounts: Vec<ThresholdAccount>,
}

impl ThresholdStore {
    /// `~/.latch/threshold.db`, or `$LATCH_HOME/threshold.db` when set (tests).
    pub fn path() -> Result<PathBuf, ThresholdStoreError> {
        if let Some(dir) = std::env::var_os("LATCH_HOME") {
            return Ok(PathBuf::from(dir).join("threshold.db"));
        }
        let home = std::env::var_os("HOME").ok_or(ThresholdStoreError::NoHome)?;
        Ok(PathBuf::from(home).join(".latch").join("threshold.db"))
    }

    /// Load the store, returning an empty one if the file does not exist.
    pub fn load() -> Result<Self, ThresholdStoreError> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the store 0600, creating the parent dir 0700. Enforces the R4
    /// invariant (all ephemeral bases distinct) before writing, so a store that
    /// would break the "one captured partial ⇒ one account" claim is never saved.
    pub fn save(&self) -> Result<(), ThresholdStoreError> {
        use std::os::unix::fs::PermissionsExt;
        let records: Vec<ThresholdRecord> =
            self.accounts.iter().map(|a| a.record.clone()).collect();
        if !all_ephemerals_unique(&records) {
            return Err(ThresholdStoreError::DuplicateEphemeral);
        }
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

    /// Look up a v2 account by label.
    pub fn get(&self, label: &str) -> Option<&ThresholdAccount> {
        self.accounts.iter().find(|a| a.label() == label)
    }

    /// Pick the v2 account whose vault list contains `vault` exactly, with no
    /// single-account fallback. Used when v1 accounts coexist (a migration
    /// store): v2 then claims only an exact match, leaving everything else to v1.
    pub fn route_exact(&self, vault: Option<&str>) -> Option<&ThresholdAccount> {
        let v = vault?;
        self.accounts
            .iter()
            .find(|a| a.vaults.iter().any(|x| x == v))
    }

    /// Pick the v2 account that serves `vault`, mirroring
    /// [`AccountStore::route`](crate::secrets::AccountStore::route): a matching
    /// vault wins; with a single account and no match it is the fallback; `None`
    /// means no v2 account serves this request (the caller then tries v1).
    pub fn route(&self, vault: Option<&str>) -> Option<&ThresholdAccount> {
        if self.accounts.is_empty() {
            return None;
        }
        match vault {
            Some(v) => self
                .accounts
                .iter()
                .find(|a| a.vaults.iter().any(|x| x == v))
                .or_else(|| (self.accounts.len() == 1).then(|| &self.accounts[0])),
            None => Some(&self.accounts[0]),
        }
    }

    /// Remove the v2 account with `label`. Returns true if one was removed.
    pub fn remove(&mut self, label: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.label() != label);
        self.accounts.len() != before
    }
}

/// Account-add (a Mac-only, human-present CLI ceremony; design §5). Mint a fresh
/// unique `E` (R4), derive `K` from the Mac share `m` and the pinned phone share
/// `F`, seal the token, and add the resulting v2 record to `store`. The ephemeral
/// `e`, `Z_M`, `Z_F`, and `K` are all transient inside
/// [`ThresholdRecord::seal`] and dropped (zeroized) as it returns; only the
/// public `E` survives in the record.
///
/// Rejects a duplicate label. The R4 uniqueness of `E` across the whole store is
/// re-checked on [`ThresholdStore::save`].
#[allow(clippy::too_many_arguments)]
pub fn seal_account(
    store: &mut ThresholdStore,
    label: &str,
    m: &MacShare,
    phone: &PhoneShare,
    token: &[u8],
    vaults: Vec<String>,
) -> Result<(), ThresholdStoreError> {
    if store.get(label).is_some() {
        return Err(ThresholdStoreError::Duplicate(label.to_string()));
    }
    let record = ThresholdRecord::seal(
        label,
        m,
        &phone.point,
        phone.ecdh_algo,
        &phone.se_key_id,
        token,
    )?;
    store.accounts.push(ThresholdAccount { record, vaults });
    Ok(())
}

/// The daemon's per-request decrypt (design §6, steps 9-13), with `K` page-locked
/// and wiped immediately. Given the Mac share `m` and the phone's partial
/// `Z_F = x(f·E)`, recompute `K = combine(Z_M, Z_F, E, account_id)` and open the
/// token. Fails closed if the record is not v2 (R3), if `E` is off-curve (R2), or
/// if `Z_F` is wrong/absent (the GCM tag fails). The token lands in a zeroize
/// buffer.
///
/// This mirrors [`ThresholdRecord::decrypt`] but keeps `Z_M`, `K` in mlock'd
/// memory rather than delegating the combine, so the daemon meets the residency
/// requirement for the combined key (design §10).
pub fn decrypt(
    record: &ThresholdRecord,
    m: &MacShare,
    zf: &[u8; XCOORD_LEN],
) -> Result<Zeroizing<Vec<u8>>, ThresholdStoreError> {
    // R3: never open anything that is not a v2 record.
    record.require_v2()?;
    // R2: the base point E is validated on-curve here before any scalar mult.
    let e_point = record.ephemeral_point()?;
    let e_x963 = e_point.as_x963();

    // Z_M = x(m·E), shaped per the record. Page-lock it for its brief life.
    let zm = m.partial(&e_point, record.ecdh_algo, e_x963);
    let _zm_lock = MlockGuard::lock(&zm[..]);

    // K = combine(Z_M, Z_F, E, account_id). Page-lock the combined key.
    let k = combine(&zm, zf, e_x963, &record.account_id);
    let _k_lock = MlockGuard::lock(&k[..]);

    let nonce_bytes = B64
        .decode(&record.aead_nonce)
        .map_err(|_| ThresholdError::Base64)?;
    let nonce: [u8; TOKEN_NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::TokenTruncated)?;
    let ct = B64
        .decode(&record.token_ct)
        .map_err(|_| ThresholdError::Base64)?;
    Ok(aead_open(&k, &nonce, &ct)?)
    // `zm`, `k` (and their mlock guards) drop here: munlock then zeroize.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{Keystore, MemoryKeystore};
    use latch_proto::threshold::THRESHOLD_RECORD_VERSION;

    const TOKEN: &[u8] = b"ops_eyJzaWduSW5BZGRyZXNzIjoi.example.account.token";

    /// A software stand-in for the phone's Secure Enclave key `f`, plus its
    /// pinned public share `F`. On device `f` never leaves the enclave; here it
    /// is an ordinary P-256 scalar so the round trip runs headlessly.
    fn phone_se(se_key_id: &str, algo: EcdhAlgo) -> (MacShare, PhoneShare) {
        let f = MacShare::generate();
        let f_x963 = *f.public_point().as_x963();
        let share = PhoneShare::from_x963(se_key_id, &f_x963, algo).unwrap();
        (f, share)
    }

    /// The phone's per-request work: `Z_F = x(f·E)`, shaped per the record.
    fn phone_partial(f: &MacShare, record: &ThresholdRecord) -> Zeroizing<[u8; XCOORD_LEN]> {
        let e_point = record.ephemeral_point().unwrap();
        f.partial(&e_point, record.ecdh_algo, e_point.as_x963())
    }

    #[test]
    fn mac_share_is_generated_once_and_stable() {
        let ks = MemoryKeystore::new();
        assert!(!has_mac_share(&ks));
        let m1 = load_or_create_mac_share(&ks).unwrap();
        assert!(has_mac_share(&ks));
        // A second call loads the SAME share, never a fresh one (idempotent).
        let m2 = load_or_create_mac_share(&ks).unwrap();
        assert_eq!(*m1.scalar_bytes(), *m2.scalar_bytes());
        // And a plain load returns it too.
        let m3 = load_mac_share(&ks).unwrap().unwrap();
        assert_eq!(*m1.scalar_bytes(), *m3.scalar_bytes());
    }

    #[test]
    fn corrupt_mac_share_fails_closed() {
        let ks = MemoryKeystore::new();
        ks.store_blob(MAC_SHARE_LABEL, &[0u8; 32]).unwrap(); // zero scalar: invalid
        assert!(matches!(
            load_mac_share(&ks),
            Err(ThresholdStoreError::CorruptMacShare)
        ));
    }

    #[test]
    fn full_two_of_two_round_trip_raw_x() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);

        let mut store = ThresholdStore::default();
        seal_account(
            &mut store,
            "Rowm",
            &m,
            &phone,
            TOKEN,
            vec!["Engineering".into()],
        )
        .unwrap();

        let account = store.route(Some("Engineering")).unwrap();
        assert_eq!(account.record.version, THRESHOLD_RECORD_VERSION);
        // e was destroyed: only the public E survives, no scalar in the record.
        let json = serde_json::to_string(&account.record).unwrap();
        assert!(!json.contains("\"e\""), "no ephemeral scalar in the record");

        // The phone contributes Z_F; the Mac supplies m. Together: the token.
        let zf = phone_partial(&f, &account.record);
        let recovered = decrypt(&account.record, &m, &zf).unwrap();
        assert_eq!(&recovered[..], TOKEN);
    }

    #[test]
    fn full_two_of_two_round_trip_x963() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (f, phone) = phone_se("se-key-1", EcdhAlgo::X963Sha256);
        let mut store = ThresholdStore::default();
        seal_account(&mut store, "Rowm", &m, &phone, TOKEN, vec![]).unwrap();
        let rec = &store.accounts[0].record;
        let zf = phone_partial(&f, rec);
        assert_eq!(&decrypt(rec, &m, &zf).unwrap()[..], TOKEN);
    }

    #[test]
    fn a_wrong_or_missing_partial_fails_closed() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (_f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);
        let mut store = ThresholdStore::default();
        seal_account(&mut store, "Rowm", &m, &phone, TOKEN, vec![]).unwrap();
        let rec = &store.accounts[0].record;

        // A zero / wrong Z_F yields a wrong K and the GCM tag fails.
        assert!(matches!(
            decrypt(rec, &m, &[0u8; 32]),
            Err(ThresholdStoreError::Crypto(ThresholdError::Aead))
        ));

        // A different SE key f' does not open this account's token.
        let other = MacShare::generate();
        let zf_other = phone_partial(&other, rec);
        assert!(matches!(
            decrypt(rec, &m, &zf_other),
            Err(ThresholdStoreError::Crypto(ThresholdError::Aead))
        ));
    }

    #[test]
    fn a_wrong_mac_share_fails_closed() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);
        let mut store = ThresholdStore::default();
        seal_account(&mut store, "Rowm", &m, &phone, TOKEN, vec![]).unwrap();
        let rec = &store.accounts[0].record;
        let zf = phone_partial(&f, rec);
        // The right phone partial but the wrong Mac share still yields no token.
        let wrong_m = MacShare::generate();
        assert!(matches!(
            decrypt(rec, &wrong_m, &zf),
            Err(ThresholdStoreError::Crypto(ThresholdError::Aead))
        ));
    }

    #[test]
    fn off_curve_phone_share_is_rejected_at_pairing() {
        // R2: F is validated on-curve when it is pinned, not at use time.
        let good = MacShare::generate();
        let mut f_x963 = *good.public_point().as_x963();
        f_x963[64] ^= 1; // corrupt Y so (X,Y) is off-curve
        assert!(matches!(
            PhoneShare::from_x963("se-key-1", &f_x963, EcdhAlgo::RawX),
            Err(ThresholdError::BadPoint)
        ));
    }

    #[test]
    fn duplicate_label_is_rejected() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (_f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);
        let mut store = ThresholdStore::default();
        seal_account(&mut store, "Rowm", &m, &phone, TOKEN, vec![]).unwrap();
        assert!(matches!(
            seal_account(&mut store, "Rowm", &m, &phone, b"x", vec![]),
            Err(ThresholdStoreError::Duplicate(_))
        ));
    }

    #[test]
    fn each_account_gets_a_unique_ephemeral_and_routes() {
        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (_f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);
        let mut store = ThresholdStore::default();
        seal_account(
            &mut store,
            "Rowm",
            &m,
            &phone,
            b"t1",
            vec!["Engineering".into()],
        )
        .unwrap();
        seal_account(
            &mut store,
            "Personal",
            &m,
            &phone,
            b"t2",
            vec!["Private".into()],
        )
        .unwrap();
        // R4: distinct E per account.
        assert_ne!(
            store.accounts[0].record.ephemeral_pub, store.accounts[1].record.ephemeral_pub,
            "each account must get a fresh E"
        );
        assert_eq!(store.route(Some("Engineering")).unwrap().label(), "Rowm");
        assert_eq!(store.route(Some("Private")).unwrap().label(), "Personal");
        // An unknown vault with several accounts does not route (fail closed).
        assert!(store.route(Some("Nope")).is_none());
    }

    #[test]
    fn store_persists_ciphertext_only_and_reloads() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("latch-thr-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("LATCH_HOME", &tmp);

        let ks = MemoryKeystore::new();
        let m = load_or_create_mac_share(&ks).unwrap();
        let (f, phone) = phone_se("se-key-1", EcdhAlgo::RawX);
        let mut store = ThresholdStore::default();
        seal_account(
            &mut store,
            "Rowm",
            &m,
            &phone,
            b"super-secret-token",
            vec!["Engineering".into()],
        )
        .unwrap();
        store.save().unwrap();

        // The plaintext token must not appear on disk.
        let raw = std::fs::read(ThresholdStore::path().unwrap()).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("super-secret-token"),
            "plaintext token leaked into the threshold store"
        );

        let loaded = ThresholdStore::load().unwrap();
        let rec = &loaded.route(Some("Engineering")).unwrap().record;
        let zf = phone_partial(&f, rec);
        assert_eq!(&decrypt(rec, &m, &zf).unwrap()[..], b"super-secret-token");

        std::env::remove_var("LATCH_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
