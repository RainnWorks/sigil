//! On-disk persistence of the daemon<->phone pairing(s) that make the phone the
//! approving factor across daemon restarts.
//!
//! # Multi-device (#36)
//!
//! The file is a versioned container of N devices (`{version:2, devices:[...]}`),
//! one row per paired phone. Each device is fully independent: its own daemon
//! identity in the keystore (under a per-device label), its own pinned phone, its
//! own mailbox, and its own DEK delivery, so the relay sees N unrelated mailbox
//! hashes and cannot link them. A legacy v1 (flat, single-device) file is migrated
//! to the container on read; its device keeps the `primary` sentinel id so its
//! keystore identity stays under the legacy label and migration never touches the
//! keystore. [`load`] returns the primary alone (byte-identical single-device
//! behavior); [`load_all`] returns every device for the ring-all coordinator.
//!
//! # What is persisted, and why it stays inert at rest
//!
//! A paired daemon needs three things to run the phone factor for each device: its
//! own long-term identity (to sign requests and open responses), the phone's
//! pinned **public** identity (to seal to and verify), and the relay URL. This
//! module persists exactly those, split by sensitivity:
//!
//! * The daemon's **private identity** (Ed25519 signing seed + X25519 agreement
//!   secret, 64 bytes) goes into the [`Keystore`] blob seam — the login Keychain
//!   on macOS. It never touches the plaintext config file.
//! * The **public** parts — the phone's pinned [`PeerIdentity`], the relay URL,
//!   the pairing time, and the six SAS words (for `list-paired-devices`) — go
//!   into `~/.sigil/pairing.json`, mode 0600.
//!
//! Crucially, **no DEK is persisted.** The DEK lives only on the phone; it
//! arrives per-approval inside a sealed [`ApprovalResponse`] and is zeroized
//! after one use. This is what keeps the daemon inert at rest: the on-disk state
//! (even including the private identity) can *ask* the phone to approve a
//! request, but it cannot by itself decrypt any service-account token, because
//! the tokens are AES-256-GCM ciphertext under the DEK the daemon does not hold.
//! An attacker who steals the whole disk gains only the ability to send the
//! phone a request — which the phone answers only after Tom's hardware-gated
//! approval, exactly the gate Sigil exists to enforce. Nothing releasable at
//! rest, by construction.
//!
//! Flagged to security-reviewer: the persisted set is `{daemon private identity
//! (keystore), phone public identity, relay URL, SAS words}` and deliberately
//! excludes any DEK or DEK envelope.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use sigil_proto::identity::DeviceIdentity;
use sigil_proto::threshold::EcdhAlgo;
use sigil_proto::PeerIdentity;

use crate::daemon::RemotePairingConfig;
use crate::keystore::{Keystore, KeystoreError};
use crate::paths;
use crate::threshold::PhoneShare;

/// Keystore blob label under which the PRIMARY device's 64-byte private identity
/// is sealed. This is the historical single-device label; a v1 pairing (and the
/// v1-migrated primary of a v2 container) keeps its identity here forever, so
/// migration never has to touch the keystore. Each ADDITIONAL device (#36
/// multi-device) seals its own identity under a per-device label derived from
/// this stem plus its `deviceId` (see [`identity_label`]).
const DAEMON_IDENTITY_LABEL: &str = "pairing.daemon-identity.v1";

/// The v1 on-disk `pairing.json` schema: a single [`PersistedPairing`] object.
/// Still read (and migrated on the fly) so an existing single-device pairing
/// keeps working after the v2 container lands.
const PAIRING_VERSION_V1: u32 = 1;

/// The current on-disk `pairing.json` schema: a versioned container holding N
/// devices (#36 multi-device). New writes always emit this.
const PAIRING_VERSION_V2: u32 = 2;

/// The stable `deviceId` sentinel for the primary device: the one a v1 file
/// migrates into, or the one a single-device `save` writes. Its keystore label
/// is the legacy [`DAEMON_IDENTITY_LABEL`] (not the per-device scheme), so a
/// v1 -> v2 migration is a pure file rewrite that leaves the keystore untouched.
const PRIMARY_DEVICE_ID: &str = "primary";

/// The keystore blob label for a device's private daemon identity. The primary
/// device (a v1-migrated or single-`save` pairing) stays on the legacy stem so
/// migration never re-keys the keystore; every additional device gets its own
/// `pairing.daemon-identity.v1.<deviceId>` label, fully independent.
fn identity_label(device_id: &str) -> String {
    if device_id == PRIMARY_DEVICE_ID {
        DAEMON_IDENTITY_LABEL.to_string()
    } else {
        format!("{DAEMON_IDENTITY_LABEL}.{device_id}")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PairingStoreError {
    #[error("HOME is not set, so ~/.sigil has no location")]
    NoHome,
    #[error("pairing config io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pairing config json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("unsupported pairing config version {0} (this build understands {PAIRING_VERSION_V1} and {PAIRING_VERSION_V2})")]
    Version(u32),
    #[error("the daemon identity is missing from the keystore; re-pair with `sigil pair`")]
    MissingIdentity,
    #[error("the stored daemon identity is corrupt; re-pair with `sigil pair`")]
    CorruptIdentity,
    #[error("the persisted phone Secure-Enclave share F is not a valid P-256 point; re-pair")]
    CorruptPhoneShare,
}

/// The phone's Secure-Enclave threshold share `F`, as persisted in the plaintext
/// config. Public key material only (a point, an id, and a shape tag); the
/// enclave private key `f` never leaves the phone. Additive and optional, so a v1
/// pairing (no v2 share) round-trips unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPhoneShare {
    /// Which pinned SE key this is (echoed into the per-request challenge).
    se_key_id: String,
    /// `F = f·G`, ANSI X9.63 uncompressed (65 bytes), base64.
    f_x963: String,
    /// Which SE ECDH output shape this key emits (NV-2/NV-7).
    ecdh_algo: EcdhAlgo,
}

/// The v1 (single-device) on-disk shape: one flat pairing object. Only READ now,
/// to migrate an existing single-device `pairing.json` into the v2 container on
/// the fly (see [`read_container`]). New writes never emit this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPairingV1 {
    version: u32,
    /// The relay base URL the daemon attaches to for approvals.
    relay_url: String,
    /// The phone's pinned public identity (verify + seal targets).
    phone: PeerIdentity,
    /// When pairing completed, unix ms.
    paired_at: u64,
    /// The six SAS words this pairing confirmed, kept for display only.
    sas_words: Vec<String>,
    /// The phone's v2 threshold share `F`, present only for a v2 pairing. A v1
    /// pairing omits it; `#[serde(default)]` keeps old configs loading unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone_share: Option<PersistedPhoneShare>,
}

/// One device's public row inside the v2 container. Everything safe to keep in a
/// plaintext 0600 file; the device's private daemon identity lives in the
/// keystore under [`identity_label`]`(device_id)`, never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedDevice {
    /// Stable id (uuidv7, or the [`PRIMARY_DEVICE_ID`] sentinel for the migrated
    /// primary): names the keystore identity label and the removal handle.
    device_id: String,
    /// Human label for `sigil pair list` / removal. Defaults empty on an old
    /// row that predates the field.
    #[serde(default)]
    label: String,
    /// The relay base URL the daemon attaches to for this device's approvals.
    relay_url: String,
    /// The phone's pinned public identity (verify + seal targets).
    phone: PeerIdentity,
    /// When pairing completed, unix ms.
    paired_at: u64,
    /// The six SAS words this pairing confirmed, kept for display only.
    sas_words: Vec<String>,
    /// The phone's v2 threshold share `F`, present only for a v2 pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone_share: Option<PersistedPhoneShare>,
    /// The rung-2 owned endpoint (`host:port`) the daemon binds for a direct link
    /// to this device (#51). Absent/omitted means direct transport is OFF for this
    /// device (the default), so the field is additive and an existing pairing
    /// round-trips unchanged. It is a NON-secret routing address, safe in the
    /// plaintext 0600 file, and never a trust boundary: an inbound direct byte is
    /// dropped unless it opens as the pinned phone (`verify_and_promote`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct_endpoint: Option<String>,
}

impl PersistedDevice {
    /// Build a persisted row from a completed pairing plus a stable id + label.
    fn from_new(device_id: &str, label: &str, p: &NewPairing) -> Self {
        Self {
            device_id: device_id.to_string(),
            label: label.to_string(),
            relay_url: p.relay_url.clone(),
            phone: p.phone,
            paired_at: p.paired_at,
            sas_words: p.sas_words.to_vec(),
            phone_share: p.phone_share.as_ref().map(|s| PersistedPhoneShare {
                se_key_id: s.se_key_id.clone(),
                f_x963: B64.encode(&s.f_x963),
                ecdh_algo: s.ecdh_algo,
            }),
            // A fresh pairing does not enable direct transport; it stays OFF until
            // the user configures an endpoint (kept additive and default-off).
            direct_endpoint: None,
        }
    }
}

/// The v2 on-disk container: a versioned list of paired devices (#36
/// multi-device). Order is arm/pairing order; `devices[0]` is the primary.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedContainer {
    version: u32,
    devices: Vec<PersistedDevice>,
}

impl PersistedContainer {
    /// An empty v2 container (no devices yet).
    fn empty() -> Self {
        Self {
            version: PAIRING_VERSION_V2,
            devices: Vec::new(),
        }
    }

    /// Lift a v1 flat pairing into a one-device v2 container. The single device
    /// takes the [`PRIMARY_DEVICE_ID`] sentinel, so its identity stays under the
    /// legacy keystore label and nothing in the keystore has to move.
    fn from_v1(v1: PersistedPairingV1) -> Self {
        Self {
            version: PAIRING_VERSION_V2,
            devices: vec![PersistedDevice {
                device_id: PRIMARY_DEVICE_ID.to_string(),
                label: "iPhone".to_string(),
                relay_url: v1.relay_url,
                phone: v1.phone,
                paired_at: v1.paired_at,
                sas_words: v1.sas_words,
                phone_share: v1.phone_share,
                // A v1 file predates direct transport: OFF on migration.
                direct_endpoint: None,
            }],
        }
    }
}

/// A read-only public summary of one paired device, for `sigil pair list` and
/// `sigil pair remove`. Public parts only (no keystore access).
#[derive(Debug, Clone)]
pub struct DeviceSummary {
    pub device_id: String,
    pub label: String,
    pub relay_url: String,
    pub phone: PeerIdentity,
    pub paired_at: u64,
    pub sas_words: Vec<String>,
}

/// The phone's v2 threshold share as handed to [`save`]: the id, the raw 65-byte
/// `F` in ANSI X9.63 form, and the SE output shape. Validated on-curve at load.
#[derive(Debug, Clone)]
pub struct NewPhoneShare {
    pub se_key_id: String,
    pub f_x963: Vec<u8>,
    pub ecdh_algo: EcdhAlgo,
}

/// The inputs a completed pairing hands this module to persist.
pub struct NewPairing {
    /// The daemon's own long-term identity (private; sealed into the keystore).
    pub daemon_identity: DeviceIdentity,
    /// The phone's pinned public identity.
    pub phone: PeerIdentity,
    /// The relay base URL.
    pub relay_url: String,
    /// The confirmed SAS words, for `list-paired-devices`.
    pub sas_words: [String; 6],
    /// Pairing completion time, unix ms.
    pub paired_at: u64,
    /// The phone's v2 Secure-Enclave threshold share `F`, when this is a v2
    /// pairing. `None` for a v1 pairing (DEK handoff), which keeps working.
    pub phone_share: Option<NewPhoneShare>,
}

/// A read-only summary of the persisted pairing, for `list-paired-devices`. Uses
/// only the public config file, so it needs no keystore access.
#[derive(Debug, Clone)]
pub struct PairingSummary {
    pub relay_url: String,
    pub phone: PeerIdentity,
    pub paired_at: u64,
    pub sas_words: Vec<String>,
}

fn config_path() -> Result<std::path::PathBuf, PairingStoreError> {
    paths::pairing_path().ok_or(PairingStoreError::NoHome)
}

/// True if a pairing config file is present (does not validate it or the
/// keystore identity).
pub fn exists() -> bool {
    config_path().map(|p| p.exists()).unwrap_or(false)
}

/// The biometric prompt shown when authorizing a new pairing (#48). No
/// em-dash, no emoji (invariant #6).
const PAIRING_PRESENCE_REASON: &str = "Authorize pairing this phone to Sigil";

/// Read `pairing.json` and normalize it to the v2 container, migrating a v1
/// (flat, single-device) file on the fly. `None` when no file is present.
///
/// Migration is a pure in-memory read transform: a v1 object becomes a
/// one-device container whose device keeps the [`PRIMARY_DEVICE_ID`] sentinel, so
/// its keystore identity stays under the legacy label and nothing in the keystore
/// moves. The rewrite to a v2 file on disk happens on the next mutating call
/// (`add_device`/`remove_device`); reads never rewrite, so this is idempotent and
/// crash-safe.
fn read_container(path: &std::path::Path) -> Result<Option<PersistedContainer>, PairingStoreError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    match version {
        PAIRING_VERSION_V2 => Ok(Some(serde_json::from_value(value)?)),
        PAIRING_VERSION_V1 => {
            let v1: PersistedPairingV1 = serde_json::from_value(value)?;
            Ok(Some(PersistedContainer::from_v1(v1)))
        }
        other => Err(PairingStoreError::Version(other)),
    }
}

/// Write a v2 container to `pairing.json`, 0600, creating `~/.sigil` (0700) if
/// needed. The container never holds any private key material (only public
/// pins), matching the inert-at-rest invariant.
fn write_container(
    path: &std::path::Path,
    container: &PersistedContainer,
) -> Result<(), PairingStoreError> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let json = serde_json::to_vec_pretty(container)?;
    std::fs::write(path, json)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Reconstruct one device's [`RemotePairingConfig`] from its persisted public row
/// plus its private identity in the keystore. Fails loud (not `None`) when the
/// keystore identity is missing/corrupt or the pinned v2 share is off-curve, so a
/// half-broken device surfaces instead of silently arming without a pin.
fn device_to_config(
    ks: &dyn Keystore,
    d: &PersistedDevice,
) -> Result<RemotePairingConfig, PairingStoreError> {
    let blob = ks
        .load_blob(&identity_label(&d.device_id))?
        .ok_or(PairingStoreError::MissingIdentity)?;
    let daemon_identity =
        DeviceIdentity::from_secret_bytes(&blob).ok_or(PairingStoreError::CorruptIdentity)?;

    // Validate and pin the phone's v2 threshold share F on-curve (R2). A v1
    // pairing has none, which is not an error (it takes the DEK path).
    let phone_share = match &d.phone_share {
        Some(s) => {
            let f = B64
                .decode(&s.f_x963)
                .map_err(|_| PairingStoreError::CorruptPhoneShare)?;
            let share = PhoneShare::from_x963(&s.se_key_id, &f, s.ecdh_algo)
                .map_err(|_| PairingStoreError::CorruptPhoneShare)?;
            Some(share)
        }
        None => None,
    };

    Ok(RemotePairingConfig {
        relay_url: d.relay_url.clone(),
        daemon_identity,
        phone: d.phone,
        phone_share,
        direct_endpoint: d.direct_endpoint.clone(),
    })
}

/// Run the #48 biometric gate before any pairing mutation. On a hardware keystore
/// this is a live Secure-Enclave user-presence check; a decline returns an error
/// and the caller writes nothing. Non-biometric dev keystores (only reachable
/// under `SIGIL_DEV_KEYSTORE`) skip it so headless dev and tests still pair.
fn gate_presence(ks: &dyn Keystore) -> Result<(), PairingStoreError> {
    if ks.is_biometric() {
        ks.verify_presence(PAIRING_PRESENCE_REASON)?;
    }
    Ok(())
}

/// Persist a completed pairing as the SOLE device, replacing any existing
/// pairing. This is the single-device writer kept for source compatibility; the
/// additive multi-device path is [`add_device`]. The written device takes the
/// [`PRIMARY_DEVICE_ID`] sentinel (identity under the legacy label).
///
/// **Biometric gate (#48):** authorizing a new pairing on a hardware keystore
/// requires a live Touch ID / Secure Enclave user-presence, run BEFORE anything
/// is written, deny-closed: a declined or absent biometric refuses the pairing
/// with NOTHING written (no identity blob, no config file).
pub fn save(ks: &dyn Keystore, p: &NewPairing) -> Result<(), PairingStoreError> {
    // 0. Gate on a live hardware biometric before persisting anything.
    gate_presence(ks)?;

    // 1. Seal the private daemon identity into the keystore blob seam. The bytes
    //    are Zeroizing and are wiped when `secret` drops at the end of this call.
    let secret = p.daemon_identity.to_secret_bytes();
    ks.store_blob(DAEMON_IDENTITY_LABEL, &secret[..])?;

    // 2. Write a fresh one-device v2 container 0600.
    let container = PersistedContainer {
        version: PAIRING_VERSION_V2,
        devices: vec![PersistedDevice::from_new(PRIMARY_DEVICE_ID, "iPhone", p)],
    };
    write_container(&config_path()?, &container)?;
    Ok(())
}

/// Append a completed pairing as an ADDITIONAL device WITHOUT dropping the
/// existing devices (#36 additive pairing). Returns the new `deviceId`.
///
/// Each device is fully independent: a fresh uuidv7 id, its own daemon identity
/// sealed under a per-device keystore label, its own pinned phone, its own
/// mailbox, and its own DEK delivery. The #48 biometric gate fires on EVERY add,
/// deny-closed and BEFORE any write. Crash-order: the identity blob is sealed,
/// then the container file is rewritten; a crash in between leaves an orphan
/// identity blob (inert, unreferenced by any device row), never an armed device
/// without a pinned phone.
pub fn add_device(
    ks: &dyn Keystore,
    p: &NewPairing,
    label: &str,
) -> Result<String, PairingStoreError> {
    // 0. #48 gate on EACH add, before any write.
    gate_presence(ks)?;

    // 1. A fresh, stable device id (uuidv7: time-ordered, collision-free).
    let device_id = uuid::Uuid::now_v7().to_string();

    // 2. Seal this device's private identity under its per-device label.
    let secret = p.daemon_identity.to_secret_bytes();
    ks.store_blob(&identity_label(&device_id), &secret[..])?;

    // 3. Read (migrating v1) and append; a brand-new store starts empty.
    let path = config_path()?;
    let mut container = read_container(&path)?.unwrap_or_else(PersistedContainer::empty);
    container.version = PAIRING_VERSION_V2;
    container
        .devices
        .push(PersistedDevice::from_new(&device_id, label, p));
    write_container(&path, &container)?;
    Ok(device_id)
}

/// Load the PRIMARY device (`devices[0]`) into a [`RemotePairingConfig`], or
/// `None` when no pairing is configured. Byte-identical to the historical
/// single-device `load` for a one-device store, so an N == 1 daemon arms exactly
/// as before. Fails loud when the primary's keystore identity is missing/corrupt.
pub fn load(ks: &dyn Keystore) -> Result<Option<RemotePairingConfig>, PairingStoreError> {
    let Some(container) = read_container(&config_path()?)? else {
        return Ok(None);
    };
    match container.devices.first() {
        Some(primary) => Ok(Some(device_to_config(ks, primary)?)),
        None => Ok(None),
    }
}

/// Load EVERY paired device into a [`RemotePairingConfig`], for the ring-all
/// coordinator (#36). Order is arm order (`devices[0]` is the primary). A single
/// device yields a one-element vector identical to [`load`], so the composition
/// over N == 1 is byte-identical to today. Fails loud if ANY device is
/// half-broken, so the daemon degrades to fail-closed rather than arming a subset
/// silently.
pub fn load_all(ks: &dyn Keystore) -> Result<Vec<RemotePairingConfig>, PairingStoreError> {
    let Some(container) = read_container(&config_path()?)? else {
        return Ok(Vec::new());
    };
    container
        .devices
        .iter()
        .map(|d| device_to_config(ks, d))
        .collect()
}

/// The public summary of the PRIMARY device, for display. `None` when no pairing
/// is configured. Reads the public file alone (no keystore).
pub fn summary() -> Result<Option<PairingSummary>, PairingStoreError> {
    let Some(container) = read_container(&config_path()?)? else {
        return Ok(None);
    };
    Ok(container.devices.first().map(|d| PairingSummary {
        relay_url: d.relay_url.clone(),
        phone: d.phone,
        paired_at: d.paired_at,
        sas_words: d.sas_words.clone(),
    }))
}

/// A public summary of every paired device, for `sigil pair list` (#36). Reads
/// the public file alone (no keystore). Empty when nothing is paired.
pub fn list_devices() -> Result<Vec<DeviceSummary>, PairingStoreError> {
    let Some(container) = read_container(&config_path()?)? else {
        return Ok(Vec::new());
    };
    Ok(container
        .devices
        .into_iter()
        .map(|d| DeviceSummary {
            device_id: d.device_id,
            label: d.label,
            relay_url: d.relay_url,
            phone: d.phone,
            paired_at: d.paired_at,
            sas_words: d.sas_words,
        })
        .collect())
}

/// Remove ONE device by id: drop its row and delete its keystore identity blob.
/// Idempotent (`false` if no such device). Removing the last device returns to
/// the fully unpaired state (the file is deleted). Crash-order: the container
/// file is rewritten (device gone) BEFORE the blob is deleted, so a crash leaves
/// an orphan blob (inert), never a dangling row pointing at a deleted identity.
pub fn remove_device(ks: &dyn Keystore, device_id: &str) -> Result<bool, PairingStoreError> {
    let path = config_path()?;
    let Some(mut container) = read_container(&path)? else {
        return Ok(false);
    };
    let Some(idx) = container
        .devices
        .iter()
        .position(|d| d.device_id == device_id)
    else {
        return Ok(false);
    };
    let removed = container.devices.remove(idx);
    // Write the file first (row gone), then delete the identity blob.
    if container.devices.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    } else {
        write_container(&path, &container)?;
    }
    ks.delete_blob(&identity_label(&removed.device_id))?;
    Ok(true)
}

/// Remove the pairing entirely: delete every device's keystore identity blob and
/// the config file. Returns `true` if a config file was removed. Idempotent.
/// `sigil unpair` (remove all) maps here.
pub fn remove(ks: &dyn Keystore) -> Result<bool, PairingStoreError> {
    let path = config_path()?;
    // Snapshot the device ids before deleting the file, so we know which
    // per-device identity blobs to reap.
    let container = read_container(&path)?;

    let mut removed = false;
    match std::fs::remove_file(&path) {
        Ok(()) => removed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    // Delete every device's identity blob. Always sweep the legacy label too, so
    // a store that predates the container (or a partial migration) is fully
    // cleaned regardless of what the file said.
    ks.delete_blob(DAEMON_IDENTITY_LABEL)?;
    if let Some(container) = container {
        for d in container.devices {
            if d.device_id != PRIMARY_DEVICE_ID {
                ks.delete_blob(&identity_label(&d.device_id))?;
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use crate::secrets::Dek;

    /// A private SIGIL_HOME for one test, plus a guard that restores the env.
    /// Holds the process-wide env lock so parallel tests do not clobber it.
    struct HomeGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
        dir: std::path::PathBuf,
    }
    impl HomeGuard {
        fn new(tag: &str) -> Self {
            let lock = crate::TEST_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "sigil-pairstore-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("SIGIL_HOME");
            std::env::set_var("SIGIL_HOME", &dir);
            Self {
                _lock: lock,
                prev,
                dir,
            }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("SIGIL_HOME", v),
                None => std::env::remove_var("SIGIL_HOME"),
            }
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn new_pairing() -> (DeviceIdentity, PeerIdentity, NewPairing) {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let daemon_pub = daemon.peer_identity();
        let np = NewPairing {
            daemon_identity: daemon,
            phone,
            relay_url: "https://relay.example".into(),
            sas_words: [
                "tide".into(),
                "brass".into(),
                "anchor".into(),
                "harbor".into(),
                "reef".into(),
                "mast".into(),
            ],
            paired_at: 1_720_000_000_000,
            phone_share: None,
        };
        // Rebuild a daemon identity handle with the same public id for asserts.
        (DeviceIdentity::generate(), daemon_pub, np)
    }

    /// A keystore that reports as biometric with a scripted presence result, so
    /// the #48 pairing gate is testable headlessly. Blob/DEK ops delegate to an
    /// inner [`MemoryKeystore`].
    struct ScriptedBiometric {
        inner: MemoryKeystore,
        grant_presence: bool,
    }
    impl ScriptedBiometric {
        fn new(grant_presence: bool) -> Self {
            Self {
                inner: MemoryKeystore::new(),
                grant_presence,
            }
        }
    }
    impl Keystore for ScriptedBiometric {
        fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
            self.inner.store_blob(label, data)
        }
        fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
            self.inner.load_blob(label)
        }
        fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
            self.inner.delete_blob(label)
        }
        fn is_biometric(&self) -> bool {
            true
        }
        fn has_dek(&self) -> bool {
            self.inner.has_dek()
        }
        fn ensure_dek(&self) -> Result<(), KeystoreError> {
            self.inner.ensure_dek()
        }
        fn unwrap_dek(&self, reason: &str) -> Result<Dek, KeystoreError> {
            self.inner.unwrap_dek(reason)
        }
        fn verify_presence(&self, _reason: &str) -> Result<(), KeystoreError> {
            if self.grant_presence {
                Ok(())
            } else {
                Err(KeystoreError::Declined)
            }
        }
    }

    #[test]
    fn a_biometric_keystore_that_grants_presence_persists_the_pairing() {
        // #48: on a hardware keystore, authorizing a pairing runs the biometric
        // gate; a granted presence lets it persist normally.
        let _home = HomeGuard::new("bio-grant");
        let ks = ScriptedBiometric::new(true);
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).expect("a granted biometric persists the pairing");
        assert!(exists(), "the pairing was written");
        assert!(
            ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_some(),
            "the daemon identity blob was sealed"
        );
    }

    #[test]
    fn a_declined_biometric_refuses_the_pairing_and_writes_nothing() {
        // #48 deny-closed: a declined Touch ID must refuse the pairing BEFORE any
        // state is written -- no config file, no identity blob.
        let _home = HomeGuard::new("bio-deny");
        let ks = ScriptedBiometric::new(false);
        let (_i, _p, np) = new_pairing();
        let err = save(&ks, &np).expect_err("a declined biometric must refuse");
        assert!(
            matches!(err, PairingStoreError::Keystore(KeystoreError::Declined)),
            "the refusal is the biometric decline, got {err:?}"
        );
        assert!(
            !exists(),
            "no config file may be written on a declined biometric"
        );
        assert!(
            ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_none(),
            "no identity blob may be sealed on a declined biometric"
        );
    }

    #[test]
    fn a_biometric_keystore_missing_a_verify_presence_override_fails_closed() {
        // Defense in depth: a keystore that claims is_biometric() but forgets to
        // override verify_presence inherits the trait default, which errs. The
        // pairing gate then refuses rather than persisting without a check.
        struct NoOverride(MemoryKeystore);
        impl Keystore for NoOverride {
            fn store_blob(&self, l: &str, d: &[u8]) -> Result<(), KeystoreError> {
                self.0.store_blob(l, d)
            }
            fn load_blob(&self, l: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
                self.0.load_blob(l)
            }
            fn delete_blob(&self, l: &str) -> Result<(), KeystoreError> {
                self.0.delete_blob(l)
            }
            fn is_biometric(&self) -> bool {
                true
            }
            fn has_dek(&self) -> bool {
                self.0.has_dek()
            }
            fn ensure_dek(&self) -> Result<(), KeystoreError> {
                self.0.ensure_dek()
            }
            fn unwrap_dek(&self, r: &str) -> Result<Dek, KeystoreError> {
                self.0.unwrap_dek(r)
            }
            // deliberately no verify_presence override
        }
        let _home = HomeGuard::new("bio-noimpl");
        let ks = NoOverride(MemoryKeystore::new());
        let (_i, _p, np) = new_pairing();
        assert!(
            save(&ks, &np).is_err(),
            "a biometric keystore with no presence check must fail closed"
        );
        assert!(
            !exists(),
            "nothing written when the presence check is unavailable"
        );
    }

    #[test]
    fn save_then_load_reconstructs_the_config_and_pins_the_phone() {
        let _home = HomeGuard::new("roundtrip");
        let ks = MemoryKeystore::new();
        let (_ignore, daemon_pub, np) = new_pairing();
        let phone = np.phone;
        let relay = np.relay_url.clone();

        save(&ks, &np).unwrap();
        assert!(exists());

        let cfg = load(&ks).unwrap().expect("a pairing was saved");
        assert_eq!(cfg.relay_url, relay);
        assert_eq!(cfg.phone, phone);
        // The reconstructed daemon identity has the same pinned public halves,
        // so the mailbox it derives matches what the phone computes.
        assert_eq!(cfg.daemon_identity.peer_identity(), daemon_pub);
    }

    #[test]
    fn no_config_file_loads_as_none() {
        let _home = HomeGuard::new("none");
        let ks = MemoryKeystore::new();
        assert!(!exists());
        assert!(load(&ks).unwrap().is_none());
        assert!(summary().unwrap().is_none());
    }

    #[test]
    fn config_present_but_identity_missing_is_a_loud_error() {
        let _home = HomeGuard::new("half");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        // Simulate a keystore that lost the identity (e.g. Keychain wiped).
        ks.delete_blob(DAEMON_IDENTITY_LABEL).unwrap();
        let err = match load(&ks) {
            Err(e) => e,
            Ok(_) => panic!("expected a MissingIdentity error"),
        };
        assert!(matches!(err, PairingStoreError::MissingIdentity));
    }

    #[test]
    fn config_file_is_0600_and_holds_no_dek() {
        use std::os::unix::fs::PermissionsExt;
        let _home = HomeGuard::new("perms");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        let path = config_path().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Inert-at-rest: no DEK, no key material of any kind in the plaintext.
        let raw = std::fs::read_to_string(&path).unwrap().to_lowercase();
        assert!(!raw.contains("dek"), "no DEK field in the config");
        assert!(!raw.contains("secret"), "no secret in the config");
        assert!(!raw.contains("signing"), "no private key in the config");
    }

    #[test]
    fn summary_reads_public_parts_without_the_keystore() {
        let _home = HomeGuard::new("summary");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        let phone = np.phone;
        save(&ks, &np).unwrap();
        // No keystore passed: the summary comes from the config file alone.
        let s = summary().unwrap().expect("a pairing exists");
        assert_eq!(s.phone, phone);
        assert_eq!(s.sas_words.len(), 6);
        assert_eq!(s.relay_url, "https://relay.example");
    }

    #[test]
    fn v2_pairing_persists_and_revalidates_the_phone_share_f() {
        use sigil_proto::threshold::{EcdhAlgo, MacShare};
        let _home = HomeGuard::new("v2-share");
        let ks = MemoryKeystore::new();
        let (_i, _p, mut np) = new_pairing();

        // A valid on-curve F (software stand-in for the phone's SE public key).
        let f = MacShare::generate();
        let f_x963 = f.public_point().as_x963().to_vec();
        np.phone_share = Some(NewPhoneShare {
            se_key_id: "se-key-1".into(),
            f_x963: f_x963.clone(),
            ecdh_algo: EcdhAlgo::RawX,
        });
        save(&ks, &np).unwrap();

        // Reload validates F on-curve (R2) and pins it.
        let cfg = load(&ks).unwrap().expect("a v2 pairing was saved");
        let share = cfg.phone_share.expect("the phone share round-trips");
        assert_eq!(share.se_key_id, "se-key-1");
        assert_eq!(share.point.as_x963().to_vec(), f_x963);
        assert_eq!(share.ecdh_algo, EcdhAlgo::RawX);
    }

    #[test]
    fn a_corrupt_persisted_phone_share_fails_closed_on_load() {
        use sigil_proto::threshold::EcdhAlgo;
        let _home = HomeGuard::new("v2-corrupt");
        let ks = MemoryKeystore::new();
        let (_i, _p, mut np) = new_pairing();
        // 65 bytes that are not an on-curve point.
        np.phone_share = Some(NewPhoneShare {
            se_key_id: "se-key-1".into(),
            f_x963: vec![0x04u8; 65],
            ecdh_algo: EcdhAlgo::RawX,
        });
        save(&ks, &np).unwrap();
        assert!(matches!(
            load(&ks),
            Err(PairingStoreError::CorruptPhoneShare)
        ));
    }

    #[test]
    fn a_v1_pairing_without_a_phone_share_still_loads() {
        // Additive field: a pairing saved with no v2 share reconstructs with
        // `phone_share: None` and takes the DEK path, unchanged.
        let _home = HomeGuard::new("v1-still");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        let cfg = load(&ks).unwrap().unwrap();
        assert!(cfg.phone_share.is_none());
    }

    #[test]
    fn remove_deletes_both_the_config_and_the_identity() {
        let _home = HomeGuard::new("remove");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        assert!(remove(&ks).unwrap());
        assert!(!exists());
        assert!(load(&ks).unwrap().is_none());
        // The identity blob is gone too.
        assert!(ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_none());
        // A second remove is a no-op, not an error.
        assert!(!remove(&ks).unwrap());
    }

    /// The current writer emits a v2 container; a fresh `save` is v2 on disk.
    #[test]
    fn save_writes_a_v2_container() {
        let _home = HomeGuard::new("v2-write");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        let raw = std::fs::read_to_string(config_path().unwrap()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v.get("version").and_then(|x| x.as_u64()), Some(2));
        assert_eq!(
            v.get("devices").and_then(|d| d.as_array()).unwrap().len(),
            1
        );
    }

    /// A legacy v1 flat file is migrated on read: `load` reconstructs the primary
    /// device from the LEGACY keystore label (untouched by migration), and
    /// `load_all` yields exactly that one device. This is the byte-compatible
    /// upgrade path for an existing single-device pairing.
    #[test]
    fn a_v1_file_migrates_on_read() {
        let _home = HomeGuard::new("v1-migrate");
        let ks = MemoryKeystore::new();
        let daemon = DeviceIdentity::generate();
        let daemon_pub = daemon.peer_identity();
        let phone = DeviceIdentity::generate().peer_identity();

        // Hand-write a v1 flat file + the identity under the LEGACY label, exactly
        // as the old `save` used to.
        ks.store_blob(DAEMON_IDENTITY_LABEL, &daemon.to_secret_bytes()[..])
            .unwrap();
        let v1 = PersistedPairingV1 {
            version: PAIRING_VERSION_V1,
            relay_url: "https://relay.legacy".into(),
            phone,
            paired_at: 42,
            sas_words: vec!["a".into(), "b".into()],
            phone_share: None,
        };
        write_v1(&v1);

        // load() reconstructs the primary from the legacy label.
        let cfg = load(&ks).unwrap().expect("v1 migrates to a primary");
        assert_eq!(cfg.relay_url, "https://relay.legacy");
        assert_eq!(cfg.phone, phone);
        assert_eq!(cfg.daemon_identity.peer_identity(), daemon_pub);

        // load_all yields exactly one device, and list_devices names the primary.
        assert_eq!(load_all(&ks).unwrap().len(), 1);
        let devices = list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, PRIMARY_DEVICE_ID);
        assert_eq!(devices[0].relay_url, "https://relay.legacy");
    }

    /// Adding a device is ADDITIVE: the existing device is not dropped, the new
    /// one gets its own uuidv7 id and its own per-device keystore label, and
    /// `load_all` returns both with distinct daemon identities.
    #[test]
    fn add_device_is_additive_and_per_device_isolated() {
        let _home = HomeGuard::new("add-additive");
        let ks = MemoryKeystore::new();

        let (_i, primary_pub, np1) = new_pairing();
        save(&ks, &np1).unwrap();

        let (_i2, second_pub, np2) = new_pairing();
        let id2 = add_device(&ks, &np2, "iPad").unwrap();
        assert_ne!(id2, PRIMARY_DEVICE_ID);

        // Both devices load, in arm order, each with its OWN daemon identity.
        let all = load_all(&ks).unwrap();
        assert_eq!(all.len(), 2, "the primary was not dropped by the add");
        assert_eq!(all[0].daemon_identity.peer_identity(), primary_pub);
        assert_eq!(all[1].daemon_identity.peer_identity(), second_pub);
        // Distinct mailboxes: the relay cannot link them.
        assert_ne!(all[0].mailbox(), all[1].mailbox());

        // The second device's identity is under its OWN per-device label, not the
        // legacy one, so it is fully independent of the primary.
        assert!(ks.load_blob(&identity_label(&id2)).unwrap().is_some());
        let devices = list_devices().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].label, "iPad");
    }

    /// `add_device` also works as the FIRST device on an empty store, and the
    /// #48 biometric gate fires on the add (a decline writes nothing).
    #[test]
    fn add_device_gates_on_biometric_and_writes_nothing_on_decline() {
        let _home = HomeGuard::new("add-gate");
        let ks = ScriptedBiometric::new(false);
        let (_i, _p, np) = new_pairing();
        let err = add_device(&ks, &np, "iPhone").expect_err("a declined biometric refuses");
        assert!(matches!(
            err,
            PairingStoreError::Keystore(KeystoreError::Declined)
        ));
        assert!(!exists(), "no file written on a declined biometric add");
    }

    /// Removing one device of several drops only that row + its identity blob,
    /// leaving the others intact; removing the last device returns to unpaired.
    #[test]
    fn remove_device_drops_one_then_the_last() {
        let _home = HomeGuard::new("remove-one");
        let ks = MemoryKeystore::new();

        let (_i, _p, np1) = new_pairing();
        save(&ks, &np1).unwrap();
        let (_i2, _p2, np2) = new_pairing();
        let id2 = add_device(&ks, &np2, "iPad").unwrap();

        // Remove the second: the primary stays, the second's blob is reaped.
        assert!(remove_device(&ks, &id2).unwrap());
        assert!(ks.load_blob(&identity_label(&id2)).unwrap().is_none());
        assert_eq!(load_all(&ks).unwrap().len(), 1);
        assert!(exists(), "the primary remains, so the file remains");

        // An unknown id is idempotent-false.
        assert!(!remove_device(&ks, "no-such-device").unwrap());

        // Remove the last (primary): back to fully unpaired.
        assert!(remove_device(&ks, PRIMARY_DEVICE_ID).unwrap());
        assert!(!exists());
        assert!(ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_none());
        assert!(load(&ks).unwrap().is_none());
    }

    /// `remove` (unpair all) reaps EVERY device's identity blob, not just the
    /// primary's, so no per-device identity is orphaned in the keystore.
    #[test]
    fn remove_all_reaps_every_device_identity() {
        let _home = HomeGuard::new("remove-all");
        let ks = MemoryKeystore::new();
        let (_i, _p, np1) = new_pairing();
        save(&ks, &np1).unwrap();
        let (_i2, _p2, np2) = new_pairing();
        let id2 = add_device(&ks, &np2, "iPad").unwrap();

        assert!(remove(&ks).unwrap());
        assert!(!exists());
        assert!(ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_none());
        assert!(ks.load_blob(&identity_label(&id2)).unwrap().is_none());
    }

    /// Hand-write a v1 flat `pairing.json`, as the pre-#36 `save` produced, for the
    /// migration test.
    fn write_v1(v1: &PersistedPairingV1) {
        use std::os::unix::fs::PermissionsExt;
        let path = config_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(v1).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
