//! The keystore seam: secret-at-rest blob storage and a biometric presence gate.
//!
//! This trait is the single platform boundary for the opaque blobs the daemon
//! keeps at rest: the daemon identity keys and the Mac threshold share `m` (see
//! [`crate::threshold`]). It also exposes one privileged operation,
//! [`Keystore::verify_presence`], which on macOS performs a Touch-ID-gated
//! Secure Enclave op used to gate authorizing a new pairing.
//!
//! There is no data-encryption key here anymore: everything Sigil stores at rest
//! is threshold-sealed and opened per-approval with the phone's partial, so the
//! daemon holds no key that a compromise of this store could turn into a secret.
//!
//! macOS is the first fill ([`crate::keystore_macos`]); Linux (libsecret / TPM)
//! and Windows (DPAPI / TPM) are later fills of the same trait. Blob store/load
//! is exercised now through [`MemoryKeystore`], which also stands in for the
//! Secure Enclave in headless tests and the dev-approval loop.

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The biometric prompt was declined or the enclave refused the op.
    #[error("biometric presence check declined")]
    Declined,
    /// A backend (Keychain, Secure Enclave, libsecret) call failed.
    #[error("keystore backend: {0}")]
    Backend(String),
    /// The Secure Enclave / Touch-ID path exists but has never been verified on
    /// hardware; it refuses rather than pretending to work. See the module
    /// NEEDS-VERIFICATION notes.
    #[error("secure enclave path not yet verified on hardware: {0}")]
    NeedsVerification(&'static str),
    /// The on-disk store is Secure-Enclave wrapped (v2), so its bytes are
    /// ciphertext and only the running Sigil app can open them. A short-lived
    /// process (the CLI) can never read it directly; the daemon holds the opened
    /// material in RAM and is the only path to it.
    ///
    /// Worded for the human who hits it: it names the app, and it explicitly
    /// says the pairing is fine, because the failure it replaces (a JSON parse
    /// error, or a missing identity) reads exactly like "your pairing is gone"
    /// and would send someone into an unnecessary re-pair.
    #[error(
        "the keystore is sealed to the Sigil app's Secure Enclave, so this command \
         cannot read it directly. Make sure the Sigil app is running and try again. \
         Your pairing is intact: this is not a re-pair situation"
    )]
    Sealed,
}

/// Storage of encrypted blobs plus a biometric presence gate. Implementations
/// must be safe to share across daemon worker threads.
pub trait Keystore: Send + Sync {
    /// Which backend this is, for diagnostics and error messages: `file`,
    /// `memory`, or `keychain`. Named so a "nothing is stored here" error can say
    /// WHERE it looked, instead of implying the pairing is gone.
    fn backend(&self) -> &'static str;

    /// Persist an opaque blob under `label`, replacing any existing value.
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError>;

    /// Load the blob stored under `label`, or `None` if absent.
    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError>;

    /// Remove the blob stored under `label`. Absent is not an error.
    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError>;

    /// True if [`verify_presence`](Self::verify_presence) is gated by a real
    /// hardware biometric (the Secure Enclave). The pairing gate only asks a
    /// keystore to prove presence when this is true; a dev/in-memory keystore
    /// returns false so it can never masquerade as Touch ID.
    fn is_biometric(&self) -> bool {
        false
    }

    /// Prove a live hardware user-presence (Touch ID / Secure Enclave).
    /// Authorizing a new pairing calls this so accepting a device is gated on the
    /// human's biometric. This is independent of any at-rest secret: nothing is
    /// unwrapped or delivered, the enclave op only proves the human is present.
    ///
    /// The default fails **closed**: any keystore that reports
    /// [`is_biometric`](Self::is_biometric) `== true` MUST override this with a
    /// real hardware check, or the pairing gate refuses. Non-biometric dev
    /// keystores keep this default and are simply never asked: the pairing gate
    /// calls this only when `is_biometric()` is true, so `SIGIL_DEV_KEYSTORE`
    /// (which makes `is_biometric()` false, behind its own one-time notice) is the
    /// single switch that lets headless dev and tests through without a biometric.
    fn verify_presence(&self, reason: &str) -> Result<(), KeystoreError> {
        let _ = reason;
        Err(KeystoreError::Backend(
            "this keystore has no hardware user-presence check".into(),
        ))
    }
}

/// In-memory keystore. Holds blobs in RAM, wiped on drop. It is the unit-test and
/// headless-dev backend, and the stand-in for the Secure Enclave when Touch ID
/// cannot be exercised. It is **not** an at-rest secure store: nothing here
/// survives a restart, which is exactly why it is dev/test-only.
#[derive(Default)]
pub struct MemoryKeystore {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    blobs: std::collections::HashMap<String, Vec<u8>>,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keystore for MemoryKeystore {
    fn backend(&self) -> &'static str {
        "memory"
    }

    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .insert(label.to_string(), data.to_vec());
        Ok(())
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .get(label)
            .cloned())
    }

    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .remove(label);
        Ok(())
    }
}

/// A keystore that persists blobs to a 0600 JSON file at `~/.sigil/keystore.json`.
///
/// **This is the default store.** Under the threshold posture it is the correct
/// at-rest store for a portable, unsigned daemon: the only blobs it holds are the
/// daemon identity key and the Mac threshold share `m`, and neither is a
/// data-decryption secret. `m` is inert on its own (opening any sealed secret
/// also needs the phone's per-request partial), so a reader of this file still
/// cannot decrypt anything without a live phone approval. The honest residual is
/// that a reader gets both at once: see [`file_keystore_residual`].
///
/// It is portable (no platform keychain, no code signature required), which is
/// what lets one unsigned binary behave identically for the daemon and the CLI.
/// The login keychain is still reachable with `SIGIL_KEYSTORE=keychain`.
pub struct FileKeystore {
    path: std::path::PathBuf,
    inner: std::sync::Mutex<()>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct FileState {
    /// label -> base64 blob.
    blobs: std::collections::HashMap<String, String>,
}

impl FileKeystore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            inner: std::sync::Mutex::new(()),
        }
    }

    /// Where this store keeps its file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn read(&self) -> Result<FileState, KeystoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                // A wrapped (v2) store holds ciphertext, not blobs. Say that,
                // rather than letting it surface as a JSON parse error or, worse,
                // as an empty store that reads like a vanished pairing.
                if is_sealed_body(&bytes) {
                    return Err(KeystoreError::Sealed);
                }
                serde_json::from_slice(&bytes).map_err(|e| KeystoreError::Backend(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileState::default()),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    /// Write the store back.
    ///
    /// **The ordering is the security property, not an implementation detail:
    /// the mode is narrowed to 0600 while the file is still empty, and the
    /// content only ever reaches `self.path` through an atomic rename.** Writing
    /// the content first and chmodding after (which this did until 2026-08-08)
    /// publishes the daemon identity and the Mac threshold share `m` at the
    /// umask default, 0644 on a stock account, for the width of a syscall. Do
    /// not reintroduce a `fs::write(path, json)` here, and do not move the
    /// permission call below the `write_all`. Same discipline as
    /// [`crate::threshold::ThresholdStore::save`] and
    /// [`crate::keystore_seal::write_private`].
    ///
    /// The rename also means a concurrent reader sees either the whole old file
    /// or the whole new one, never a half-written store that would read as a
    /// vanished pairing.
    fn write(&self, state: &FileState) -> Result<(), KeystoreError> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let backend = |e: std::io::Error| KeystoreError::Backend(e.to_string());
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(dir).map_err(backend)?;
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| KeystoreError::Backend(e.to_string()))?;

        let tmp = dir.join(format!(
            ".{}.tmp.{}",
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "keystore.json".into()),
            std::process::id()
        ));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(backend)?;
            // `mode` above applies only when the file is created. A temp left
            // behind by a crashed writer with this pid would keep whatever mode
            // it had, so narrow it explicitly, still before any content exists.
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(backend)?;
            f.write_all(&json).map_err(backend)?;
            // The bytes must be on the platter before the rename makes them the
            // store: a crash in between should lose the write, not the pairing.
            f.sync_all().map_err(backend)?;
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(backend(e));
        }
        Ok(())
    }
}

impl Keystore for FileKeystore {
    fn backend(&self) -> &'static str {
        "file"
    }

    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let mut state = self.read()?;
        state.blobs.insert(
            label.to_string(),
            base64::engine::general_purpose::STANDARD.encode(data),
        );
        self.write(&state)
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        match self.read()?.blobs.get(label) {
            Some(b64) => Ok(Some(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| KeystoreError::Backend(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let mut state = self.read()?;
        state.blobs.remove(label);
        self.write(&state)
    }
}

/// The opened material of a wrapped (v2) keystore, held in RAM for the daemon's
/// lifetime and never written back.
///
/// This is what a provisioned daemon reads its identity and Mac share from. It
/// is deliberately **read-only**: while the store on disk is wrapped, nothing may
/// write it, because the daemon cannot re-wrap (only the app's enclave can) and a
/// plaintext write beside a wrapped file would silently undo the whole thing. So
/// every mutation refuses with [`KeystoreError::Sealed`], and the callers that
/// mutate (pairing) refuse earlier still, before they touch any file.
///
/// Values are `Zeroizing`, so the material is wiped when this drops: daemon
/// shutdown, or a replacement being provisioned.
pub struct RamKeystore {
    blobs: std::collections::HashMap<String, zeroize::Zeroizing<Vec<u8>>>,
}

impl RamKeystore {
    /// Parse opened material (the exact bytes a v1 file would hold) into a
    /// read-only in-RAM store. The input is the same JSON shape [`FileKeystore`]
    /// writes, which is what makes adoption and de-adoption lossless.
    pub fn from_material(material: &[u8]) -> Result<Self, KeystoreError> {
        use base64::Engine as _;
        use zeroize::Zeroize as _;
        // `state` holds each blob's base64 as a plain `String`, because that is
        // what serde hands back and serde has no zeroizing string. The decoded
        // bytes go straight into `Zeroizing`, and the base64 originals are wiped
        // below before `state` drops. That is as tight as this gets without a
        // hand-written deserializer; the residual is recorded in §10a.
        let mut state: FileState =
            serde_json::from_slice(material).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        let mut blobs = std::collections::HashMap::with_capacity(state.blobs.len());
        for (label, b64) in &state.blobs {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| KeystoreError::Backend(e.to_string()))?;
            blobs.insert(label.clone(), zeroize::Zeroizing::new(bytes));
        }
        for b64 in state.blobs.values_mut() {
            b64.zeroize();
        }
        Ok(Self { blobs })
    }

    /// How many blobs were opened. For logging the shape of what arrived without
    /// logging any of it.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

impl Keystore for RamKeystore {
    fn backend(&self) -> &'static str {
        "file"
    }

    fn store_blob(&self, _label: &str, _data: &[u8]) -> Result<(), KeystoreError> {
        Err(KeystoreError::Sealed)
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(self.blobs.get(label).map(|b| b.to_vec()))
    }

    fn delete_blob(&self, _label: &str) -> Result<(), KeystoreError> {
        Err(KeystoreError::Sealed)
    }
}

/// Whether these bytes are a Secure-Enclave-wrapped (v2) keystore rather than the
/// plaintext form. A cheap shape check, not a parse: any wrapped file is refused
/// by [`FileKeystore`] the same way, and the daemon does the authoritative
/// classification once at startup ([`crate::keystore_seal::KeystoreFile`]).
fn is_sealed_body(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("v").and_then(serde_json::Value::as_u64))
        .is_some_and(|v| v >= 2)
}

/// The honest residual of the default on-disk store, as ONE line, in one place so
/// `sigil up` and `sigil keystore status` cannot drift from each other.
///
/// It is a line, not a paragraph, because it is printed inside row-shaped CLI
/// output: a nine-line block with embedded newlines only indents its first line
/// and breaks the shape of whatever verb prints it. The full reasoning (why `m`
/// is inert alone, how a phished approval combines with a stolen `m` to decrypt
/// off-box) lives in this module's docs and in `docs/security-claims.md`, which
/// is where someone reading for depth is already looking.
///
/// What survives the compression is the part that changes behaviour: a reader of
/// the file gets BOTH blobs, so guard it.
pub fn file_keystore_residual() -> &'static str {
    "no standalone decryption key at rest, but a reader gets the daemon identity \
     and the inert Mac share together, so guard the file"
}

/// An honest, calm notice that a NON-DEFAULT store is active. The file store is
/// the default and gets no banner; this fires only for `memory` and `keychain`,
/// which change where a pairing lives and so must be visible. It is deliberately
/// not an alarm.
fn override_keystore_notice(mode: &str) -> String {
    let body = match mode {
        "memory" => {
            "Blobs held in plaintext RAM for this process only.\n\
                     Nothing survives a restart, so the pairing is re-created each run.\n\
                     Intended for tests and headless dev, not a persistent install.\n"
        }
        _ => {
            "Blobs held in the login keychain instead of the default on-disk store.\n\
              A pairing made here is invisible to a daemon running with the default\n\
              store, and vice versa: keep this set for every sigil process or unset\n\
              it everywhere.\n"
        }
    };
    format!("\nsigil keystore: SIGIL_KEYSTORE={mode} is active.\n{body}")
}

/// Print a notice once per process, not once per construction: the daemon
/// resolves a keystore on hot paths (each relay poll cycle re-resolves it), and a
/// repeated banner amounted to tens of megabytes of log per day while burying the
/// lines that mattered. Silent under `cfg(test)`.
#[cfg(not(test))]
fn note_once(msg: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let msg = msg.to_string();
    ONCE.call_once(move || eprintln!("{msg}"));
}

#[cfg(test)]
fn note_once(_msg: &str) {}

/// `$SIGIL_HOME`, else `~/.sigil`, else the working directory (degenerate).
fn sigil_home() -> std::path::PathBuf {
    std::env::var_os("SIGIL_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".sigil")))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// The default store's file: `$SIGIL_HOME/keystore.json`, else `~/.sigil/keystore.json`.
pub fn file_keystore_path() -> std::path::PathBuf {
    sigil_home().join("keystore.json")
}

/// The pre-default name, from when the on-disk store was a dev-only override.
fn legacy_file_keystore_path() -> std::path::PathBuf {
    sigil_home().join("dev-keystore.json")
}

/// Move a pre-default `dev-keystore.json` to the canonical `keystore.json` the
/// first time the new name is opened.
///
/// The pairing MUST survive an upgrade (never force a re-pair), and the old name
/// is where every existing install's daemon identity and Mac share `m` live. A
/// same-directory rename is atomic, so a crash mid-upgrade leaves exactly one of
/// the two names holding the blobs, never a half-copy. Absent old file, or an
/// already-present new one, is a no-op. A failure is reported and NOT fatal: the
/// caller opens the canonical path either way and a missing pairing surfaces as
/// the usual "no pairing here" error rather than a crash at startup.
fn migrate_legacy_file_keystore(from: &std::path::Path, to: &std::path::Path) -> Option<String> {
    if to.exists() || !from.exists() {
        return None;
    }
    match std::fs::rename(from, to) {
        Ok(()) => Some(format!(
            "sigil keystore: moved {} to {} (the on-disk store is now the default; \
             your pairing is unchanged)",
            from.display(),
            to.display()
        )),
        Err(e) => Some(format!(
            "sigil keystore: could not move {} to {} ({e}); the daemon will look at {} \
             and may not find your pairing. Move the file by hand.",
            from.display(),
            to.display(),
            to.display()
        )),
    }
}

/// Select the keystore for the daemon and CLI. Both must agree so the Mac
/// threshold share `m` a `sigil` command seals with is the same one the daemon
/// combines against, which is exactly why the default is not platform-dependent
/// and needs no environment to reproduce: an env-gated default is a mismatch
/// waiting to happen (a CLI in a plain shell and a daemon under launchd disagreed
/// about where the pairing lived, and the resulting error advised re-pairing).
///
/// * **Default (every platform)** -> [`FileKeystore`] at `~/.sigil/keystore.json`.
///   Portable, needs no code signature, and under the threshold posture holds no
///   standalone data-decryption secret.
/// * `SIGIL_KEYSTORE=memory` -> [`MemoryKeystore`] (ephemeral; single process).
/// * `SIGIL_KEYSTORE=keychain` -> the login-keychain store, macOS only.
/// * `SIGIL_DEV_KEYSTORE` is the deprecated spelling, still honored, with a
///   one-time notice.
///
/// Only an override prints a notice; the default is silent.
pub fn for_host() -> std::sync::Arc<dyn Keystore> {
    use std::sync::Arc;
    let (mode, deprecated) = match std::env::var("SIGIL_KEYSTORE") {
        Ok(v) if !v.is_empty() => (Some(v), false),
        _ => match std::env::var("SIGIL_DEV_KEYSTORE") {
            Ok(v) if !v.is_empty() => (Some(v), true),
            _ => (None, false),
        },
    };
    if deprecated {
        note_once(
            "sigil keystore: SIGIL_DEV_KEYSTORE is deprecated; use SIGIL_KEYSTORE \
             (file|memory|keychain). The on-disk store is now the default, so for \
             `file` you can simply unset it.",
        );
    }
    match mode.as_deref() {
        Some("memory") => {
            note_once(&override_keystore_notice("memory"));
            Arc::new(MemoryKeystore::new())
        }
        #[cfg(target_os = "macos")]
        Some("keychain") => {
            note_once(&override_keystore_notice("keychain"));
            Arc::new(crate::keystore_macos::MacKeystore::new())
        }
        // `file` names the default explicitly. Anything unrecognized also lands
        // on the default rather than failing a process over a typo, but it says
        // so: silently selecting a different store is how `SIGIL_KEYSTORE=keychian`
        // becomes "no pairing" becomes an unnecessary re-pair that orphans the
        // real one. Name what was asked for and what was chosen.
        other => {
            if let Some(asked) = other.filter(|v| *v != "file") {
                note_once(&format!(
                    "\nsigil keystore: SIGIL_KEYSTORE={asked} is not a store this build knows \
                     (file|memory|keychain).\nUsing the default on-disk store. If you meant a \
                     different one, fix the spelling: a pairing made under another store is \
                     invisible from here, and that reads like a missing pairing.\n"
                ));
            }
            let path = file_keystore_path();
            if let Some(msg) = migrate_legacy_file_keystore(&legacy_file_keystore_path(), &path) {
                note_once(&msg);
            }
            Arc::new(FileKeystore::new(path))
        }
    }
}

/// What a caller should do about proving a live human is present, given the
/// active store. Storing blobs and proving presence are separate capabilities,
/// and promoting the on-disk store split them apart: the file store is not
/// hardware-backed, but the HOST it runs on can still raise a Touch ID prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePlan {
    /// Ask the store itself (a hardware-backed store proves its own presence).
    AskStore,
    /// Ask the host (the store cannot, but this platform has a presence check).
    AskHost,
    /// Nothing to ask: this host offers no presence check, so a caller that
    /// requires one has nothing to demand and proceeds. Its real gate is
    /// elsewhere (for pairing: the optical QR and the SAS confirmation).
    None,
}

/// How to prove presence for a store with this `backend`/`is_biometric`.
///
/// Split out as a pure function so the decision is testable without raising a
/// system prompt. The in-memory store deliberately lands on `None`, which is what
/// keeps headless tests and dev from blocking on a biometric.
pub fn presence_plan(backend: &str, is_biometric: bool) -> PresencePlan {
    if is_biometric {
        return PresencePlan::AskStore;
    }
    if backend == "file" && cfg!(target_os = "macos") {
        return PresencePlan::AskHost;
    }
    PresencePlan::None
}

/// Ask the host for a live human presence (Touch ID), independent of where blobs
/// are stored. `Ok(())` means a human was verified; an error means declined or
/// unavailable, and callers gate on it.
///
/// This exists because the default store moved to a plain file. The Touch ID
/// check the pairing ceremony runs was never about the keychain: on macOS it is
/// `LAContext.evaluatePolicy`, which needs no keychain, no Secure Enclave, and no
/// code signature. Tying it to the storage backend would have quietly deleted the
/// gate the moment storage changed.
pub fn verify_host_presence(reason: &str) -> Result<(), KeystoreError> {
    #[cfg(target_os = "macos")]
    {
        crate::keystore_macos::MacKeystore::new().verify_presence(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Err(KeystoreError::Backend(
            "this host has no presence check".into(),
        ))
    }
}

/// One line to log when a pairing appears to be stranded in the login keychain:
/// the default on-disk store has no daemon identity, but the keychain does.
///
/// Deliberately a REPORT, not a migration. Reading a keychain item can prompt,
/// and a startup path that pops a system dialog is not a startup path; so this
/// says what exists and what to do, and the human decides. Returns `None` when
/// the file store is populated (the normal case), on non-macOS, and whenever the
/// keychain cannot be read at all.
pub fn legacy_keychain_notice(active: &dyn Keystore) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        use crate::pairing_store::DAEMON_IDENTITY_LABEL;
        // Only when the active store is the default file store and it is empty.
        if active.backend() != "file"
            || active
                .load_blob(DAEMON_IDENTITY_LABEL)
                .ok()
                .flatten()
                .is_some()
        {
            return None;
        }
        let keychain = crate::keystore_macos::MacKeystore::new();
        keychain.load_blob(DAEMON_IDENTITY_LABEL).ok().flatten()?;
        Some(
            "sigil keystore: a daemon identity from an older build is still in the login \
             keychain, and the default on-disk store is empty. Nothing was moved \
             automatically. To keep using that pairing, run sigil with \
             SIGIL_KEYSTORE=keychain set everywhere; to start fresh on the default \
             store, run: sigil pair"
                .to_string(),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = active;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_store_load_delete() {
        let ks = MemoryKeystore::new();
        assert!(ks.load_blob("id.key").unwrap().is_none());
        ks.store_blob("id.key", b"\x01\x02\x03").unwrap();
        assert_eq!(ks.load_blob("id.key").unwrap().unwrap(), b"\x01\x02\x03");
        // Replace.
        ks.store_blob("id.key", b"\x04").unwrap();
        assert_eq!(ks.load_blob("id.key").unwrap().unwrap(), b"\x04");
        ks.delete_blob("id.key").unwrap();
        assert!(ks.load_blob("id.key").unwrap().is_none());
        // Deleting an absent blob is fine.
        ks.delete_blob("id.key").unwrap();
    }

    #[test]
    fn memory_keystore_is_not_a_biometric_factor() {
        assert!(!MemoryKeystore::new().is_biometric());
        // And it never proves presence, so it can never masquerade as Touch ID.
        assert!(MemoryKeystore::new().verify_presence("x").is_err());
    }

    #[test]
    fn file_keystore_persists_blobs_across_instances() {
        let dir = std::env::temp_dir().join(format!("sigil-ks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");

        let a = FileKeystore::new(path.clone());
        a.store_blob("id.key", b"blobby").unwrap();

        // A fresh instance (as if a second process) sees the same blob.
        let b = FileKeystore::new(path.clone());
        assert_eq!(b.load_blob("id.key").unwrap().unwrap(), b"blobby");
        assert!(!b.is_biometric());
        assert_eq!(b.backend(), "file");

        // File is 0600.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_store_lands_on_a_fresh_0600_inode_instead_of_being_widened_in_place() {
        // The daemon identity and the Mac share must never exist in a file that
        // anyone but the owner can read, not even for the width of a syscall.
        // Observing that window directly would be a racy test, so this asserts
        // the mechanism that removes it: the content reaches the destination
        // only by renaming a file that was 0600 before it held a byte. Put a
        // world-readable file at the destination first, and the inode must
        // CHANGE. A write-then-chmod implementation keeps the inode (and holds
        // the content at 0666 until the chmod), so it fails here deterministically
        // rather than depending on the ambient umask or on timing.
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = std::env::temp_dir().join(format!(
            "sigil-ks-mode-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        std::fs::write(&path, b"{\"blobs\":{}}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let wide_inode = std::fs::metadata(&path).unwrap().ino();

        FileKeystore::new(path.clone())
            .store_blob("pairing.daemon-identity.v1", b"the-identity")
            .unwrap();

        let after = std::fs::metadata(&path).unwrap();
        assert_ne!(
            wide_inode,
            after.ino(),
            "the content must land on a new file, never be written into the world-readable one"
        );
        assert_eq!(after.permissions().mode() & 0o777, 0o600);

        // And the temp the rename came from is gone, not left holding a copy.
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "keystore.json")
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A private home for one selection test, so these can set `SIGIL_HOME` and
    /// the keystore env without stepping on each other or on the real `~/.sigil`.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        dir: std::path::PathBuf,
        prev_home: Option<std::ffi::OsString>,
        prev_new: Option<std::ffi::OsString>,
        prev_old: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn new(tag: &str) -> Self {
            let lock = crate::TEST_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "sigil-kssel-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let g = Self {
                _lock: lock,
                prev_home: std::env::var_os("SIGIL_HOME"),
                prev_new: std::env::var_os("SIGIL_KEYSTORE"),
                prev_old: std::env::var_os("SIGIL_DEV_KEYSTORE"),
                dir,
            };
            std::env::set_var("SIGIL_HOME", &g.dir);
            std::env::remove_var("SIGIL_KEYSTORE");
            std::env::remove_var("SIGIL_DEV_KEYSTORE");
            g
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let restore = |k: &str, v: &Option<std::ffi::OsString>| match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            };
            restore("SIGIL_HOME", &self.prev_home);
            restore("SIGIL_KEYSTORE", &self.prev_new);
            restore("SIGIL_DEV_KEYSTORE", &self.prev_old);
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    #[test]
    fn the_default_store_is_the_on_disk_file_with_no_environment_at_all() {
        // The whole point of the promotion: a plain shell and a launchd daemon
        // resolve the same store without either of them setting anything.
        let g = EnvGuard::new("default");
        let ks = for_host();
        assert_eq!(ks.backend(), "file");
        assert!(
            !ks.is_biometric(),
            "the file store is not a biometric factor"
        );
        assert_eq!(file_keystore_path(), g.dir.join("keystore.json"));

        // And it is really usable at that path.
        ks.store_blob("id.key", b"x").unwrap();
        assert!(g.dir.join("keystore.json").exists());
    }

    #[test]
    fn a_pre_default_dev_keystore_is_migrated_in_place() {
        // Pairing durability: an install whose blobs live under the old dev-only
        // name must keep working after the upgrade, with no re-pair.
        let g = EnvGuard::new("migrate");
        let old = g.dir.join("dev-keystore.json");
        FileKeystore::new(old.clone())
            .store_blob("pairing.daemon-identity.v1", b"the-old-identity")
            .unwrap();

        let ks = for_host();
        assert_eq!(
            ks.load_blob("pairing.daemon-identity.v1").unwrap().unwrap(),
            b"the-old-identity",
            "the existing pairing must survive the rename"
        );
        assert!(!old.exists(), "the old file is moved, not copied");
        assert!(g.dir.join("keystore.json").exists());

        // Idempotent: a second open has nothing left to move and still reads.
        assert!(for_host()
            .load_blob("pairing.daemon-identity.v1")
            .unwrap()
            .is_some());
    }

    #[test]
    fn migration_never_overwrites_an_existing_canonical_store() {
        // If both names exist, the canonical one is the truth; the stale old file
        // is left alone rather than clobbering a newer pairing.
        let g = EnvGuard::new("migrate-both");
        let old = g.dir.join("dev-keystore.json");
        let new = g.dir.join("keystore.json");
        FileKeystore::new(old.clone())
            .store_blob("k", b"old")
            .unwrap();
        FileKeystore::new(new.clone())
            .store_blob("k", b"new")
            .unwrap();

        assert_eq!(for_host().load_blob("k").unwrap().unwrap(), b"new");
        assert!(
            old.exists(),
            "the stale file is left for the human to remove"
        );
    }

    #[test]
    fn the_env_override_selects_memory_under_either_spelling() {
        let _g = EnvGuard::new("override");
        std::env::set_var("SIGIL_KEYSTORE", "memory");
        assert_eq!(for_host().backend(), "memory");

        // The deprecated spelling still works, so an old shell profile or an old
        // launchd plist does not silently change which store is in play.
        std::env::remove_var("SIGIL_KEYSTORE");
        std::env::set_var("SIGIL_DEV_KEYSTORE", "memory");
        assert_eq!(for_host().backend(), "memory");

        // The new spelling wins when both are set.
        std::env::set_var("SIGIL_KEYSTORE", "file");
        assert_eq!(for_host().backend(), "file");
    }

    #[test]
    fn file_is_the_default_for_an_empty_or_unrecognized_value() {
        // A typo must not strand a process on some other store: the default is
        // fail-safe, and a wrong guess would surface as a missing pairing.
        let _g = EnvGuard::new("typo");
        std::env::set_var("SIGIL_KEYSTORE", "flie");
        assert_eq!(for_host().backend(), "file");
        std::env::set_var("SIGIL_KEYSTORE", "");
        assert_eq!(for_host().backend(), "file");
    }

    #[test]
    fn only_an_override_gets_a_banner_and_it_names_the_new_variable() {
        // The default is silent (it is not a deviation), and the overrides that
        // move where a pairing lives say so in the new spelling.
        let memory = override_keystore_notice("memory");
        assert!(memory.contains("SIGIL_KEYSTORE=memory"));
        assert!(memory.contains("plaintext RAM"));
        assert!(!memory.contains("SIGIL_DEV_KEYSTORE"));

        let keychain = override_keystore_notice("keychain");
        assert!(keychain.contains("SIGIL_KEYSTORE=keychain"));
        assert!(keychain.contains("login keychain"));
    }

    #[test]
    fn presence_is_asked_of_the_host_when_the_store_cannot_prove_it() {
        // Promoting the file store must not delete the pairing presence gate.
        // Storage and presence are separate capabilities: a hardware store proves
        // its own, the file store cannot but macOS can, and the in-memory store
        // has nothing to ask (which is what keeps tests and Linux headless).
        assert_eq!(presence_plan("keychain", true), PresencePlan::AskStore);
        assert_eq!(presence_plan("memory", false), PresencePlan::None);
        let file = presence_plan("file", false);
        if cfg!(target_os = "macos") {
            assert_eq!(file, PresencePlan::AskHost, "macOS can still prompt");
        } else {
            assert_eq!(file, PresencePlan::None, "no presence check to demand");
        }
    }

    #[test]
    fn the_file_store_residual_stays_honest_and_fits_one_line() {
        // Compressed to a line for CLI use, but it must still carry the part that
        // changes behaviour: no standalone decryption key, AND the fact that a
        // reader gets both blobs at once (F9). Not an alarm, not falsely
        // reassuring, and not a paragraph that breaks a row-shaped verb.
        let r = file_keystore_residual();
        assert!(r.contains("no standalone decryption key"), "{r}");
        assert!(r.contains("identity"), "{r}");
        assert!(r.contains("inert"), "{r}");
        assert!(
            r.contains("together"),
            "names the both-at-once residual: {r}"
        );
        assert!(r.contains("guard the file"), "{r}");
        assert!(!r.contains("RISK"), "no scare framing");
        assert!(!r.contains('\n'), "one line, so callers can indent it: {r}");
        assert!(r.len() < 160, "short enough for one terminal line: {r}");
    }
}
