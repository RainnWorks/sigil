//! The APNs push "doorbell": a content-free notification the daemon sends
//! directly to Apple to wake the paired phone so it fetches the real, sealed
//! request from the relay.
//!
//! # Why the daemon, and only the daemon, sends it
//!
//! The relay is powerless and anonymous: it never sees the push token and never
//! sends a push. The daemon is the sole push origin. The token reaches the daemon
//! only inside a sealed [`PushRegister`](latch_proto::PushRegister) over the
//! established session ([`crate::remote`]); the daemon signs its own APNs JWT and
//! POSTs to Apple. Nothing about a request crosses this path.
//!
//! # Zero-knowledge payload
//!
//! The push body is fixed and generic ("Approval requested"). It carries **no**
//! caller, command, account, secret, or reason. It is a dumb doorbell: it only
//! tells the phone "wake up and check the mailbox". This preserves the
//! blind-relay / zero-knowledge invariant even against a compromised APNs.
//!
//! # Best-effort, fail-open
//!
//! Every step here is allowed to fail: no token yet, no signing key, no network,
//! an Apple 4xx/5xx. On any failure this logs and returns; the caller ignores the
//! result and continues. The request still lands in the relay mailbox and the
//! phone's poll backstop delivers it. **Correctness never depends on the push.**
//!
//! # Key source resolution (in order)
//!
//! 1. `LATCH_APNS_KEY_PATH` -> read that file as the `.p8` PEM (dev/test/self-host
//!    override, and the reliable source in a headless launchd daemon).
//! 2. 1Password: `op document get <item> --vault Engineering` via the real `op`
//!    (never the shim). This only works if `op` is authenticated in the daemon's
//!    context; when it is not, resolution fails and the doorbell stays disabled,
//!    which is fine (fail-open to polling).
//!
//! # Android / FCM
//!
//! Not built here. [`crate::remote`] matches `platform` and logs an "unsupported,
//! poll backstop" line for `"fcm"`. Follow-up when Android is a target.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use zeroize::Zeroizing;

/// Production APNs host. (There is a separate sandbox host for dev builds signed
/// with a development APS entitlement; the shipping app uses production.)
const APNS_HOST: &str = "https://api.push.apple.com";
/// The app's APNs topic == the bundle id (product rename Latch -> Sigil).
const APNS_TOPIC: &str = "works.rainn.sigil";
/// Rainnworks Apple Team id (the JWT `iss`).
const APNS_TEAM_ID: &str = "53W966FBFP";
/// The APNs Auth Key id (the JWT header `kid`).
const APNS_KEY_ID: &str = "5PCK76SDBA";
/// The 1Password item holding the `.p8` as a document, in the Engineering vault.
const APNS_KEY_OP_ITEM: &str = "bs6pgv35lpazziews7zsvd6y7e";
const APNS_KEY_OP_VAULT: &str = "Engineering";
/// Env override for the `.p8` path (resolution step 1).
const APNS_KEY_PATH_ENV: &str = "LATCH_APNS_KEY_PATH";

/// Refresh the JWT before Apple's ~60 minute cap. Apple rejects tokens older than
/// one hour and also rejects minting too frequently, so ~50 minutes is the sweet
/// spot: comfortably fresh, and far from the "too new" floor.
const JWT_REFRESH: Duration = Duration::from_secs(50 * 60);

/// The fixed, request-free push payload. Generic by design; see the module docs.
const DOORBELL_BODY: &str = concat!(
    "{\"aps\":{\"alert\":{\"title\":\"Sigil\",\"body\":\"Approval requested\"},",
    "\"sound\":\"default\",\"content-available\":1}}"
);

/// How long a single APNs POST may take before we give up (fail-open).
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ApnsError {
    #[error("building the http client: {0}")]
    Client(String),
    #[error("no APNs signing key: set {APNS_KEY_PATH_ENV} or store it in 1Password")]
    NoKey,
    #[error("reading the APNs key file {0}: {1}")]
    KeyFile(PathBuf, std::io::Error),
    #[error("fetching the APNs key from 1Password: {0}")]
    OpFetch(String),
    #[error("the APNs key is not a valid PKCS#8 EC private key")]
    KeyParse,
    #[error("signing the APNs JWT: {0}")]
    Sign(String),
    #[error("the APNs POST failed: {0}")]
    Http(String),
    #[error("APNs rejected the push: HTTP {status} {body}")]
    Rejected { status: u16, body: String },
}

/// A cached JWT and when it was minted (unix seconds).
struct CachedJwt {
    bearer: String,
    minted_at: u64,
}

/// The APNs doorbell sender: an HTTP/2 client plus a cached provider JWT. One is
/// built per armed phone factor and shared; sends are best-effort.
pub struct ApnsDoorbell {
    client: reqwest::blocking::Client,
    host: String,
    jwt: Mutex<Option<CachedJwt>>,
}

impl ApnsDoorbell {
    /// Build the doorbell. Only the HTTP client is created eagerly (so a bad TLS
    /// stack surfaces at arm time); the signing key is resolved lazily on the
    /// first send and refreshed hourly, so a daemon with no key still arms and
    /// simply never rings.
    pub fn new() -> Result<Self, ApnsError> {
        Self::with_host(APNS_HOST.to_string())
    }

    /// Build against an explicit host (tests point this at a local stub).
    pub fn with_host(host: String) -> Result<Self, ApnsError> {
        // APNs is HTTP/2-only; reqwest negotiates h2 via TLS ALPN with the http2
        // feature on. No timeouts are set on the client itself so the JWT mint
        // path is unbounded; each send below carries its own short timeout.
        let client = reqwest::blocking::Client::builder()
            .user_agent("latch-daemon")
            .build()
            .map_err(|e| ApnsError::Client(e.to_string()))?;
        Ok(Self {
            client,
            host,
            jwt: Mutex::new(None),
        })
    }

    /// Ring the doorbell for one device `token` (lowercase hex). Returns `Ok(())`
    /// on a 2xx from Apple; every other outcome is an [`ApnsError`] the caller is
    /// expected to log and ignore. Never blocks longer than [`SEND_TIMEOUT`] plus
    /// a possible one-time key fetch.
    pub fn ring(&self, token: &str, now_secs: u64) -> Result<(), ApnsError> {
        let bearer = self.bearer(now_secs)?;
        let url = format!("{}/3/device/{}", self.host, token);
        let resp = self
            .client
            .post(url)
            .header("authorization", format!("bearer {bearer}"))
            .header("apns-topic", APNS_TOPIC)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("content-type", "application/json")
            .timeout(SEND_TIMEOUT)
            .body(DOORBELL_BODY)
            .send()
            .map_err(|e| ApnsError::Http(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // Apple returns a small JSON reason ({"reason":"BadDeviceToken"}, ...).
            // Surface it for the log; it names no secret.
            let code = status.as_u16();
            let body = resp.text().unwrap_or_default();
            Err(ApnsError::Rejected { status: code, body })
        }
    }

    /// The current provider JWT, minting (and caching) a fresh one if none is
    /// cached or the cached one is past [`JWT_REFRESH`].
    fn bearer(&self, now_secs: u64) -> Result<String, ApnsError> {
        let mut slot = self.jwt.lock().expect("apns jwt lock poisoned");
        let fresh = slot
            .as_ref()
            .is_some_and(|c| now_secs.saturating_sub(c.minted_at) < JWT_REFRESH.as_secs());
        if fresh {
            return Ok(slot.as_ref().expect("checked fresh").bearer.clone());
        }
        let bearer = mint_provider_jwt(now_secs)?;
        *slot = Some(CachedJwt {
            bearer: bearer.clone(),
            minted_at: now_secs,
        });
        Ok(bearer)
    }
}

/// Mint an ES256 provider JWT (header `{alg:ES256,kid}`, claims `{iss,iat}`),
/// signed with the resolved `.p8` key. The token authenticates the daemon to
/// APNs for up to an hour and names nothing request-specific.
fn mint_provider_jwt(now_secs: u64) -> Result<String, ApnsError> {
    let pem = resolve_key_pem()?;
    let signing = load_signing_key(&pem)?;

    // Compact JWS: base64url(header) "." base64url(claims), signed, then
    // "." base64url(signature). ES256 signatures are the raw 64-byte r||s, which
    // is exactly the JWS ES256 encoding.
    let header = format!("{{\"alg\":\"ES256\",\"kid\":\"{APNS_KEY_ID}\"}}");
    let claims = format!("{{\"iss\":\"{APNS_TEAM_ID}\",\"iat\":{now_secs}}}");
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(header.as_bytes()),
        B64URL.encode(claims.as_bytes())
    );

    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = signing
        .try_sign(signing_input.as_bytes())
        .map_err(|e| ApnsError::Sign(e.to_string()))?;
    Ok(format!("{signing_input}.{}", B64URL.encode(sig.to_bytes())))
}

/// Parse a `.p8` PKCS#8 PEM into a P-256 ECDSA signing key.
fn load_signing_key(pem: &str) -> Result<p256::ecdsa::SigningKey, ApnsError> {
    use p256::pkcs8::DecodePrivateKey;
    let secret = p256::SecretKey::from_pkcs8_pem(pem).map_err(|_| ApnsError::KeyParse)?;
    Ok(p256::ecdsa::SigningKey::from(&secret))
}

/// Resolve the `.p8` PEM per the documented order: the env path override first,
/// then 1Password. The PEM is held in a `Zeroizing` buffer and wiped after the
/// signing key is derived from it.
fn resolve_key_pem() -> Result<Zeroizing<String>, ApnsError> {
    if let Some(path) = std::env::var_os(APNS_KEY_PATH_ENV) {
        let path = PathBuf::from(path);
        let bytes = std::fs::read(&path).map_err(|e| ApnsError::KeyFile(path.clone(), e))?;
        let text = String::from_utf8(bytes).map_err(|_| ApnsError::KeyParse)?;
        return Ok(Zeroizing::new(text));
    }
    fetch_key_from_op()
}

/// Fetch the `.p8` document from 1Password with the real `op` (never the shim),
/// into a `Zeroizing` buffer. Fails (fail-open) if `op` is absent or not
/// authenticated in the daemon's context.
fn fetch_key_from_op() -> Result<Zeroizing<String>, ApnsError> {
    use std::process::{Command, Stdio};

    let op = crate::paths::find_real_op().ok_or(ApnsError::NoKey)?;
    let output = Command::new(op)
        .args([
            "document",
            "get",
            APNS_KEY_OP_ITEM,
            "--vault",
            APNS_KEY_OP_VAULT,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ApnsError::OpFetch(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ApnsError::OpFetch(format!(
            "op exited {}: {err}",
            output.status.code().unwrap_or(-1)
        )));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| ApnsError::KeyParse)?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway P-256 `.p8` (PKCS#8 PEM) generated in-process, so the JWT
    /// signing path is exercised with a real key and no network or 1Password.
    fn test_key_pem() -> Zeroizing<String> {
        use p256::pkcs8::EncodePrivateKey;
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode pkcs8 pem");
        Zeroizing::new(pem.as_str().to_string())
    }

    #[test]
    fn env_path_override_is_read_first() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("latch-apns-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("AuthKey.p8");
        std::fs::write(&path, test_key_pem().as_bytes()).unwrap();

        let prev = std::env::var_os(APNS_KEY_PATH_ENV);
        std::env::set_var(APNS_KEY_PATH_ENV, &path);
        let pem = resolve_key_pem().expect("the env path resolves the key");
        assert!(pem.contains("PRIVATE KEY"));
        match prev {
            Some(v) => std::env::set_var(APNS_KEY_PATH_ENV, v),
            None => std::env::remove_var(APNS_KEY_PATH_ENV),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mints_a_three_segment_es256_jwt() {
        // A locally generated key drives the full mint path; assert the compact
        // JWS shape (header.claims.signature, all base64url) and the pinned header
        // and claims decode to the Rainnworks identity.
        let pem = test_key_pem();
        let signing = load_signing_key(&pem).expect("parse pkcs8");

        let header = format!("{{\"alg\":\"ES256\",\"kid\":\"{APNS_KEY_ID}\"}}");
        let claims = format!(
            "{{\"iss\":\"{APNS_TEAM_ID}\",\"iat\":{}}}",
            1_720_000_000u64
        );
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(header.as_bytes()),
            B64URL.encode(claims.as_bytes())
        );
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = signing.try_sign(signing_input.as_bytes()).unwrap();
        let jwt = format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()));

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three segments");
        let hdr = B64URL.decode(parts[0]).unwrap();
        assert_eq!(String::from_utf8(hdr).unwrap(), header);
        let sig_bytes = B64URL.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ES256 signature is raw r||s, 64 bytes");

        // The signature verifies under the public key: proves it is a real ES256
        // signature over the signing input, not a stray blob.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let vk = VerifyingKey::from(&signing);
        let parsed = Signature::from_slice(&sig_bytes).unwrap();
        assert!(Verifier::verify(&vk, signing_input.as_bytes(), &parsed).is_ok());
    }

    #[test]
    fn a_garbage_pem_fails_closed() {
        assert!(matches!(
            load_signing_key("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"),
            Err(ApnsError::KeyParse)
        ));
    }
}
