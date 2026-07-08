//! The doorbell: a content-free notification that wakes a paired phone so it
//! drains the real, sealed request waiting for it. Rust port of
//! `relay/shared/push.ts`, plus the pluggable knock modes for self-hosting.
//!
//! Zero-knowledge payload: the push body is fixed and generic ("Approval
//! requested"). It carries no caller, command, account, secret, or reason; it
//! only tells the phone "check the mailbox". Best-effort, fail-open: every
//! failure here is logged and swallowed. The deposit that triggered it has
//! already succeeded, and the phone's own poll backstop covers a missed push.
//! Correctness never depends on this module.
//!
//! Knock modes ([`KnockMode`]):
//!
//! - `direct`: this relay holds the APNs auth key and sends the wake itself.
//! - `upstream`: this relay holds NO Apple key; it forwards an opaque knock
//!   (`{opaque_token, mailbox_hash}`) to a configured upstream relay's `/knock`,
//!   which does the actual APNs send. This lets a self-hosted message relay keep
//!   the background doorbell for official-app users without the publisher's cert.
//! - `off`: no doorbell; clients fall back to their foreground poll.
//!
//! The knock forwarded upstream is powerless: only the opaque APNs token plus
//! the mailbox hash (for the upstream's rate bucket), never message content. An
//! upstream knock relay therefore learns only the opaque token and that *some*
//! mailbox has traffic; it cannot read, forge, or attribute anything.

use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use tokio::sync::OnceCell;

pub const APNS_HOST: &str = "https://api.push.apple.com";
const APNS_TOPIC: &str = "works.rainn.sigil";
const APNS_TEAM_ID: &str = "53W966FBFP";
const APNS_KEY_ID: &str = "5PCK76SDBA";

/// Refresh the JWT before Apple's ~60 minute cap; ~50 minutes is the sweet spot.
const JWT_REFRESH_MS: u64 = 50 * 60 * 1000;
/// How long a single APNs / upstream POST may take before giving up (fail-open).
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// The fixed, request-free push payload. Byte-identical to `push.ts`'s.
const DOORBELL_BODY: &str = r#"{"aps":{"alert":{"title":"Sigil","body":"Approval requested"},"sound":"default","content-available":1}}"#;

/// How this relay rings the doorbell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KnockMode {
    Direct,
    Upstream,
    Off,
}

/// One shared reqwest client, built lazily the first time a doorbell actually
/// fires. At idle (no configured doorbell, or no deposit yet) it is never
/// constructed, so it costs nothing toward the "free to run" footprint.
static CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();

async fn client() -> &'static reqwest::Client {
    CLIENT
        .get_or_init(|| async {
            reqwest::Client::builder()
                .timeout(SEND_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
        .await
}

/// A cached provider JWT, so a repeated ring within the refresh window neither
/// re-parses the PEM nor re-signs. Keyed loosely by the PEM string; if it
/// changes, the cache just misses and re-signs.
struct Cached {
    pem: String,
    bearer: String,
    minted_at: u64,
}

static JWT_CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// Decode a PKCS#8 `.p8` PEM into a P-256 signing key.
fn signing_key_from_pem(pem: &str) -> Result<SigningKey, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .split_whitespace()
        .collect();
    let der = B64_STD
        .decode(body.as_bytes())
        .map_err(|e| format!("base64: {e}"))?;
    let sk = p256::SecretKey::from_pkcs8_der(&der).map_err(|e| format!("pkcs8: {e}"))?;
    Ok(SigningKey::from(sk))
}

/// Mint (ES256, header `{alg,kid}`, claims `{iss,iat}`) or reuse a cached
/// provider JWT. The ECDSA signature is the raw 64-byte `r||s` that JWS ES256
/// requires, so no re-encoding is needed.
fn bearer(pem: &str, now_ms: u64) -> Result<String, String> {
    {
        let guard = JWT_CACHE
            .lock()
            .map_err(|_| "jwt cache poisoned".to_string())?;
        if let Some(c) = guard.as_ref() {
            if c.pem == pem && now_ms.saturating_sub(c.minted_at) < JWT_REFRESH_MS {
                return Ok(c.bearer.clone());
            }
        }
    }
    let key = signing_key_from_pem(pem)?;
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{APNS_KEY_ID}"}}"#));
    let claims = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"iss":"{APNS_TEAM_ID}","iat":{}}}"#,
        now_ms / 1000
    ));
    let signing_input = format!("{header}.{claims}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    if let Ok(mut guard) = JWT_CACHE.lock() {
        *guard = Some(Cached {
            pem: pem.to_string(),
            bearer: jwt.clone(),
            minted_at: now_ms,
        });
    }
    Ok(jwt)
}

/// Ring the APNs doorbell for one device token (lowercase hex). Never returns an
/// error to the caller: every failure is logged and swallowed. `host` is
/// overridable so tests can point this at a local stub.
pub async fn ring_apns(token: &str, key_pem: &str, now_ms: u64, host: &str) {
    let jwt = match bearer(key_pem, now_ms) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("push: minting the APNs JWT failed, relying on the poll backstop: {e}");
            return;
        }
    };
    let url = format!("{host}/3/device/{token}");
    let res = client()
        .await
        .post(&url)
        .header("authorization", format!("bearer {jwt}"))
        .header("apns-topic", APNS_TOPIC)
        .header("apns-push-type", "alert")
        .header("apns-priority", "10")
        .header("content-type", "application/json")
        .body(DOORBELL_BODY)
        .send()
        .await;
    match res {
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            eprintln!("push: apns rejected the doorbell: {status} {text}");
        }
        Ok(_) => {}
        Err(e) => eprintln!("push: apns doorbell failed, relying on the poll backstop: {e}"),
    }
}

/// Direct-mode dispatch for one deposit's optional push token: sign + POST to
/// APNs ourselves. `platform` other than `"apns"` (e.g. `"fcm"`) is a stub:
/// logged and skipped, no network call, matching `push.ts`.
pub async fn send_push_direct(
    token: String,
    platform: Option<String>,
    key_pem: Option<String>,
    host: String,
    now_ms: u64,
) {
    if platform.as_deref() == Some("fcm") {
        eprintln!("push: fcm not implemented yet, relying on the poll backstop");
        return;
    }
    let Some(pem) = key_pem else {
        eprintln!("push: no APNs signing key configured, relying on the poll backstop");
        return;
    };
    ring_apns(&token, &pem, now_ms, &host).await;
}

/// Upstream-mode dispatch: forward an opaque knock to a configured upstream
/// relay's `/knock`. Best-effort, fail-open; carries only the opaque token, the
/// mailbox hash, and the platform tag — never any message content.
pub async fn forward_knock(
    upstream: String,
    token: String,
    mailbox_hash: String,
    platform: Option<String>,
) {
    let url = format!("{}/knock", upstream.trim_end_matches('/'));
    let body = serde_json::json!({
        "opaque_token": token,
        "mailbox_hash": mailbox_hash,
        "platform": platform.unwrap_or_else(|| "apns".to_string()),
    })
    .to_string();
    let res = client()
        .await
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
    match res {
        Ok(resp) if !resp.status().is_success() => {
            eprintln!(
                "push: upstream knock rejected: {} (relying on the poll backstop)",
                resp.status()
            );
        }
        Ok(_) => {}
        Err(e) => eprintln!("push: upstream knock failed, relying on the poll backstop: {e}"),
    }
}
