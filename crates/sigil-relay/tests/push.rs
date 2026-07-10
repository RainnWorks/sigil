//! Doorbell tests, mirroring relay/shared/push.test.ts: a real ES256 JWT minted
//! against a throwaway P-256 key and verified, the fixed request-free body, and
//! the fail-open paths (Apple rejection swallowed, fcm/no-key make no call).

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use tokio::net::TcpListener;

use sigil_relay::push::{send_push_direct, ApnsIdentity};

#[derive(Clone, Default)]
struct Captured {
    authorization: String,
    topic: String,
    push_type: String,
    priority: String,
    body: String,
    hit: bool,
}

/// A tiny local APNs stub. Captures the one request it receives and replies
/// with `status`. Returns (host_url, shared capture cell).
async fn spawn_stub(status: u16) -> (String, Arc<Mutex<Captured>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cap = Arc::new(Mutex::new(Captured::default()));
    let cap2 = cap.clone();
    tokio::spawn(async move {
        // One connection is enough for these single-shot tests.
        if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let cap = cap2.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let cap = cap.clone();
                async move {
                    let h = req.headers().clone();
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(|b| b.to_bytes())
                        .unwrap_or_default();
                    let mut c = cap.lock().unwrap();
                    c.hit = true;
                    c.authorization = header(&h, "authorization");
                    c.topic = header(&h, "apns-topic");
                    c.push_type = header(&h, "apns-push-type");
                    c.priority = header(&h, "apns-priority");
                    c.body = String::from_utf8_lossy(&body).to_string();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from_static(b"")))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        }
    });
    (format!("http://{addr}"), cap)
}

fn header(h: &hyper::HeaderMap, k: &str) -> String {
    h.get(k)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// A deterministic throwaway P-256 key and its PKCS#8 PEM (as `.p8` would be).
fn test_key() -> (String, VerifyingKey) {
    let secret = SecretKey::from_slice(&[2u8; 32]).expect("valid scalar");
    let signing = SigningKey::from(secret.clone());
    let verifying = *signing.verifying_key();
    let der = secret.to_pkcs8_der().expect("pkcs8");
    let b64 = B64_STD.encode(der.as_bytes());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    (pem, verifying)
}

fn b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rings_a_real_es256_jwt_with_the_pinned_identity() {
    let (pem, verifying) = test_key();
    let (host, cap) = spawn_stub(200).await;
    send_push_direct(
        "deadbeef".into(),
        Some("apns".into()),
        Some(pem),
        ApnsIdentity::default(),
        host,
        1_700_000_000_000,
    )
    .await;
    // Give the detached response a beat (send_push_direct awaits it, so it is
    // already captured by return).
    let c = cap.lock().unwrap().clone();
    assert!(c.hit);
    let jwt = c
        .authorization
        .strip_prefix("bearer ")
        .expect("bearer prefix");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value = serde_json::from_slice(&b64url(parts[0])).unwrap();
    assert_eq!(
        header,
        serde_json::json!({ "alg": "ES256", "kid": "5PCK76SDBA" })
    );
    let claims: serde_json::Value = serde_json::from_slice(&b64url(parts[1])).unwrap();
    assert_eq!(
        claims.get("iss").and_then(|v| v.as_str()),
        Some("53W966FBFP")
    );
    assert!(claims.get("iat").and_then(|v| v.as_u64()).is_some());
    // The signature verifies over "header.claims" with the matching public key.
    let sig = Signature::from_slice(&b64url(parts[2])).unwrap();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    assert!(verifying.verify(signing_input.as_bytes(), &sig).is_ok());
    assert_eq!(c.topic, "works.rainn.sigil");
    assert_eq!(c.push_type, "alert");
    assert_eq!(c.priority, "10");
    let body: serde_json::Value = serde_json::from_str(&c.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "aps": {
                "alert": { "title": "Sigil", "body": "Approval requested" },
                "sound": "default",
                "content-available": 1
            }
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_from_apple_is_swallowed() {
    let (pem, _) = test_key();
    let (host, _cap) = spawn_stub(400).await;
    // Must simply return, never panic or error.
    send_push_direct(
        "deadbeef".into(),
        Some("apns".into()),
        Some(pem),
        ApnsIdentity::default(),
        host,
        1,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fcm_is_a_stub_no_network_call() {
    let (host, cap) = spawn_stub(200).await;
    send_push_direct(
        "deadbeef".into(),
        Some("fcm".into()),
        Some("irrelevant".into()),
        ApnsIdentity::default(),
        host,
        1,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!cap.lock().unwrap().hit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_key_no_network_call() {
    let (host, cap) = spawn_stub(200).await;
    send_push_direct(
        "deadbeef".into(),
        Some("apns".into()),
        None,
        ApnsIdentity::default(),
        host,
        1,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!cap.lock().unwrap().hit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undefined_platform_defaults_to_apns() {
    let (pem, _) = test_key();
    let (host, cap) = spawn_stub(200).await;
    send_push_direct(
        "deadbeef".into(),
        None,
        Some(pem),
        ApnsIdentity::default(),
        host,
        1,
    )
    .await;
    assert!(cap.lock().unwrap().hit);
}

/// The default identity (no env override) is byte-for-byte the pinned official
/// values, so a build with no APNS_* env set is unchanged from the compiled-in
/// constants that preceded this parameterization.
#[test]
fn default_identity_is_the_pinned_official_values() {
    let id = ApnsIdentity::default();
    assert_eq!(id.topic, "works.rainn.sigil");
    assert_eq!(id.team_id, "53W966FBFP");
    assert_eq!(id.key_id, "5PCK76SDBA");
}

/// A self-hoster's overridden identity flows all the way into the wire push: the
/// `apns-topic` header, and the JWT's `kid` (header) and `iss` (claims).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overridden_identity_rides_the_wire() {
    let (pem, _) = test_key();
    let (host, cap) = spawn_stub(200).await;
    let id = ApnsIdentity {
        topic: "com.example.self".into(),
        team_id: "TEAM123456".into(),
        key_id: "KEYID98765".into(),
    };
    send_push_direct(
        "deadbeef".into(),
        Some("apns".into()),
        Some(pem),
        id,
        host,
        1_700_000_000_001,
    )
    .await;
    let c = cap.lock().unwrap().clone();
    assert!(c.hit);
    assert_eq!(c.topic, "com.example.self");
    let jwt = c.authorization.strip_prefix("bearer ").expect("bearer");
    let parts: Vec<&str> = jwt.split('.').collect();
    let header: serde_json::Value = serde_json::from_slice(&b64url(parts[0])).unwrap();
    assert_eq!(
        header.get("kid").and_then(|v| v.as_str()),
        Some("KEYID98765")
    );
    let claims: serde_json::Value = serde_json::from_slice(&b64url(parts[1])).unwrap();
    assert_eq!(
        claims.get("iss").and_then(|v| v.as_str()),
        Some("TEAM123456")
    );
}

/// `ApnsIdentity::from_env` reads the three vars, each falling back to its
/// pinned default when unset. This test owns these vars (no other test touches
/// them) and restores the environment before returning.
#[test]
fn from_env_overrides_and_defaults() {
    // Unset: every field is the pinned default.
    std::env::remove_var("APNS_TOPIC");
    std::env::remove_var("APNS_TEAM_ID");
    std::env::remove_var("APNS_KEY_ID");
    assert_eq!(ApnsIdentity::from_env(), ApnsIdentity::default());

    // Set: each field is taken from its var.
    std::env::set_var("APNS_TOPIC", "com.acme.relay");
    std::env::set_var("APNS_TEAM_ID", "ACME000000");
    std::env::set_var("APNS_KEY_ID", "ACMEKEY999");
    let id = ApnsIdentity::from_env();
    assert_eq!(id.topic, "com.acme.relay");
    assert_eq!(id.team_id, "ACME000000");
    assert_eq!(id.key_id, "ACMEKEY999");

    // An empty value falls back to the default, not the empty string.
    std::env::set_var("APNS_TOPIC", "");
    assert_eq!(ApnsIdentity::from_env().topic, "works.rainn.sigil");

    std::env::remove_var("APNS_TOPIC");
    std::env::remove_var("APNS_TEAM_ID");
    std::env::remove_var("APNS_KEY_ID");
}
