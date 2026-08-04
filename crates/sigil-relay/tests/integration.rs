//! HTTP integration tests: spin the real server on an ephemeral loopback port
//! and drive it with reqwest, mirroring relay/test/worker.test.ts and
//! relay/bun/server.test.ts so the native relay is checked against the same
//! wire contract. The long-poll window is shrunk (150ms) so an empty GET
//! resolves quickly instead of the real ~25s.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sigil_relay::push::KnockMode;
use sigil_relay::server::{AppState, Config};
use tokio::net::TcpListener;

const LONG_POLL_MS: u64 = 150;

fn test_config() -> Config {
    Config {
        knock_mode: KnockMode::Off,
        knock_upstream: None,
        apns_key: None,
        apns_identity: sigil_relay::push::ApnsIdentity::default(),
        apns_host: "http://127.0.0.1:0".to_string(),
        long_poll_ms: LONG_POLL_MS,
        trusted_proxy_hops: 0,
    }
}

/// A relay configured to believe `hops` trusted proxies sit in front of it, so
/// the forwarded-header path can be driven end to end.
fn config_behind_proxies(hops: usize) -> Config {
    Config {
        trusted_proxy_hops: hops,
        ..test_config()
    }
}

/// Bind a relay on a random loopback port and serve it on a background task.
async fn spawn(config: Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = AppState::new(config);
    tokio::spawn(async move { sigil_relay::serve(state, listener).await });
    format!("http://{addr}")
}

static MB_SEQ: AtomicU64 = AtomicU64::new(1);
fn mailbox_id() -> String {
    // Any unique 64-lowercase-hex string isolates a mailbox; a counter suffices.
    let n = MB_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{n:064x}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().build().expect("client")
}

async fn to_phone(
    c: &reqwest::Client,
    base: &str,
    id: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    c.post(format!("{base}/mailbox/{id}/to-phone"))
        .json(&body)
        .send()
        .await
        .expect("to-phone post")
}

async fn to_daemon(
    c: &reqwest::Client,
    base: &str,
    id: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    c.post(format!("{base}/mailbox/{id}/to-daemon"))
        .json(&body)
        .send()
        .await
        .expect("to-daemon post")
}

async fn get(c: &reqwest::Client, base: &str, id: &str, verb: &str) -> reqwest::Response {
    c.get(format!("{base}/mailbox/{id}/{verb}"))
        .send()
        .await
        .expect("get")
}

/// POST a to-phone deposit wearing a forwarded chain, the way a reverse proxy
/// (or a client trying to forge one) would present it.
async fn to_phone_forwarded(
    c: &reqwest::Client,
    base: &str,
    id: &str,
    body: serde_json::Value,
    forwarded_for: &str,
) -> reqwest::Response {
    c.post(format!("{base}/mailbox/{id}/to-phone"))
        .header("x-forwarded-for", forwarded_for)
        .json(&body)
        .send()
        .await
        .expect("to-phone post")
}

async fn drain_body(resp: reqwest::Response) -> serde_json::Value {
    resp.json().await.expect("json")
}

/// The `origins[i]` entry of a drain body, or `None` when the relay recorded
/// nothing (the whole key is omitted in that case).
fn origin_at(body: &serde_json::Value, i: usize) -> Option<serde_json::Value> {
    body.get("origins")?.as_array()?.get(i).cloned()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

async fn envelopes(resp: reqwest::Response) -> Vec<String> {
    let v: serde_json::Value = resp.json().await.expect("json");
    v.get("envelopes")
        .and_then(|e| e.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_a_bare_liveness_body() {
    let base = spawn(test_config()).await;
    let c = client();
    let v: serde_json::Value = c
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v,
        serde_json::json!({ "ok": true, "service": "sigil-relay" })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn landing_is_served_as_html() {
    let base = spawn(test_config()).await;
    let c = client();
    let resp = c.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("<title>Sigil relay</title>"));
    assert!(body.contains("coat check")); // the ELI5 landing metaphor
    assert!(!body.contains("{{")); // static, no templating tokens
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_reports_version_and_commit() {
    let base = spawn(test_config()).await;
    let c = client();
    let v: serde_json::Value = c
        .get(format!("{base}/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v.get("version").and_then(|x| x.as_str()), Some("0.1.0"));
    assert!(v.get("git_commit").and_then(|x| x.as_str()).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_mailbox_id() {
    let base = spawn(test_config()).await;
    let c = client();
    let resp = get(&c, &base, "not-hex", "to-phone").await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn to_phone_deposit_then_drain_then_empty() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let env = r#"{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}"#;
    let resp = to_phone(&c, &base, &id, serde_json::json!({ "env": env })).await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v, serde_json::json!({ "ok": true }));
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-phone").await).await,
        vec![env]
    );
    // Nothing queued now: this long-polls and times out to empty.
    assert!(envelopes(get(&c, &base, &id, "to-phone").await)
        .await
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_poll_resolves_on_deposit_before_timeout() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let started = Instant::now();
    let held = {
        let c = c.clone();
        let base = base.clone();
        let id = id.clone();
        tokio::spawn(async move { envelopes(get(&c, &base, &id, "to-phone").await).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    to_phone(&c, &base, &id, serde_json::json!({ "env": "woke-it-up" })).await;
    let body = held.await.unwrap();
    assert_eq!(body, vec!["woke-it-up"]);
    assert!(started.elapsed() < Duration::from_millis(LONG_POLL_MS)); // woken, not timed out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lone_long_poll_holds_the_full_window() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let started = Instant::now();
    let body = envelopes(get(&c, &base, &id, "to-phone").await).await;
    assert!(body.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(LONG_POLL_MS * 6 / 10)); // held, not fast
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_concurrent_gets_newest_gets_the_deposit_other_holds() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let spawn_get = || {
        let c = c.clone();
        let base = base.clone();
        let id = id.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let e = envelopes(get(&c, &base, &id, "to-phone").await).await;
            (e, started.elapsed())
        })
    };
    let first = spawn_get();
    let second = spawn_get();
    tokio::time::sleep(Duration::from_millis(20)).await;
    to_phone(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "for-the-newest" }),
    )
    .await;

    let (b1, t1) = first.await.unwrap();
    let (b2, t2) = second.await.unwrap();
    let bodies = [b1.clone(), b2.clone()];
    assert!(bodies.contains(&vec!["for-the-newest".to_string()]));
    assert!(bodies.contains(&Vec::<String>::new()));
    // The empty one HELD (timed out near the full window), not a fast supersede.
    let empty_elapsed = if b1.is_empty() { t1 } else { t2 };
    assert!(empty_elapsed >= Duration::from_millis(LONG_POLL_MS * 6 / 10));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_survives_disconnect_then_reconnect() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();

    // A held GET disconnects (we drop its future via a short timeout).
    {
        let fut = c.get(format!("{base}/mailbox/{id}/to-phone")).send();
        let _ = tokio::time::timeout(Duration::from_millis(20), fut).await;
    }
    // Reconnect and hold, then deposit: it must reach the live reconnect.
    let reconnect = {
        let c = c.clone();
        let base = base.clone();
        let id = id.clone();
        tokio::spawn(async move { envelopes(get(&c, &base, &id, "to-phone").await).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    to_phone(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "survives-reconnect" }),
    )
    .await;
    assert_eq!(reconnect.await.unwrap(), vec!["survives-reconnect"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnected_get_does_not_leak() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    {
        let fut = c.get(format!("{base}/mailbox/{id}/to-phone")).send();
        let _ = tokio::time::timeout(Duration::from_millis(15), fut).await;
    }
    // A fresh GET behaves like any empty-slot long-poll (times out empty).
    assert!(envelopes(get(&c, &base, &id, "to-phone").await)
        .await
        .is_empty());
    // And a real deposit afterward still drains normally.
    to_phone(&c, &base, &id, serde_json::json!({ "env": "still-works" })).await;
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-phone").await).await,
        vec!["still-works"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn to_daemon_is_symmetric() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let env = r#"{"to":"daemon"}"#;
    assert_eq!(
        to_daemon(&c, &base, &id, serde_json::json!({ "env": env }))
            .await
            .status(),
        200
    );
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-daemon").await).await,
        vec![env]
    );
    assert!(envelopes(get(&c, &base, &id, "to-daemon").await)
        .await
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_directions_are_independent() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    to_phone(&c, &base, &id, serde_json::json!({ "env": "for-phone" })).await;
    to_daemon(&c, &base, &id, serde_json::json!({ "env": "for-daemon" })).await;
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-phone").await).await,
        vec!["for-phone"]
    );
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-daemon").await).await,
        vec!["for-daemon"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_with_push_token_still_200s_without_a_key() {
    let base = spawn(test_config()).await; // knock mode Off, no key
    let c = client();
    let id = mailbox_id();
    let resp = to_phone(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "hello", "pushToken": "deadbeef", "platform": "apns" }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-phone").await).await,
        vec!["hello"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_missing_env_is_400() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    assert_eq!(
        to_phone(
            &c,
            &base,
            &id,
            serde_json::json!({ "pushToken": "deadbeef" })
        )
        .await
        .status(),
        400
    );
    assert_eq!(
        to_daemon(&c, &base, &id, serde_json::json!({ "nope": true }))
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opacity_arbitrary_bytes_round_trip() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let opaque = "\\x00{\"not\":parsed}\n\t\"quote\"\u{2601} \u{7f} raw";
    to_phone(&c, &base, &id, serde_json::json!({ "env": opaque })).await;
    assert_eq!(
        envelopes(get(&c, &base, &id, "to-phone").await).await,
        vec![opaque]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_envelope_is_413() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let big = "x".repeat(16_384 + 1);
    assert_eq!(
        to_phone(&c, &base, &id, serde_json::json!({ "env": big }))
            .await
            .status(),
        413
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_bound_is_507() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    for i in 0..32 {
        assert_eq!(
            to_daemon(
                &c,
                &base,
                &id,
                serde_json::json!({ "env": format!("e{i}") })
            )
            .await
            .status(),
            200
        );
    }
    assert_eq!(
        to_daemon(&c, &base, &id, serde_json::json!({ "env": "overflow" }))
            .await
            .status(),
        507
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_is_rate_limited_429() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let mut saw_limit = false;
    for _ in 0..(60 + 5) {
        // Malformed deposits still count against the rate limit (checked before
        // the body is parsed), so this floods fast regardless of queue depth.
        if to_phone(&c, &base, &id, serde_json::json!({}))
            .await
            .status()
            == 429
        {
            saw_limit = true;
            break;
        }
    }
    assert!(saw_limit);
}

// ---- origin stamping ----
//
// The relay notes the address it saw a to-phone deposit arrive from and hands
// it to the phone alongside the envelope, as a display-only hint. These check
// the wire shape, the forwarded-header gate, and that the envelope bytes are
// untouched by any of it. Whether the hint is trustworthy is not a question the
// relay answers: it cannot be, and the phone must treat it as unverified.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_to_phone_delivery_carries_the_observed_origin() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let before = now_ms();
    to_phone(&c, &base, &id, serde_json::json!({ "env": "sealed" })).await;

    let body = drain_body(get(&c, &base, &id, "to-phone").await).await;
    assert_eq!(
        body.get("envelopes").unwrap(),
        &serde_json::json!(["sealed"])
    );
    let origin = origin_at(&body, 0).expect("an origin for a loopback deposit");
    assert_eq!(origin.get("ip").and_then(|v| v.as_str()), Some("127.0.0.1"));
    let at_ms = origin.get("at_ms").and_then(|v| v.as_u64()).expect("at_ms");
    assert!(at_ms >= before && at_ms <= now_ms());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_to_daemon_direction_is_never_stamped() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    to_daemon(&c, &base, &id, serde_json::json!({ "env": "reply" })).await;

    let body = drain_body(get(&c, &base, &id, "to-daemon").await).await;
    assert_eq!(
        body.get("envelopes").unwrap(),
        &serde_json::json!(["reply"])
    );
    // Not null-filled: the key is absent entirely.
    assert!(body.get("origins").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_header_is_ignored_when_no_proxy_is_trusted() {
    let base = spawn(test_config()).await; // trusted_proxy_hops: 0
    let c = client();
    let id = mailbox_id();
    to_phone_forwarded(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "sealed" }),
        "203.0.113.7",
    )
    .await;

    let body = drain_body(get(&c, &base, &id, "to-phone").await).await;
    let origin = origin_at(&body, 0).expect("origin");
    // The forged claim is not what the phone is shown; the socket peer is.
    assert_eq!(origin.get("ip").and_then(|v| v.as_str()), Some("127.0.0.1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_header_is_read_when_a_proxy_is_trusted() {
    let base = spawn(config_behind_proxies(1)).await;
    let c = client();
    let id = mailbox_id();
    to_phone_forwarded(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "sealed" }),
        "203.0.113.7",
    )
    .await;

    let body = drain_body(get(&c, &base, &id, "to-phone").await).await;
    let origin = origin_at(&body, 0).expect("origin");
    assert_eq!(
        origin.get("ip").and_then(|v| v.as_str()),
        Some("203.0.113.7")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_shorter_than_the_trusted_hops_yields_no_origin() {
    // Configured for the two-hop deploy/gcp chain but reached directly: rather
    // than reach left into whatever the client wrote, the relay says nothing.
    let base = spawn(config_behind_proxies(2)).await;
    let c = client();
    let id = mailbox_id();
    to_phone_forwarded(
        &c,
        &base,
        &id,
        serde_json::json!({ "env": "sealed" }),
        "1.2.3.4",
    )
    .await;

    let body = drain_body(get(&c, &base, &id, "to-phone").await).await;
    assert_eq!(
        body.get("envelopes").unwrap(),
        &serde_json::json!(["sealed"])
    );
    assert!(body.get("origins").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_envelope_bytes_are_untouched_with_or_without_an_origin() {
    let opaque = "\\x00{\"not\":parsed}\n\t\"quote\"\u{2601} \u{7f} raw";
    let c = client();

    // Stamped (loopback peer, no proxies trusted).
    let stamped = spawn(test_config()).await;
    let id = mailbox_id();
    to_phone(&c, &stamped, &id, serde_json::json!({ "env": opaque })).await;
    let with_origin = drain_body(get(&c, &stamped, &id, "to-phone").await).await;
    assert!(origin_at(&with_origin, 0).is_some());

    // Unstamped (the chain is shorter than the configured trust, so unknown).
    let unstamped = spawn(config_behind_proxies(2)).await;
    let id2 = mailbox_id();
    to_phone(&c, &unstamped, &id2, serde_json::json!({ "env": opaque })).await;
    let without_origin = drain_body(get(&c, &unstamped, &id2, "to-phone").await).await;
    assert!(without_origin.get("origins").is_none());

    // Byte-identical to the deposit either way: nothing about provenance
    // touches the sealed bytes.
    assert_eq!(
        with_origin.get("envelopes").unwrap(),
        &serde_json::json!([opaque])
    );
    assert_eq!(
        without_origin.get("envelopes").unwrap(),
        with_origin.get("envelopes").unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_is_dropped_with_the_entry_it_belongs_to() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    to_phone(&c, &base, &id, serde_json::json!({ "env": "sealed" })).await;

    // Drain-on-read takes the envelope and its origin together.
    assert!(origin_at(&drain_body(get(&c, &base, &id, "to-phone").await).await, 0).is_some());
    let after = drain_body(get(&c, &base, &id, "to-phone").await).await;
    assert_eq!(after.get("envelopes").unwrap(), &serde_json::json!([]));
    assert!(after.get("origins").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_reaches_a_waiting_long_poll() {
    let base = spawn(test_config()).await;
    let c = client();
    let id = mailbox_id();
    let held = {
        let c = c.clone();
        let base = base.clone();
        let id = id.clone();
        tokio::spawn(async move { drain_body(get(&c, &base, &id, "to-phone").await).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    to_phone(&c, &base, &id, serde_json::json!({ "env": "woke-it-up" })).await;

    let body = held.await.unwrap();
    assert_eq!(
        body.get("envelopes").unwrap(),
        &serde_json::json!(["woke-it-up"])
    );
    let origin = origin_at(&body, 0).expect("origin on the woken delivery");
    assert_eq!(origin.get("ip").and_then(|v| v.as_str()), Some("127.0.0.1"));
}
