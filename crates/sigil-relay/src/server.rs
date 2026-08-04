//! The HTTP surface and in-memory mailbox state. A hand-rolled tiny router over
//! hyper (no framework), holding idle long-polls as parked futures.
//!
//! State is a `HashMap<mailbox_id, Arc<Mutex<Mailbox>>>` behind one map lock;
//! each mailbox has its own lock so a held long-poll never blocks another
//! mailbox. Nothing is ever written to disk: if the process restarts, every
//! mailbox is simply gone, exactly as if its short TTL had elapsed. The
//! depositing side still holds its own copy and can redeposit.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::oneshot;

use crate::protocol::{self as p, Mailbox, Slot};
use crate::push::{self, KnockMode};

/// The landing page, embedded from the ONE source file in `relay/` so the
/// native relay and the TS variants serve byte-identical HTML (no drift).
const LANDING_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../relay/landing.html"
));

/// Immutable runtime configuration, resolved once from the environment.
pub struct Config {
    pub knock_mode: KnockMode,
    pub knock_upstream: Option<String>,
    pub apns_key: Option<String>,
    /// The APNs identity (topic/team/key id) the direct doorbell signs and
    /// addresses with. Defaults to the pinned official values; overridable via
    /// env for self-hosters.
    pub apns_identity: push::ApnsIdentity,
    /// Overridable so tests can point the doorbell at a local stub.
    pub apns_host: String,
    /// Overridable so tests can shrink the long-poll window; production uses
    /// [`p::LONG_POLL_MS`].
    pub long_poll_ms: u64,
    /// How many trusted reverse proxies stand in front of this relay, which is
    /// what decides whether `X-Forwarded-For` is read at all when stamping a
    /// deposit's [`p::Origin`]. `0` (the default) reads only the socket peer.
    /// See [`p::client_ip`] for the indexing rule and the misconfiguration
    /// hazard; in the `deploy/gcp/` layout the correct value is `2`.
    pub trusted_proxy_hops: usize,
}

/// The whole shared server state.
pub struct AppState {
    boxes: Mutex<HashMap<String, Arc<Mutex<Mailbox>>>>,
    config: Config,
    waiter_seq: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned mailbox lock is unrecoverable state we would only make worse by
    // panicking mid-request; recover the guard and carry on (fail-safe).
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            boxes: Mutex::new(HashMap::new()),
            config,
            waiter_seq: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Fetch an existing mailbox, or create one if the global cap allows.
    /// Returns `None` only when the id is new AND the process is already holding
    /// [`p::MAX_MAILBOXES`] distinct mailboxes: an established pairing (its id is
    /// already in the map) is never refused, so a flood of fresh ids fails closed
    /// without evicting real traffic. See [`p::MAX_MAILBOXES`].
    fn get_box(&self, id: &str) -> Option<Arc<Mutex<Mailbox>>> {
        let mut map = lock(&self.boxes);
        if let Some(mb) = map.get(id) {
            return Some(mb.clone());
        }
        if map.len() >= p::MAX_MAILBOXES {
            return None;
        }
        Some(
            map.entry(id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(Mailbox::new())))
                .clone(),
        )
    }

    /// Periodic sweep: evict expired items and drop mailboxes that are both
    /// empty and unwatched, so the map stays bounded. Never drops one with a
    /// live waiter (its queue is legitimately empty; deleting it would orphan
    /// that waiter from the object a concurrent deposit would recreate).
    pub fn sweep(&self) {
        let now = p::now_ms();
        let mut map = lock(&self.boxes);
        map.retain(|_, mb| {
            let mut g = lock(mb);
            p::evict_expired(&mut g, now);
            !g.idle()
        });
    }
}

// ---- response helpers ----

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("a status + one static header is always a valid response")
}

fn err(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    json(status, &p::err_body(msg))
}

fn landing() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(LANDING_HTML)))
        .expect("a status + one static header is always a valid response")
}

#[derive(Serialize)]
struct VersionBody {
    version: &'static str,
    git_commit: &'static str,
}

// ---- routing ----

/// The single service entry point. Never returns an error to hyper: every
/// failure is turned into a response, so a bad request can never drop a
/// connection in a way a client would read as anything but its status code.
pub async fn handle(
    state: Arc<AppState>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let resp = match parts.first().copied() {
        None => landing(),
        Some("health") => json(StatusCode::OK, &p::health_body()),
        Some("version") => json(
            StatusCode::OK,
            &VersionBody {
                version: env!("CARGO_PKG_VERSION"),
                git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown"),
            },
        ),
        Some("knock") if method == hyper::Method::POST => knock(&state, req).await,
        Some("mailbox") => match parts.get(1).copied() {
            Some(id) if p::valid_id(id) => {
                let id = id.to_string();
                let verb = parts.get(2).copied().unwrap_or("");
                mailbox(&state, &id, verb, method, peer, req).await
            }
            _ => err(StatusCode::BAD_REQUEST, "bad_mailbox"),
        },
        _ => err(StatusCode::BAD_REQUEST, "bad_mailbox"),
    };
    Ok(resp)
}

async fn mailbox(
    state: &Arc<AppState>,
    id: &str,
    verb: &str,
    method: hyper::Method,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let Some(mb) = state.get_box(id) else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "at_capacity");
    };
    let slot = match verb {
        "to-phone" => Some(Slot::ToPhone),
        "to-daemon" => Some(Slot::ToDaemon),
        _ => None,
    };
    let Some(slot) = slot else {
        // Still rate-check an unknown verb, matching the TS order (rate is
        // checked before routing), then 404.
        {
            let mut g = lock(&mb);
            if !p::rate_ok(&mut g, p::now_ms()) {
                return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            }
        }
        return err(StatusCode::NOT_FOUND, "not_found");
    };

    match method {
        hyper::Method::GET => poll(state, &mb, slot).await,
        hyper::Method::POST => deposit(state, &mb, id, slot, peer, req).await,
        _ => {
            let mut g = lock(&mb);
            if !p::rate_ok(&mut g, p::now_ms()) {
                return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            }
            err(StatusCode::NOT_FOUND, "not_found")
        }
    }
}

/// GET a slot: long-poll on an empty slot (see the module docs on `wake`).
async fn poll(
    state: &Arc<AppState>,
    mb: &Arc<Mutex<Mailbox>>,
    slot: Slot,
) -> Response<Full<Bytes>> {
    let id = state.waiter_seq.fetch_add(1, Ordering::Relaxed);

    // Rate check + immediate drain + (maybe) waiter registration, all under one
    // lock so nothing races between the empty-check and the registration.
    let rx = {
        let mut g = lock(mb);
        let now = p::now_ms();
        if !p::rate_ok(&mut g, now) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
        let (list, waiters) = slot.parts(&mut g);
        let immediate = p::drain(list, now);
        if !immediate.is_empty() {
            return json(StatusCode::OK, &p::envelopes_body(immediate));
        }
        // Bound the coexisting waiters: at the cap drop the OLDEST (stalest,
        // likeliest orphaned). The slot is provably empty here, so the dropped
        // waiter is resolved with [] and no queued deposit can be lost to it.
        while waiters.len() >= p::MAX_WAITERS {
            let mut oldest = waiters.remove(0);
            oldest.offer(&[]);
        }
        let (tx, rx) = oneshot::channel::<Vec<p::Delivery>>();
        let mut tx = Some(tx);
        waiters.push(p::Waiter::new(
            id,
            Box::new(move |items| match tx.take() {
                // send() Ok  => the receiver is live: this is the accept.
                // send() Err => the receiver was dropped (client gone / timed
                // out): reject, so `wake` leaves the item queued (offer-then-drain).
                Some(s) => s.send(items.to_vec()).is_ok(),
                None => false,
            }),
        ));
        rx
    };

    // Hold open until woken, timed out, or the connection drops (which drops
    // this future, and the guard reaps the waiter).
    let mut guard = WaiterGuard {
        mb: mb.clone(),
        slot,
        id,
        active: true,
    };
    let envelopes = tokio::select! {
        biased;
        r = rx => {
            guard.active = false; // wake already removed the waiter
            r.unwrap_or_default()
        }
        _ = tokio::time::sleep(Duration::from_millis(state.config.long_poll_ms)) => {
            guard.active = false;
            let mut g = lock(mb);
            let (list, waiters) = slot.parts(&mut g);
            waiters.retain(|w| w.id != id);
            // A live waiter that `wake` offered to would have accepted and been
            // removed before this fired; this final drain only matters for the
            // vanishingly unlikely deposit-in-the-same-tick case.
            p::drain(list, p::now_ms())
        }
    };
    json(StatusCode::OK, &p::envelopes_body(envelopes))
}

/// A drop guard that reaps this GET's waiter if the future is dropped (the
/// client disconnected) without either the wake or the timeout branch having
/// already cleaned it up.
struct WaiterGuard {
    mb: Arc<Mutex<Mailbox>>,
    slot: Slot,
    id: u64,
    active: bool,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if self.active {
            let mut g = lock(&self.mb);
            let (_, waiters) = self.slot.parts(&mut g);
            waiters.retain(|w| w.id != self.id);
        }
    }
}

/// POST a slot: enqueue an opaque envelope and wake a waiter; for `to-phone`,
/// stamp the observed origin and fire the configured doorbell (direct APNs /
/// upstream knock) if a token rode along.
async fn deposit(
    state: &Arc<AppState>,
    mb: &Arc<Mutex<Mailbox>>,
    id: &str,
    slot: Slot,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    // Rate check first (matches the TS order), before reading the body.
    {
        let mut g = lock(mb);
        if !p::rate_ok(&mut g, p::now_ms()) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
    }

    // Coarse content-length pre-guard, then a hard-capped read.
    if let Some(len) = content_length(&req) {
        if len > p::MAX_BODY_BYTES {
            return err(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
        }
    }
    // Read the forwarded chain before the body consumes the request. Only the
    // to-phone direction is stamped: the daemon has no use for the phone's
    // address, so none is ever taken on to-daemon. See [`p::Origin`].
    let origin = match slot {
        Slot::ToPhone => {
            // Repeated header lines are one logical list, so join before parsing.
            let lines: Vec<&str> = req
                .headers()
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            let forwarded = (!lines.is_empty()).then(|| lines.join(","));
            p::client_ip(
                forwarded.as_deref(),
                peer.ip(),
                state.config.trusted_proxy_hops,
            )
            .map(|ip| p::Origin::new(ip, p::now_ms()))
        }
        Slot::ToDaemon => None,
    };

    let Some(body) = read_body(req).await else {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    };
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "bad_body");
    };

    // Parse only the fields the relay reads; `env` itself stays opaque.
    let (env, push_token, platform) = match slot {
        Slot::ToPhone => match parse_to_phone(&value) {
            Some(t) => t,
            None => return err(StatusCode::BAD_REQUEST, "bad_body"),
        },
        Slot::ToDaemon => match parse_env(&value) {
            Some(e) => (e, None, None),
            None => return err(StatusCode::BAD_REQUEST, "bad_body"),
        },
    };

    // Enqueue + wake + push gate, under one lock.
    let do_push = {
        let mut g = lock(mb);
        let now = p::now_ms();
        {
            let (list, _) = slot.parts(&mut g);
            match p::enqueue(list, env, origin, now) {
                p::EnqueueResult::TooLarge => {
                    return err(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
                }
                p::EnqueueResult::QueueFull => {
                    return err(StatusCode::INSUFFICIENT_STORAGE, "queue_full")
                }
                p::EnqueueResult::Ok => {}
            }
        }
        let (list, waiters) = slot.parts(&mut g);
        p::wake(list, waiters, now);
        // Only a to-phone deposit carrying a token rings a doorbell, and only
        // within the tighter push cap.
        slot == Slot::ToPhone && push_token.is_some() && p::push_ok(&mut g, now)
    };

    if do_push {
        if let Some(token) = push_token {
            dispatch_doorbell(state, id, token, platform);
        }
    }
    json(StatusCode::OK, &p::deposited_body())
}

/// Fire the configured doorbell for a deposit, detached and best-effort.
fn dispatch_doorbell(state: &Arc<AppState>, id: &str, token: String, platform: Option<String>) {
    let cfg = &state.config;
    let now = p::now_ms();
    match cfg.knock_mode {
        KnockMode::Direct => {
            let key = cfg.apns_key.clone();
            let host = cfg.apns_host.clone();
            let identity = cfg.apns_identity.clone();
            tokio::spawn(push::send_push_direct(
                token, platform, key, identity, host, now,
            ));
        }
        KnockMode::Upstream => {
            if let Some(up) = cfg.knock_upstream.clone() {
                tokio::spawn(push::forward_knock(up, token, id.to_string(), platform));
            } else {
                eprintln!("push: upstream knock mode but no KNOCK_UPSTREAM set, skipping");
            }
        }
        KnockMode::Off => {}
    }
}

/// The `POST /knock` endpoint. Accepts an opaque knock and either sends the
/// APNs wake (direct) or forwards it further upstream. Powerless: it carries
/// only the opaque token, a mailbox hash (for the rate bucket), and a platform
/// tag; never message content, and it stores nothing.
async fn knock(state: &Arc<AppState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if let Some(len) = content_length(&req) {
        if len > p::MAX_BODY_BYTES {
            return err(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
        }
    }
    let Some(body) = read_body(req).await else {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    };
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "bad_body");
    };
    let obj = value.as_object();
    let token = obj
        .and_then(|o| o.get("opaque_token"))
        .and_then(|v| v.as_str());
    let mailbox_hash = obj
        .and_then(|o| o.get("mailbox_hash"))
        .and_then(|v| v.as_str());
    let platform = obj
        .and_then(|o| o.get("platform"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let (Some(token), Some(mailbox_hash)) = (token, mailbox_hash) else {
        return err(StatusCode::BAD_REQUEST, "bad_body");
    };
    if !p::valid_id(mailbox_hash) {
        return err(StatusCode::BAD_REQUEST, "bad_mailbox");
    }

    // Rate-limit the knock on the same tight per-mailbox push budget.
    {
        let Some(mb) = state.get_box(mailbox_hash) else {
            return err(StatusCode::SERVICE_UNAVAILABLE, "at_capacity");
        };
        let mut g = lock(&mb);
        if !p::push_ok(&mut g, p::now_ms()) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
    }

    let now = p::now_ms();
    match state.config.knock_mode {
        KnockMode::Direct => {
            let key = state.config.apns_key.clone();
            let host = state.config.apns_host.clone();
            let identity = state.config.apns_identity.clone();
            tokio::spawn(push::send_push_direct(
                token.to_string(),
                platform,
                key,
                identity,
                host,
                now,
            ));
        }
        KnockMode::Upstream => {
            if let Some(up) = state.config.knock_upstream.clone() {
                tokio::spawn(push::forward_knock(
                    up,
                    token.to_string(),
                    mailbox_hash.to_string(),
                    platform,
                ));
            }
        }
        KnockMode::Off => {}
    }
    json(StatusCode::OK, &p::deposited_body())
}

// ---- small request helpers ----

fn content_length(req: &Request<Incoming>) -> Option<usize> {
    req.headers()
        .get(hyper::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Read the whole body through a hard [`p::MAX_BODY_BYTES`] cap. `None` means
/// the body was over the cap (or errored) and the caller should 413.
async fn read_body(req: Request<Incoming>) -> Option<Bytes> {
    let limited = Limited::new(req.into_body(), p::MAX_BODY_BYTES);
    limited.collect().await.ok().map(|c| c.to_bytes())
}

fn parse_to_phone(v: &Value) -> Option<(String, Option<String>, Option<String>)> {
    let o = v.as_object()?;
    let env = o.get("env")?.as_str()?.to_string();
    let push = o
        .get("pushToken")
        .and_then(|x| x.as_str())
        .map(String::from);
    let platform = o.get("platform").and_then(|x| x.as_str()).map(String::from);
    Some((env, push, platform))
}

fn parse_env(v: &Value) -> Option<String> {
    v.as_object()?.get("env")?.as_str().map(String::from)
}
