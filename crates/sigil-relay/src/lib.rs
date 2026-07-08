//! Sigil blind relay, native Rust. See `docs/design/rust-relay.md` for the
//! design and footprint numbers, and `relay/README.md` for the shared protocol
//! this is wire-compatible with.
//!
//! The library exposes the pure protocol, the doorbell/knock, and the server so
//! integration tests can drive the real thing in-process; `main.rs` is a thin
//! wrapper that resolves config from the environment and serves forever.

pub mod protocol;
pub mod push;
pub mod server;

use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::protocol as p;
use crate::push::KnockMode;
use crate::server::{handle, AppState, Config};

/// Resolve the APNs signing key: the raw PEM in `APNS_KEY_P8`, else the file at
/// `APNS_KEY_P8_PATH` (meant to be a 0600 file). Absent disables direct pushes.
pub fn resolve_apns_key() -> Option<String> {
    if let Ok(k) = std::env::var("APNS_KEY_P8") {
        if !k.is_empty() {
            return Some(k);
        }
    }
    if let Ok(path) = std::env::var("APNS_KEY_P8_PATH") {
        if !path.is_empty() {
            match std::fs::read_to_string(&path) {
                Ok(s) => return Some(s),
                Err(e) => eprintln!("push: reading APNS_KEY_P8_PATH: {e}"),
            }
        }
    }
    None
}

fn resolve_knock_mode(apns_key: &Option<String>, upstream: &Option<String>) -> KnockMode {
    let inferred = if apns_key.is_some() {
        KnockMode::Direct
    } else if upstream.is_some() {
        KnockMode::Upstream
    } else {
        KnockMode::Off
    };
    match std::env::var("KNOCK_MODE").ok().as_deref() {
        Some("direct") => KnockMode::Direct,
        Some("upstream") => KnockMode::Upstream,
        Some("off") => KnockMode::Off,
        Some(other) => {
            eprintln!("unknown KNOCK_MODE {other:?}, inferring from config");
            inferred
        }
        None => inferred,
    }
}

/// Build the runtime [`Config`] from the process environment.
pub fn config_from_env() -> Config {
    let apns_key = resolve_apns_key();
    let knock_upstream = std::env::var("KNOCK_UPSTREAM")
        .ok()
        .filter(|s| !s.is_empty());
    let knock_mode = resolve_knock_mode(&apns_key, &knock_upstream);
    let long_poll_ms = std::env::var("LONG_POLL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(p::LONG_POLL_MS);
    Config {
        knock_mode,
        knock_upstream,
        apns_key,
        apns_identity: push::ApnsIdentity::from_env(),
        apns_host: push::APNS_HOST.to_string(),
        long_poll_ms,
    }
}

/// Serve forever on an already-bound listener. Spawns the periodic TTL sweep,
/// then accepts connections, serving each on its own task so an idle long-poll
/// on one connection never blocks another. Returns only on a fatal accept error.
pub async fn serve(state: Arc<AppState>, listener: TcpListener) {
    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(p::TTL_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sweeper.sweep();
        }
    });

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("relay: accept failed: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let st = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(st.clone(), req));
            // A client hanging up mid-long-poll returns an error here; it is
            // routine, not a fault, so it is swallowed. Dropping this future
            // drops the handler future, whose WaiterGuard reaps the waiter.
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}
