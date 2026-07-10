//! The `sigil-relay` binary: resolve config from the environment, bind the
//! listener, and serve until Ctrl-C. A tokio CURRENT-THREAD runtime keeps the
//! idle footprint minimal; thousands of parked long-polls cost near-zero CPU
//! and minimal RAM because they are just suspended futures on one event loop.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sigil_relay::server::AppState;
use sigil_relay::{config_from_env, serve};
use tokio::net::TcpListener;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building the current-thread tokio runtime");
    rt.block_on(async_main());
}

async fn async_main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8787);
    // BIND_ADDR lets an operator pin the listener to loopback (127.0.0.1) when
    // the relay sits behind a local reverse proxy such as Caddy. Default is
    // 0.0.0.0 so behavior is unchanged when unset. An unparsable value falls
    // back to 0.0.0.0 with a warning rather than failing to start.
    let ip: IpAddr = match std::env::var("BIND_ADDR") {
        Ok(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| {
            eprintln!("relay: BIND_ADDR {s:?} is not a valid IP, using 0.0.0.0");
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let addr = SocketAddr::new(ip, port);

    let config = config_from_env();
    eprintln!(
        "sigil-relay listening on {addr} (knock mode: {:?}, long-poll: {}ms)",
        config.knock_mode, config.long_poll_ms
    );
    let state = AppState::new(config);

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("relay: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    tokio::select! {
        _ = serve(state, listener) => {}
        _ = tokio::signal::ctrl_c() => {
            eprintln!("sigil-relay: shutting down");
        }
    }
}
