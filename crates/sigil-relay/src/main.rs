//! The `sigil-relay` binary: resolve config from the environment, bind the
//! listener, and serve until Ctrl-C. A tokio CURRENT-THREAD runtime keeps the
//! idle footprint minimal; thousands of parked long-polls cost near-zero CPU
//! and minimal RAM because they are just suspended futures on one event loop.

use std::net::SocketAddr;

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
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let config = config_from_env();
    eprintln!(
        "sigil-relay listening on :{port} (knock mode: {:?}, long-poll: {}ms)",
        config.knock_mode, config.long_poll_ms
    );
    let state = AppState::new(config);

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("relay: failed to bind :{port}: {e}");
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
