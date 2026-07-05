//! Latch multicall binary.
//!
//! Invoked under its own name (`latch`) it is the CLI: reserved verbs plus the
//! `latch <cmd>` primitive. Invoked under any *other* name (argv[0] stem — the
//! transparent PATH shim symlinked as `op`, `gcloud`, …) it is a thin alias that
//! re-enters as `latch <stem> <args>`, forwarding to the daemon. The alias path
//! is std-only and synchronous so its cold start stays near zero; only the
//! `daemon` subcommand ever builds a runtime. All the real machinery lives in the
//! `latch` library crate.

use std::path::Path;

fn main() {
    let arg0 = std::env::args_os().next().unwrap_or_default();
    let stem = Path::new(&arg0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Any name other than `latch` is a transparent command alias: `op read x`
    // becomes `latch op read x`. This is the only thing the PATH shim does.
    if !stem.is_empty() && stem != "latch" {
        let mut argv = vec![stem.to_string()];
        argv.extend(std::env::args().skip(1));
        latch::shim::dispatch(argv); // never returns
    }

    std::process::exit(latch::cli::run());
}
