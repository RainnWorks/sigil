//! Latch multicall binary.
//!
//! Invoked as `op` (argv[0] file stem) it is the shim; invoked as anything else
//! it is the `latch` CLI. The shim path is std-only and synchronous so its cold
//! start stays near zero; only the `daemon` subcommand ever builds a runtime.
//! All the real machinery lives in the `latch` library crate.

use std::path::Path;

fn main() {
    let arg0 = std::env::args_os().next().unwrap_or_default();
    let stem = Path::new(&arg0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if stem == "op" {
        latch::shim::run(); // never returns
    }

    std::process::exit(latch::cli::run());
}
