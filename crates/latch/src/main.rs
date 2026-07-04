//! Latch multicall binary.
//!
//! Invoked as `op` (argv[0] file stem) it is the shim; invoked as anything else
//! it is the `latch` CLI. The shim path is std-only and synchronous so its cold
//! start stays near zero; only the `daemon` subcommand ever builds a runtime.

mod cli;
mod daemon;
mod local;
mod paths;
mod shim;
mod style;

use std::path::Path;

fn main() {
    let arg0 = std::env::args_os().next().unwrap_or_default();
    let stem = Path::new(&arg0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if stem == "op" {
        shim::run(); // never returns
    }

    std::process::exit(cli::run());
}
