//! The lean Sigil binary: the transparent shim multicall, the `sigil <cmd>`
//! gating primitive, and the runtime/daemon verbs. All configuration management
//! lives in the sibling `sigil-config` binary, so this one stays
//! reserved-verb-minimal — a program literally named `config`, `account`, or
//! `proxy` is still gateable as `sigil <that-name> …`.
//!
//! Invoked under its own name (`sigil`) it dispatches the gating CLI. Invoked
//! under any *other* name (argv[0] stem — the PATH alias symlinked as `op`,
//! `gcloud`, …) it is a thin forwarder that re-enters as `sigil <stem> <args>`.
//! The alias path is std-only and synchronous so its cold start stays near zero;
//! only the `daemon` subcommand ever builds a runtime.

use std::path::Path;

fn main() {
    let arg0 = std::env::args_os().next().unwrap_or_default();
    let stem = Path::new(&arg0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Any name other than `sigil` is a transparent command alias: `op read x`
    // becomes `sigil op read x`. This is the only thing the PATH alias does.
    if !stem.is_empty() && stem != "sigil" {
        let mut argv = vec![stem.to_string()];
        argv.extend(std::env::args().skip(1));
        sigil_core::shim::dispatch(argv); // never returns
    }

    std::process::exit(sigil_core::cli::run_gating());
}
