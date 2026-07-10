//! The Sigil configuration-management CLI. The desktop app shells out to this
//! binary under the hood; it authors the rule/source config the daemon reads and
//! manages accounts, settings, the Mac-approval factor, and a full wipe. It
//! never sits on the gating hot path — that is the sibling `sigil` binary.

fn main() {
    std::process::exit(sigil_core::cli::run_config());
}
