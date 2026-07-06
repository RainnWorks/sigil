//! Latch: the daemon, the `op` shim, and the `latch` CLI as one library, driven
//! by a thin multicall `main`.
//!
//! The modules here are the seams and machinery: the local socket protocol, the
//! keystore trait and its macOS fill, the DEK/token model, the approval gate,
//! and leases. They are `pub` so the trait surfaces and their unit tests are
//! part of the crate's public API rather than dead code in a binary.

pub mod apns;
pub mod approve;
pub mod audit;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod factor;
pub mod json;
pub mod keystore;
#[cfg(target_os = "macos")]
pub mod keystore_macos;
pub mod lease;
pub mod local;
pub mod pair;
pub mod pairing_store;
pub mod paths;
pub mod provider;
pub mod proxy;
pub mod push_store;
pub mod qr;
pub mod remote;
pub mod report;
pub mod secrets;
pub mod service;
pub mod settings;
pub mod setup;
pub mod shim;
pub mod sshagent;
pub mod style;
pub mod threshold;

/// A process-wide lock serializing tests that mutate global environment
/// variables (`LATCH_HOME` in particular). Cargo runs a crate's tests in
/// parallel threads of one process, so any test that sets a global env var must
/// hold this for its duration or it will clobber (and be clobbered by) another.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
