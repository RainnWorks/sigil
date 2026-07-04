//! Latch: the daemon, the `op` shim, and the `latch` CLI as one library, driven
//! by a thin multicall `main`.
//!
//! The modules here are the seams and machinery: the local socket protocol, the
//! keystore trait and its macOS fill, the DEK/token model, the approval gate,
//! and leases. They are `pub` so the trait surfaces and their unit tests are
//! part of the crate's public API rather than dead code in a binary.

pub mod approve;
pub mod cli;
pub mod daemon;
pub mod keystore;
#[cfg(target_os = "macos")]
pub mod keystore_macos;
pub mod lease;
pub mod local;
pub mod paths;
pub mod remote;
pub mod secrets;
pub mod shim;
pub mod style;
