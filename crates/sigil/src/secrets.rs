//! Secret-byte handling types shared across the daemon.
//!
//! Sigil GATES commands and injects its own stored secrets (sealed under
//! threshold, opened per-approval with the phone's partial). It is not a
//! credential broker: there is no data-encryption key at rest, and no stored
//! service-account token. What remains here is the one wrapper every path that
//! briefly holds secret bytes reuses so those bytes are wiped on drop.

use zeroize::Zeroizing;

/// A decrypted secret buffer (e.g. an SSH private key held for one signature).
/// Wiped on drop; never serialized.
pub type Token = Zeroizing<Vec<u8>>;
