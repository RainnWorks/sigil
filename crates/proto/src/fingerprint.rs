//! The pairing ceremony's human-verifiable checksum, and the routing mailbox id.
//!
//! Both devices derive the same six words and the same mailbox id from the two
//! pinned public identities. The inputs are placed in a canonical (sorted)
//! order first, so the result does not depend on which device is "a" and which
//! is "b"; each side computes it locally and reads it aloud to confirm the
//! other end pinned the same keys, defeating a man-in-the-middle on the QR
//! channel.

use blake2::{Blake2b512, Digest};

use crate::identity::PeerIdentity;

const FINGERPRINT_DOMAIN: &[u8] = b"latch.fingerprint.v1";
const MAILBOX_DOMAIN: &[u8] = b"latch.mailbox.v1";

/// Six short, phonetically distinct English words with harbor flavour. The
/// list is exactly 256 entries so each output byte maps to one word.
pub const WORDS: [&str; 256] = [
    "tide", "brass", "anchor", "harbor", "reef", "mast", "sail", "keel", //
    "helm", "prow", "stern", "deck", "hull", "buoy", "wharf", "dock", //
    "pier", "cove", "bay", "gulf", "shoal", "coral", "kelp", "wave", //
    "surf", "foam", "spray", "drift", "tidal", "ebb", "flood", "swell", //
    "crest", "trough", "wake", "churn", "brine", "salt", "spume", "gale", //
    "squall", "storm", "breeze", "gust", "calm", "fog", "mist", "haze", //
    "cloud", "rain", "sleet", "frost", "ice", "snow", "hail", "bolt", //
    "north", "south", "east", "west", "compass", "chart", "course", "bearing", //
    "heading", "knot", "fathom", "league", "depth", "sound", "gauge", "lead", //
    "sextant", "star", "moon", "sun", "dawn", "dusk", "noon", "night", //
    "light", "beam", "flash", "signal", "flare", "beacon", "lantern", "glow", //
    "amber", "copper", "bronze", "iron", "steel", "rust", "gold", "silver", //
    "pearl", "jade", "slate", "stone", "rock", "cliff", "ledge", "crag", //
    "bluff", "dune", "sand", "shell", "pebble", "gravel", "shore", "coast", //
    "beach", "inlet", "strait", "channel", "lagoon", "marsh", "delta", "river", //
    "stream", "creek", "brook", "spring", "well", "pool", "pond", "lake", //
    "basin", "fjord", "sea", "ocean", "deep", "abyss", "trench", "shallow", //
    "ford", "quay", "jetty", "slip", "berth", "moor", "rope", "line", //
    "cable", "chain", "hook", "cleat", "winch", "pulley", "block", "tackle", //
    "rig", "spar", "boom", "yard", "sheet", "halyard", "stay", "shroud", //
    "canvas", "flag", "pennant", "ensign", "banner", "crew", "mate", "bosun", //
    "pilot", "captain", "skipper", "sailor", "hand", "watch", "galley", "cabin", //
    "bunk", "hatch", "porthole", "rudder", "tiller", "wheel", "oar", "paddle", //
    "scull", "raft", "canoe", "kayak", "dinghy", "skiff", "sloop", "ketch", //
    "yawl", "schooner", "clipper", "cutter", "barge", "ferry", "tug", "liner", //
    "trawler", "dory", "punt", "gig", "launch", "tender", "vessel", "craft", //
    "fleet", "convoy", "armada", "squadron", "flotilla", "cargo", "freight", "ballast", //
    "hold", "crate", "barrel", "cask", "keg", "chest", "trunk", "bundle", //
    "parcel", "crane", "hoist", "gangway", "ladder", "rail", "bell", "horn", //
    "whistle", "siren", "chime", "gong", "drum", "pipe", "twine", "mesh", //
    "net", "trap", "lure", "bait", "catch", "haul", "trawl", "seine", //
    "whale", "shark", "otter", "dolphin", "marlin", "heron", "gull", "tern", //
];

/// The two identities as a single 64-byte string, in a fixed field order.
fn identity_bytes(p: &PeerIdentity) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.verifying);
    out[32..].copy_from_slice(&p.agreement);
    out
}

/// Feed the two identities into `hasher` in sorted order, so both peers agree
/// regardless of argument order.
fn absorb_canonical(hasher: &mut Blake2b512, a: &PeerIdentity, b: &PeerIdentity) {
    let (a, b) = (identity_bytes(a), identity_bytes(b));
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    hasher.update(lo);
    hasher.update(hi);
}

/// Six words confirming both devices pinned the same key pair. Order-independent.
pub fn fingerprint_words(a: &PeerIdentity, b: &PeerIdentity) -> [&'static str; 6] {
    let mut hasher = Blake2b512::new();
    hasher.update(FINGERPRINT_DOMAIN);
    absorb_canonical(&mut hasher, a, b);
    let digest = hasher.finalize();
    std::array::from_fn(|i| WORDS[digest[i] as usize])
}

/// The routing mailbox for this pairing: a domain-separated hash of the two
/// identities. Carries no identity; a relay learns only that two anonymous
/// parties share a box. Order-independent, so both peers address the same one.
pub fn mailbox_id(a: &PeerIdentity, b: &PeerIdentity) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(MAILBOX_DOMAIN);
    absorb_canonical(&mut hasher, a, b);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use std::collections::HashSet;

    fn peer() -> PeerIdentity {
        DeviceIdentity::generate().peer_identity()
    }

    #[test]
    fn word_list_is_256_and_unique() {
        assert_eq!(WORDS.len(), 256);
        let set: HashSet<&&str> = WORDS.iter().collect();
        assert_eq!(set.len(), 256, "duplicate word in list");
        assert!(WORDS.iter().all(|w| w.len() >= 2), "word too short");
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let (a, b) = (peer(), peer());
        assert_eq!(fingerprint_words(&a, &b), fingerprint_words(&b, &a));
    }

    #[test]
    fn fingerprint_differs_for_different_pairs() {
        let (a, b, c) = (peer(), peer(), peer());
        assert_ne!(fingerprint_words(&a, &b), fingerprint_words(&a, &c));
    }

    #[test]
    fn mailbox_is_order_independent() {
        let (a, b) = (peer(), peer());
        assert_eq!(mailbox_id(&a, &b), mailbox_id(&b, &a));
    }

    #[test]
    fn mailbox_differs_for_different_pairs() {
        let (a, b, c) = (peer(), peer(), peer());
        assert_ne!(mailbox_id(&a, &b), mailbox_id(&a, &c));
    }

    #[test]
    fn fingerprint_and_mailbox_are_domain_separated() {
        // Same inputs, different domains, must not collide on the shared prefix.
        let (a, b) = (peer(), peer());
        let words = fingerprint_words(&a, &b);
        let mail = mailbox_id(&a, &b);
        // Map the mailbox's first six bytes through the word list and confirm
        // they are not simply the fingerprint (i.e. the domains diverged).
        let mail_words: [&str; 6] = std::array::from_fn(|i| WORDS[mail[i] as usize]);
        assert_ne!(words, mail_words);
    }
}
