/**
 * The 256-word fingerprint list. MUST stay byte-identical to `WORDS` in
 * crates/proto/src/fingerprint.rs; the six-word pairing checksum is derived by
 * indexing this list with hash bytes, so any divergence makes two honest
 * devices read different words and the ceremony fails closed. Guarded by a
 * shared test vector (see vectors.contract.ts).
 */
export const WORDS: readonly string[] = [
  "tide", "brass", "anchor", "harbor", "reef", "mast", "sail", "keel",
  "helm", "prow", "stern", "deck", "hull", "buoy", "wharf", "dock",
  "pier", "cove", "bay", "gulf", "shoal", "coral", "kelp", "wave",
  "surf", "foam", "spray", "drift", "tidal", "ebb", "flood", "swell",
  "crest", "trough", "wake", "churn", "brine", "salt", "spume", "gale",
  "squall", "storm", "breeze", "gust", "calm", "fog", "mist", "haze",
  "cloud", "rain", "sleet", "frost", "ice", "snow", "hail", "bolt",
  "north", "south", "east", "west", "compass", "chart", "course", "bearing",
  "heading", "knot", "fathom", "league", "depth", "sound", "gauge", "lead",
  "sextant", "star", "moon", "sun", "dawn", "dusk", "noon", "night",
  "light", "beam", "flash", "signal", "flare", "beacon", "lantern", "glow",
  "amber", "copper", "bronze", "iron", "steel", "rust", "gold", "silver",
  "pearl", "jade", "slate", "stone", "rock", "cliff", "ledge", "crag",
  "bluff", "dune", "sand", "shell", "pebble", "gravel", "shore", "coast",
  "beach", "inlet", "strait", "channel", "lagoon", "marsh", "delta", "river",
  "stream", "creek", "brook", "spring", "well", "pool", "pond", "lake",
  "basin", "fjord", "sea", "ocean", "deep", "abyss", "trench", "shallow",
  "ford", "quay", "jetty", "slip", "berth", "moor", "rope", "line",
  "cable", "chain", "hook", "cleat", "winch", "pulley", "block", "tackle",
  "rig", "spar", "boom", "yard", "sheet", "halyard", "stay", "shroud",
  "canvas", "flag", "pennant", "ensign", "banner", "crew", "mate", "bosun",
  "pilot", "captain", "skipper", "sailor", "hand", "watch", "galley", "cabin",
  "bunk", "hatch", "porthole", "rudder", "tiller", "wheel", "oar", "paddle",
  "scull", "raft", "canoe", "kayak", "dinghy", "skiff", "sloop", "ketch",
  "yawl", "schooner", "clipper", "cutter", "barge", "ferry", "tug", "liner",
  "trawler", "dory", "punt", "gig", "launch", "tender", "vessel", "craft",
  "fleet", "convoy", "armada", "squadron", "flotilla", "cargo", "freight", "ballast",
  "hold", "crate", "barrel", "cask", "keg", "chest", "trunk", "bundle",
  "parcel", "crane", "hoist", "gangway", "ladder", "rail", "bell", "horn",
  "whistle", "siren", "chime", "gong", "drum", "pipe", "twine", "mesh",
  "net", "trap", "lure", "bait", "catch", "haul", "trawl", "seine",
  "whale", "shark", "otter", "dolphin", "marlin", "heron", "gull", "tern",
];

if (WORDS.length !== 256) {
  throw new Error(`fingerprint word list must be 256 entries, got ${WORDS.length}`);
}
