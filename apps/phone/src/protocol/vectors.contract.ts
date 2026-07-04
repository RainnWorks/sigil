/**
 * SHARED TEST VECTOR CONTRACT — the JSON the phone needs crates/proto to export.
 *
 * This is the interop handshake with rust-core: the Rust crate serializes a set
 * of known-answer vectors to `src/protocol/__vectors__/latch-vectors.json`
 * (git-ignored, produced by `cargo test --features export-vectors` or an
 * xtask), and `verify-vectors.ts` replays them through this TS implementation.
 * Both sides must agree byte-for-byte or CI fails.
 *
 * All byte fields are lowercase hex strings. All timestamps are unix ms.
 *
 * Rust side, please export exactly this shape:
 *
 * {
 *   "version": 1,
 *   "canonicalBytes": [                         // deterministic, no crypto
 *     {
 *       "name": "basic",
 *       "pairingId": "<64 hex>",
 *       "requestId": "<uuid string>",
 *       "counter": 7,
 *       "ts": 1720000000000,
 *       "ephemeralPub": "<64 hex>",
 *       "nonce": "<48 hex>",
 *       "ciphertext": "<hex>",
 *       "expected": "<hex of canonical_bytes()>"
 *     }
 *   ],
 *   "fingerprint": [                            // Blake2b512 + word list + mailbox
 *     {
 *       "a": { "verifying": "<64 hex>", "agreement": "<64 hex>" },
 *       "b": { "verifying": "<64 hex>", "agreement": "<64 hex>" },
 *       "words": ["tide","brass","anchor","harbor","reef","mast"],
 *       "mailboxId": "<64 hex>"
 *     }
 *   ],
 *   "pairingQr": [                              // PairingPayload -> base64url
 *     {
 *       "daemon": { "verifying": "<64 hex>", "agreement": "<64 hex>" },
 *       "endpoints": ["lan://latch.local:4823"],
 *       "secret": "<64 hex>",
 *       "createdAt": 1720000000000,
 *       "expected": "<base64url no pad>"
 *     }
 *   ],
 *   "open": [                                   // an envelope the daemon sealed
 *     {
 *       "name": "roundtrip",
 *       "sender": { "verifying": "<64 hex>", "agreement": "<64 hex>" },
 *       "recipientAgreementSecret": "<64 hex>",
 *       "now": 1720000000000,
 *       "envelope": { ...EnvelopeWire (serde form)... },
 *       "expectOk": true,
 *       "expectedPayloadJson": "\"unlock Engineering/.env\"",   // when expectOk
 *       "expectError": null                                     // else "badSignature" | "replay" | "decrypt"
 *     }
 *   ],
 *   "replay": [                                 // ReplayGuard state machine
 *     {
 *       "name": "counter-must-advance",
 *       "windowMs": 90000,
 *       "steps": [
 *         { "requestId": "<uuid>", "counter": 5, "ts": 1000000, "now": 1000000, "expectOk": true },
 *         { "requestId": "<uuid>", "counter": 3, "ts": 1000000, "now": 1000000, "expectOk": false, "expectError": "counterRegression" }
 *       ]
 *     }
 *   ]
 * }
 *
 * A single ReplayGuard instance is threaded through the `steps` of one replay
 * case, so ordering and state carry across steps exactly as in the Rust test.
 */

export interface PeerHex {
  verifying: string;
  agreement: string;
}

export interface CanonicalVector {
  name: string;
  pairingId: string;
  requestId: string;
  counter: number;
  ts: number;
  ephemeralPub: string;
  nonce: string;
  ciphertext: string;
  expected: string;
}

export interface FingerprintVector {
  a: PeerHex;
  b: PeerHex;
  words: string[];
  mailboxId: string;
}

export interface PairingQrVector {
  daemon: PeerHex;
  endpoints: string[];
  secret: string;
  createdAt: number;
  expected: string;
}

export interface OpenVector {
  name: string;
  sender: PeerHex;
  recipientAgreementSecret: string;
  now: number;
  envelope: unknown;
  expectOk: boolean;
  expectedPayloadJson?: string;
  expectError?: "badSignature" | "replay" | "decrypt" | "deserialize" | null;
}

export interface ReplayStep {
  requestId: string;
  counter: number;
  ts: number;
  now: number;
  expectOk: boolean;
  expectError?: "duplicateRequest" | "counterRegression" | "timestampOutOfWindow" | null;
}

export interface ReplayVector {
  name: string;
  windowMs: number;
  steps: ReplayStep[];
}

export interface LatchVectors {
  version: number;
  canonicalBytes: CanonicalVector[];
  fingerprint: FingerprintVector[];
  pairingQr: PairingQrVector[];
  open: OpenVector[];
  replay: ReplayVector[];
}

/** Where verify-vectors.ts expects the Rust-exported file. */
export const VECTORS_PATH = "src/protocol/__vectors__/latch-vectors.json";
