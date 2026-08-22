/**
 * SHARED TEST VECTOR CONTRACT — the JSON the phone needs crates/sigil-proto to export.
 *
 * This is the interop handshake with rust-core: the Rust crate serializes a set
 * of known-answer vectors to `src/protocol/__vectors__/sigil-vectors.json`
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
 *       "endpoints": ["lan://sigil.local:4823"],
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
 *       "name": "counter-is-ungated",
 *       "windowMs": 90000,
 *       "steps": [
 *         { "requestId": "<uuid>", "counter": 5, "ts": 1000000, "now": 1000000, "expectOk": true },
 *         { "requestId": "<uuid>", "counter": 3, "ts": 1000000, "now": 1000000, "expectOk": true }
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
  expectError?: "duplicateRequest" | "timestampOutOfWindow" | null;
}

export interface ReplayVector {
  name: string;
  windowMs: number;
  steps: ReplayStep[];
}

/**
 * combiner: the v2 threshold combiner (crates/sigil-proto/src/threshold.rs), which the
 * phone's TS combiner must mirror byte-for-byte.
 *
 * `zm`/`zf`/`ephemeralPub`/`accountId` are the INPUTS the phone is given; the
 * phone computes `K = BLAKE2b("sigil.threshold.v2" ‖ len·Zm ‖ len·Zf ‖ len·E ‖
 * len·accountId)` (32-byte digest; libsodium `crypto_generichash(32, …)`, u64-BE
 * length prefixes, the 18-byte domain as a raw leading constant) and must match
 * `expectedK`. `expectedTokenCt` is `AES-256-GCM(token; K, aeadNonce)` as
 * `ciphertext‖tag`, locking the AEAD leg too. `ecdhAlgo` records which SE output
 * shape produced these partials (informational for the combiner — it operates on
 * the already-shaped `zm`/`zf`).
 */
export interface CombinerVector {
  name: string;
  ecdhAlgo: "raw-x" | "x963-sha256";
  /** Combiner input Z_M = x(m·E), shaped per ecdhAlgo. 32-byte hex. */
  zm: string;
  /** Combiner input Z_F = x(f·E), shaped per ecdhAlgo. 32-byte hex. */
  zf: string;
  /** The account base E = e·G, ANSI X9.63 uncompressed (65 bytes). hex. */
  ephemeralPub: string;
  accountId: string;
  /** Expected derived token key K. 32-byte hex. */
  expectedK: string;
  /** AES-256-GCM nonce (12 bytes). hex. */
  aeadNonce: string;
  /** The plaintext token that was sealed. hex. */
  token: string;
  /** Expected AES-256-GCM ciphertext‖tag under K. hex. */
  expectedTokenCt: string;
}

/**
 * approveProof: the per-request approve proof (crates/sigil-proto/src/proof.rs),
 * which the phone's TS must mirror byte-for-byte. This is what makes invariant 4
 * structural on the plain-gate path, so a mismatch here is not a test failure, it
 * is every approval being denied.
 *
 * The phone is given `challengePubB64` on the request. It hands the decoded 65
 * bytes to the enclave, which returns `seRawX` (the raw x-coordinate, base64 in
 * the native module). It then applies the pairing's `ecdhAlgo` shaping with
 * `sharedInfo = challengePub` to get `shared`, and computes
 * `BLAKE2b("sigil.approve-proof.v1" ‖ len·shared ‖ len·requestId ‖ len·decision
 * ‖ len·lease)` (32-byte digest; libsodium `crypto_generichash(32, …)`, u64-BE
 * length prefixes, the 22-byte domain as a raw leading constant), which must equal
 * `expectedProof`. `expectedProofB64` is what goes on the wire.
 *
 * The `lease` field is the one easy thing to get wrong: an ABSENT lease absorbs a
 * zero-LENGTH field, a lease of `0` absorbs eight zero bytes. The
 * `raw-x/zero-lease` and `raw-x/no-lease` cases exist to separate them, and a
 * mirror that conflates the two produces proofs the daemon denies.
 */
export interface ApproveProofVector {
  name: string;
  ecdhAlgo: "raw-x" | "x963-sha256";
  /** The daemon challenge C = c·G, ANSI X9.63 uncompressed (65 bytes). hex. */
  challengePub: string;
  /** The same C exactly as it rides on the wire. Standard base64. */
  challengePubB64: string;
  /** What the Secure Enclave returns for x(f·C): the RAW x-coordinate. 32-byte hex. */
  seRawX: string;
  /** `seRawX` after the ecdhAlgo shaping, i.e. what is folded into the proof. 32-byte hex. */
  shared: string;
  requestId: string;
  decision: "approved" | "denied";
  /** The requested lease window, or `null` for run-once. Not interchangeable with `0`. */
  leaseTtlMs: number | null;
  /** Expected proof. 32-byte hex. */
  expectedProof: string;
  /** Expected proof exactly as it rides on the wire. Standard base64. */
  expectedProofB64: string;
}

/**
 * pairingTranscript: locks the phone's `pairingTranscript` builder and the
 * final confirmation `tag` against crates/sigil-proto's `pairing_transcript` +
 * `pairing_confirmation_vector` (#34) - the exact cross-language check that
 * would have caught the camelCase `seSharePub` wire bug in CI before it ever
 * reached a device.
 *
 * All inputs are the fixed values the Rust side minted for reproducibility
 * (not fresh CSPRNG bytes); `secret` and `nonce` feed
 * `buildPairingResponseWithNonce` (the fixed-nonce production wrapper) to
 * get `expectedTag`, while `daemon`/`endpoints`/`createdAt`/`phone`/`nonce`/
 * `seSharePub` feed `pairingTranscript` directly to get `expectedTranscript`.
 * `seSharePub` is present only on the v2 case, mirroring a real v2 pairing.
 */
export interface PairingTranscriptVector {
  name: string;
  daemon: PeerHex;
  endpoints: string[];
  createdAt: number;
  /** The one-time pairing secret. 32-byte hex. */
  secret: string;
  phone: PeerHex;
  /** 32-byte hex. */
  nonce: string;
  /** v2 only: the phone's threshold share `F`, standard base64 x963. `null`
   * (not just absent) on the v1 case - Rust's `Option::None` serializes to
   * JSON `null`, so callers must treat both the same as "absent". */
  seSharePub?: string | null;
  /** Expected `pairingTranscript(...)` output. 32-byte hex. */
  expectedTranscript: string;
  /** Expected `buildPairingResponseWithNonce(...).tag`. 32-byte hex. */
  expectedTag: string;
}

export interface SigilVectors {
  version: number;
  canonicalBytes: CanonicalVector[];
  fingerprint: FingerprintVector[];
  pairingQr: PairingQrVector[];
  open: OpenVector[];
  replay: ReplayVector[];
  combiner: CombinerVector[];
  approveProof?: ApproveProofVector[];
  pairingTranscript?: PairingTranscriptVector[];
}

/** Where verify-vectors.ts expects the Rust-exported file. */
export const VECTORS_PATH = "src/protocol/__vectors__/sigil-vectors.json";
