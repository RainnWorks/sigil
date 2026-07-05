/**
 * The bridge between the Secure-Enclave native module (../../modules/latch-se)
 * and the protocol layer for v2 threshold decryption. It is the only place the
 * app turns a signed {@link ThresholdChallenge} into the phone's partial
 * `Z_F = x(f·E)`, and the only place it mints the SE share key at pairing.
 *
 * Split of responsibility, matching docs/design/threshold-v2.md:
 *   - Native (Swift/CryptoKit): on-curve validation of `E` (R2/NV-6) + the
 *     Face-ID-gated Secure-Enclave key-agreement, returning the RAW X-coordinate.
 *     The private `f` never leaves the enclave.
 *   - Here (TS): the structural pre-check, the ECDH-output shaping
 *     ({@link shapeEcdh}: raw-x identity or the x963-sha256 KDF, byte-mirroring
 *     the Rust core), and the R5 consent cross-check against the readout.
 */
import {
  fromBase64,
  looksLikeX963P256,
  type SecretRef,
  shapeEcdh,
  type Sodium,
  type ThresholdChallenge,
  type ThresholdPartial,
  toBase64,
} from "@/src/protocol";
import {
  computePartial,
  generateShareKey,
  isSecureEnclaveAvailable,
} from "@/modules/latch-se";

/**
 * The ECDH-output shape the phone's Secure-Enclave share is pinned to. CryptoKit
 * key-agreement always yields the raw X-coordinate, and raw-x is the recommended
 * shape (design §2/NV-2), so the phone advertises "raw-x" at pairing. The x963
 * KDF path is still honored per request if a v2 account was pinned that way.
 */
export const PHONE_SE_ECDH_ALGO = "raw-x" as const;

/** Whether this device can mint/use the SE share (false on the Simulator). */
export function secureEnclaveAvailable(): boolean {
  return isSecureEnclaveAvailable();
}

/** A fresh, stable id for a pinned SE share key. */
export function newSeKeyId(sodium: Sodium): string {
  const r = sodium.randombytes_buf(9);
  return `latch-se-${toBase64(r).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

/**
 * Mint the SE share key `f` under `seKeyId` and return its public point `F` in
 * ANSI X9.63 form, standard-base64, for delivery to the Mac. The private scalar
 * is generated in and never leaves the Secure Enclave.
 */
export function mintShareKey(seKeyId: string): Promise<string> {
  return generateShareKey(seKeyId);
}

export class ThresholdConsentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ThresholdConsentError";
  }
}

/**
 * Compute the phone's threshold partial for a challenge. Fails closed
 * ({@link ThresholdConsentError}) if `E` is structurally malformed BEFORE the SE
 * op; the load-bearing on-curve/twist rejection is the native validator (R2).
 * The SE key-agreement prompts Face ID (bound to the account `label`, R5) and
 * returns the raw X-coordinate, which this shapes into `Z_F` per `ecdhAlgo`.
 */
export async function computeThresholdPartial(
  sodium: Sodium,
  challenge: ThresholdChallenge,
): Promise<ThresholdPartial> {
  const e = fromBase64(challenge.ephemeralPub);
  // Cheap fail-fast; native re-validates on-curve before the scalar mult.
  if (!looksLikeX963P256(e)) {
    throw new ThresholdConsentError("The account base point E is malformed.");
  }
  if (!challenge.seKeyId || !challenge.accountId) {
    throw new ThresholdConsentError("The threshold challenge is missing its account binding.");
  }
  // Native: on-curve validate (R2/NV-6) + Face-ID-gated SE key-agreement -> raw X.
  const rawXBase64 = await computePartial(challenge.seKeyId, challenge.ephemeralPub, challenge.label);
  const rawX = fromBase64(rawXBase64);
  const zf = shapeEcdh(sodium, rawX, challenge.ecdhAlgo, e);
  return { accountId: challenge.accountId, zf: toBase64(zf) };
}

/**
 * R5 consent cross-check: does the account named in the challenge agree with the
 * secret refs shown in the readout? A residual-#7 Mac attacker can only decouple
 * "what the human sees" from "what gets unlocked" if the account label and the
 * displayed secrets can drift apart, so we flag when the challenge's account
 * shares no meaningful token with any secret ref. Returns true when consistent
 * (or when there is nothing to cross-check). The human is the final authority;
 * the UI surfaces a caution on false, it is not a silent block.
 */
export function consentConsistent(challenge: ThresholdChallenge, secrets: SecretRef[]): boolean {
  if (secrets.length === 0) return true;
  const account = new Set([...tokens(challenge.label), ...tokens(challenge.accountId)]);
  if (account.size === 0) return false;
  for (const ref of secrets) {
    for (const t of [ref.label, ref.provider, ...ref.segments].flatMap(tokens)) {
      if (account.has(t)) return true;
    }
  }
  return false;
}

/** Lowercase word tokens (>=3 chars) for the fuzzy consent cross-check. */
function tokens(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 3);
}
