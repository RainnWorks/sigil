/**
 * The JS face of the Latch Secure Enclave module. It exposes the phone's v2
 * threshold share `f`: a non-exportable P-256 key-agreement key minted in the
 * Secure Enclave under Face ID, whose only output is a per-request partial
 * `Z_F = x(f·E)`. See ios/LatchSeModule.swift and docs/design/threshold-v2.md.
 *
 * The native module is iOS-only (the Secure Enclave). On a platform or a build
 * where it is not linked, `requireNativeModule` throws at load; callers gate on
 * {@link isSecureEnclaveAvailable} first and fail closed.
 */
import { requireNativeModule } from "expo-modules-core";

interface LatchSeNative {
  isAvailable(): boolean;
  hasShareKey(keyId: string): boolean;
  generateShareKey(keyId: string): Promise<string>;
  computePartial(keyId: string, ephemeralPubBase64: string, reason: string): Promise<string>;
  deleteShareKey(keyId: string): void;
}

let cached: LatchSeNative | null = null;

/** Resolve the native module lazily so a missing link surfaces at call sites. */
function native(): LatchSeNative {
  if (!cached) cached = requireNativeModule<LatchSeNative>("LatchSe");
  return cached;
}

/**
 * Whether this device has a usable Secure Enclave. False on the Simulator. Never
 * throws: a missing native link (e.g. an old build) resolves to false, so the
 * caller falls back / fails closed rather than crashing.
 */
export function isSecureEnclaveAvailable(): boolean {
  try {
    return native().isAvailable();
  } catch {
    return false;
  }
}

/** Whether a share key blob is stored under `keyId` (cheap; no biometric). */
export function hasShareKey(keyId: string): boolean {
  try {
    return native().hasShareKey(keyId);
  } catch {
    return false;
  }
}

/**
 * Pairing: mint the share key `f` in the Secure Enclave and return F, the public
 * point in ANSI X9.63 uncompressed form (65 bytes), standard-base64. The Mac pins
 * F and seals account tokens to it. The private scalar never leaves the enclave.
 */
export function generateShareKey(keyId: string): Promise<string> {
  return native().generateShareKey(keyId);
}

/**
 * Per request: on-curve-validate `E`, then key-agree `f` against it inside the
 * Secure Enclave (the Face-ID gate) and return the RAW 32-byte ECDH X-coordinate
 * x(f·E), standard-base64. The caller applies the record's ECDH-output shaping
 * (see src/protocol/threshold.ts `shapeEcdh`) to turn this into `Z_F`. `reason`
 * is the generic biometric-prompt string; the provider-blind phone does not name
 * an account here (R5 removed). Rejects on an off-curve `E`, a missing key, or a
 * denied/failed biometric.
 */
export function computePartial(
  keyId: string,
  ephemeralPubBase64: string,
  reason: string,
): Promise<string> {
  return native().computePartial(keyId, ephemeralPubBase64, reason);
}

/** Retire a share (unpair / re-key). `f` is non-exportable, so this is final. */
export function deleteShareKey(keyId: string): void {
  try {
    native().deleteShareKey(keyId);
  } catch {
    // Absent module / already gone: nothing to retire.
  }
}
