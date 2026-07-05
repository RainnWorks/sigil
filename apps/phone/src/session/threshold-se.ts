/**
 * Pairing-time helpers for the phone's v2 Secure-Enclave threshold share `f`
 * (../../modules/latch-se). At pairing the phone mints `f` in the enclave and
 * hands its public point `F` to the Mac; the per-request partial `Z_F` is derived
 * in src/session/controller.ts. See docs/design/threshold-v2.md §5.
 */
import { type Sodium, toBase64Url } from "@/src/protocol";
import { generateShareKey, isSecureEnclaveAvailable } from "@/modules/latch-se";

/**
 * The ECDH-output shape the phone's Secure-Enclave share is pinned to. CryptoKit
 * key-agreement always yields the raw X-coordinate, and raw-x is the recommended
 * shape (design §2 / NV-2), so the phone advertises "raw-x" at pairing. The x963
 * KDF path is still honored per request if a v2 account was pinned that way.
 */
export const PHONE_SE_ECDH_ALGO = "raw-x" as const;

/** Whether this device can mint/use the SE share (false on the Simulator). */
export function secureEnclaveAvailable(): boolean {
  return isSecureEnclaveAvailable();
}

/** A fresh, stable, URL-safe id for a pinned SE share key. */
export function newSeKeyId(sodium: Sodium): string {
  return `latch-se-${toBase64Url(sodium.randombytes_buf(9))}`;
}

/**
 * Mint the SE share key `f` under `seKeyId` and return its public point `F` in
 * ANSI X9.63 form, standard-base64, for delivery to the Mac. The private scalar
 * is generated in and never leaves the Secure Enclave.
 */
export function mintShareKey(seKeyId: string): Promise<string> {
  return generateShareKey(seKeyId);
}
