/**
 * The device keystore seam for a completed pairing. It persists two things at two
 * security tiers, matching the profile's request-read vs release split:
 *
 *   - IDENTITY (passcode-tier): the phone's device identity, the pinned daemon
 *     identity, the steady-state mailbox, and the relay base. This is what the
 *     session needs to OPEN and display an inbound request (a passcode-tier read),
 *     so it is stored without a biometric prompt and loaded at app start.
 *   - DEK (biometric-tier): the data-encryption key recovered at pairing. This is
 *     what AUTHORIZES a secret release, so it is stored `requireAuthentication`
 *     and only ever read behind a fresh Face ID gate at approve time.
 *
 * NEEDS VERIFICATION (on device): expo-secure-store maps `requireAuthentication`
 * onto a Keychain item gated by the current biometric set (Secure Enclave on
 * iOS). Confirm the DEK item prompts Face ID on read and is invalidated when the
 * enrolled biometrics change. The deeper goal of an SE-held X25519 agreement key
 * that never surfaces in JS is the keystore NEEDS-VERIFICATION already tracked in
 * docs/design/pairing.md; this seam stores the private bytes in the biometric
 * Keychain until that native module lands.
 */
import * as SecureStore from "expo-secure-store";

import {
  fromBase64,
  type DeviceIdentity,
  type PeerIdentity,
  toBase64,
} from "@/src/protocol";

const IDENTITY_KEY = "latch.pairing.identity";
const DEK_KEY = "latch.pairing.dek";

/** The passcode-tier record: everything needed to read (not release). */
export interface StoredPairing {
  phone: DeviceIdentity;
  daemonPub: PeerIdentity;
  mailbox: Uint8Array;
  relayBase: string;
  sasWords: string[];
  pairedAt: number;
  /**
   * The pinned v2 Secure-Enclave share key id, when this phone minted one at
   * pairing. Passcode-tier: it only names which non-exportable enclave key to
   * key-agree with (the private `f` lives in the Secure Enclave, never here).
   * Absent on a v1-only pairing.
   */
  seKeyId?: string;
}

interface IdentityJson {
  signingSeed: string;
  agreementSeed: string;
  daemonVerifying: string;
  daemonAgreement: string;
  mailbox: string;
  relayBase: string;
  sasWords: string[];
  pairedAt: number;
  /** Optional: absent on v1-only pairings persisted before v2. */
  seKeyId?: string;
}

function encodeIdentity(p: StoredPairing): IdentityJson {
  return {
    signingSeed: toBase64(p.phone.signingSeed),
    agreementSeed: toBase64(p.phone.agreementSeed),
    daemonVerifying: toBase64(p.daemonPub.verifying),
    daemonAgreement: toBase64(p.daemonPub.agreement),
    mailbox: toBase64(p.mailbox),
    relayBase: p.relayBase,
    sasWords: p.sasWords,
    pairedAt: p.pairedAt,
    ...(p.seKeyId ? { seKeyId: p.seKeyId } : {}),
  };
}

function decodeIdentity(j: IdentityJson): StoredPairing {
  return {
    phone: {
      signingSeed: fromBase64(j.signingSeed),
      agreementSeed: fromBase64(j.agreementSeed),
    },
    daemonPub: {
      verifying: fromBase64(j.daemonVerifying),
      agreement: fromBase64(j.daemonAgreement),
    },
    mailbox: fromBase64(j.mailbox),
    relayBase: j.relayBase,
    sasWords: j.sasWords,
    pairedAt: j.pairedAt,
    ...(j.seKeyId ? { seKeyId: j.seKeyId } : {}),
  };
}

/** Persist the pairing: identity passcode-tier, DEK biometric-tier. */
export async function savePairing(p: StoredPairing, dek: Uint8Array): Promise<void> {
  await SecureStore.setItemAsync(IDENTITY_KEY, JSON.stringify(encodeIdentity(p)));
  await SecureStore.setItemAsync(DEK_KEY, toBase64(dek), {
    requireAuthentication: true,
    authenticationPrompt: "Confirm to store the unwrap key",
  });
}

/** Load the passcode-tier pairing record, or null if this phone is unpaired. */
export async function loadPairing(): Promise<StoredPairing | null> {
  const raw = await SecureStore.getItemAsync(IDENTITY_KEY);
  if (!raw) return null;
  try {
    return decodeIdentity(JSON.parse(raw) as IdentityJson);
  } catch {
    return null;
  }
}

/**
 * Read the DEK. This prompts Face ID (the item is `requireAuthentication`), so it
 * is the biometric-tier release path and must only be called after the approval
 * gate. Returns the raw 32-byte key, or null if absent / the gate was refused.
 */
export async function loadDek(prompt = "Approve secret release"): Promise<Uint8Array | null> {
  try {
    const b64 = await SecureStore.getItemAsync(DEK_KEY, { authenticationPrompt: prompt });
    if (!b64) return null;
    const bytes = fromBase64(b64);
    return bytes.length === 32 ? bytes : null;
  } catch {
    // A refused or failed biometric throws; fail closed to no key.
    return null;
  }
}

/** Whether this phone has a stored pairing (cheap, passcode-tier). */
export async function isPaired(): Promise<boolean> {
  return (await SecureStore.getItemAsync(IDENTITY_KEY)) !== null;
}

/** Remove both records (unpair / reset). */
export async function clearPairing(): Promise<void> {
  await SecureStore.deleteItemAsync(IDENTITY_KEY);
  await SecureStore.deleteItemAsync(DEK_KEY);
}
