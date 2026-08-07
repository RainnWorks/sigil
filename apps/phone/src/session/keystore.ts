/**
 * The device keystore seam for a completed pairing. It persists the phone's
 * passcode-tier identity record: the phone's device identity, the pinned daemon
 * identity, the steady-state mailbox, the relay base, and the pinned Secure
 * Enclave share id. This is what the session needs to OPEN and display an inbound
 * request (a passcode-tier read), so it is stored without a biometric prompt and
 * loaded at app start.
 *
 * There is no at-rest release key here. Authorizing a secret release is the
 * per-request Secure-Enclave key-agreement (the threshold partial `Z_F`), which
 * never surfaces the private `f` in JS: the Face ID gate is on that enclave
 * agreement, not on any bytes this seam stores. The private `f` lives in the
 * Secure Enclave, referenced only by the `seKeyId` recorded below.
 */
import * as SecureStore from "expo-secure-store";

import {
  fromBase64,
  type DeviceIdentity,
  type PeerIdentity,
  toBase64,
} from "@/src/protocol";

const IDENTITY_KEY = "sigil.pairing.identity";

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

/** Persist the pairing: the passcode-tier identity record. No at-rest release key. */
export async function savePairing(p: StoredPairing): Promise<void> {
  await SecureStore.setItemAsync(IDENTITY_KEY, JSON.stringify(encodeIdentity(p)));
}

/** Load the passcode-tier pairing record, or null if this phone is unpaired. */
export async function loadPairing(): Promise<StoredPairing | null> {
  const raw = await SecureStore.getItemAsync(IDENTITY_KEY);
  if (!raw) return null;
  try {
    return decodeIdentity(JSON.parse(raw) as IdentityJson);
  } catch (e) {
    // The stored identity record is present but unparseable (corrupt / a schema
    // from a future build). Treat as unpaired and fail closed, but leave a trace:
    // this is a local storage fault, not hostile input, and is otherwise silent.
    console.warn(
      `[keystore] stored pairing identity was unreadable: ${e instanceof Error ? e.message : String(e)}`,
    );
    return null;
  }
}

/** Whether this phone has a stored pairing (cheap, passcode-tier). */
export async function isPaired(): Promise<boolean> {
  return (await SecureStore.getItemAsync(IDENTITY_KEY)) !== null;
}

/** Remove the stored pairing (unpair / reset). */
export async function clearPairing(): Promise<void> {
  await SecureStore.deleteItemAsync(IDENTITY_KEY);
}
