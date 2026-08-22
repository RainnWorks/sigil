/**
 * The device keystore seam for a completed pairing. It persists the phone's
 * passcode-tier identity record: the phone's device identity, the pinned daemon
 * identity, the steady-state mailbox, the relay base, and the pinned Secure
 * Enclave share id. This is what the session needs to OPEN and display an inbound
 * request (a passcode-tier read), so it is stored without a biometric prompt and
 * loaded at app start.
 *
 * At rest it is protected with `WHEN_UNLOCKED_THIS_DEVICE_ONLY` so it cannot
 * travel to other hardware in an encrypted backup. That class is load-bearing
 * rather than hygiene: the biometric gate binds to a DEVICE and not to a human,
 * so a restored clone enrols its own face and passes it. See `IDENTITY_OPTIONS`.
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

/**
 * The record's keychain item name. **v2 is a NEW NAME, and that is the whole
 * mechanism, not a version bump.**
 *
 * The accessibility class can only be set on `SecItemAdd`. expo-secure-store's
 * `setItemAsync` tries the add, and on `errSecDuplicateItem` falls through to
 * `update()`, whose update dictionary is `[kSecValueData]` and nothing else
 * (vendored `ios/SecureStoreModule.swift`). So simply adding `keychainAccessible`
 * to the existing write would have protected NEW pairings only: every phone
 * already paired would keep the backup-restorable class forever, a fresh-install
 * test would pass, and nothing anywhere would report the difference. Writing
 * under a name that has never existed forces the add path, so the class actually
 * applies.
 */
const IDENTITY_KEY = "sigil.pairing.identity.v2";

/** The pre-migration name. Read once, copied forward, then retired. */
const IDENTITY_KEY_V1 = "sigil.pairing.identity";

/**
 * How the identity record is protected at rest, and it is doing more work than
 * key hygiene usually does.
 *
 * `THIS_DEVICE_ONLY` keeps the item out of encrypted backups, so it cannot be
 * restored onto other hardware. That matters because THE BIOMETRIC GATE BINDS TO
 * A DEVICE, NOT TO A HUMAN: `faceGate` asks whether a biometric is enrolled here
 * and whether it passes, so an attacker who restores a backup onto their own
 * phone enrols their own face and the gate opens for them exactly as designed.
 * Invariant #4 is not weakened by cloning, it is absent from it. This class is
 * what enforces "this phone"; `faceGate` cannot.
 *
 * What a clone would get is worth stating precisely, because it is not
 * everything: the signing seed, the agreement seed, the mailbox and the pinned
 * daemon keys, which open every PLAIN GATE, and on this machine every `op` rule
 * is a plain gate. It could NOT open a threshold-sealed secret, because `f` is
 * enclave-resident and does not travel (`seKeyId` would arrive as a dangling
 * reference and `computePartial` fails). It is also worse than a stolen phone on
 * detection: theft is noticed and the real phone stops working, whereas a clone
 * is silent, the real phone keeps working, and under ring-all both receive every
 * request with first-wins resolution, so the clone can race the human.
 *
 * `WHEN_UNLOCKED` rather than `AFTER_FIRST_UNLOCK` because nothing reads this in
 * the background: `loadPairing` runs at session arm, in the foreground.
 *
 * NOT `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`, which looks stronger and is worse: it
 * destroys the item if the passcode is ever removed, silently un-pairing a
 * working install in a way nobody could diagnose, and it buys nothing, since
 * biometry cannot be enrolled without a passcode anyway. NOT expo's
 * `requireAuthentication` either, which would put the record behind
 * `.biometryCurrentSet`, so enrolling a new fingerprint would destroy the
 * pairing, colliding head-on with the durability principle.
 *
 * NEEDS VERIFICATION on hardware. Keychain accessibility cannot be exercised
 * headlessly and the failure mode is silent, so nothing here is proof. The test
 * that would prove it: pair, take an encrypted backup, restore to a second
 * device, and confirm the restored app is unpaired.
 */
const IDENTITY_OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

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

/**
 * Decode a stored record, or null if it is unreadable.
 *
 * Unparseable means corrupt, or a schema from a future build. Treated as
 * unpaired and failing closed, but with a trace: this is a local storage fault
 * rather than hostile input, and would otherwise be silent.
 */
function parseIdentity(raw: string): StoredPairing | null {
  try {
    return decodeIdentity(JSON.parse(raw) as IdentityJson);
  } catch (e) {
    console.warn(
      `[keystore] stored pairing identity was unreadable: ${e instanceof Error ? e.message : String(e)}`,
    );
    return null;
  }
}

/** Persist the pairing: the passcode-tier identity record. No at-rest release key. */
export async function savePairing(p: StoredPairing): Promise<void> {
  await SecureStore.setItemAsync(
    IDENTITY_KEY,
    JSON.stringify(encodeIdentity(p)),
    IDENTITY_OPTIONS,
  );
}

/**
 * Move a pre-migration record to the protected key, returning it either way.
 *
 * **COPY FORWARD, VERIFY, THEN RETIRE, IN THAT ORDER.** A delete-then-write would
 * lose the pairing outright if the process died between the two, and re-pairing
 * is exactly what the durability principle says an upgrade must never force. Here
 * at least one readable copy exists at every interruption point: before the
 * write only v1, between write and delete both, afterwards only v2. A failed
 * verification leaves v1 in place and simply retries on the next launch, which
 * costs nothing but another attempt.
 *
 * The old record is not overwritten or scrubbed first, because it cannot be: its
 * accessibility class is fixed at creation, so the only way to stop it being
 * backup-restorable is to delete it.
 */
async function migrateIdentityToProtectedKey(): Promise<StoredPairing | null> {
  const raw = await SecureStore.getItemAsync(IDENTITY_KEY_V1);
  if (!raw) return null;
  const pairing = parseIdentity(raw);
  if (!pairing) return null;
  try {
    await SecureStore.setItemAsync(IDENTITY_KEY, raw, IDENTITY_OPTIONS);
    // Read back the bytes rather than trusting the write. A mismatch means the
    // copy is not safe to rely on, so v1 stays and the pairing still works.
    const check = await SecureStore.getItemAsync(IDENTITY_KEY);
    if (check !== raw || !parseIdentity(check)) {
      console.warn("[keystore] identity migration could not be verified; keeping the old record");
      return pairing;
    }
    await SecureStore.deleteItemAsync(IDENTITY_KEY_V1);
  } catch (e) {
    // The pairing is intact either way; the record simply stays on the old key
    // and the next launch tries again.
    console.warn(
      `[keystore] identity migration failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  return pairing;
}

/**
 * Load the passcode-tier pairing record, or null if this phone is unpaired.
 * Migrates a pre-migration record to the protected key on the way through.
 */
export async function loadPairing(): Promise<StoredPairing | null> {
  const raw = await SecureStore.getItemAsync(IDENTITY_KEY);
  if (raw) return parseIdentity(raw);
  return migrateIdentityToProtectedKey();
}

/** Whether this phone has a stored pairing (cheap, passcode-tier). */
export async function isPaired(): Promise<boolean> {
  if ((await SecureStore.getItemAsync(IDENTITY_KEY)) !== null) return true;
  // A phone paired before the migration is still paired; it just has not been
  // through `loadPairing` yet this launch.
  return (await SecureStore.getItemAsync(IDENTITY_KEY_V1)) !== null;
}

/** Remove the stored pairing (unpair / reset). Clears BOTH keys: a reset that
 *  left the pre-migration copy behind would silently re-pair on next launch. */
export async function clearPairing(): Promise<void> {
  await SecureStore.deleteItemAsync(IDENTITY_KEY);
  await SecureStore.deleteItemAsync(IDENTITY_KEY_V1);
}
