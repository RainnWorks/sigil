/**
 * The pairing ceremony's in-progress state, kept in one place so the crypto and
 * the six screens that drive it stay together and easy to update as proto lands.
 *
 * Real key custody: the Ed25519 + X25519 private halves are generated on-device
 * and live in the Secure Enclave; the wrapping key that holds the DEK is created
 * SE-gated with a Face ID confirmation. Here we model the shapes and compute the
 * fingerprint words; the enclave binding is the keystore seam (NEEDS
 * VERIFICATION on device — see biometric.ts).
 */
import {
  type DeviceIdentity,
  type PairingPayload,
  type PeerIdentity,
  type Sodium,
  fingerprintWords,
  generateDeviceIdentity,
  loadSodium,
  mailboxId,
  pairingFromQrString,
  peerIdentity,
} from "@/src/protocol";

export interface Ceremony {
  phone: DeviceIdentity;
  phonePub: PeerIdentity;
  /** Fingerprint of this phone's own identity, for the "this phone is the key" explainer. */
  ownWords: string[];
  scanned?: PairingPayload;
  /** The six confirmation words, once a QR is scanned. */
  confirmWords?: string[];
  /** The shared routing mailbox, once a QR is scanned. */
  mailbox?: Uint8Array;
}

let sodium: Sodium | null = null;
let ceremony: Ceremony | null = null;

async function sod(): Promise<Sodium> {
  if (!sodium) sodium = await loadSodium();
  return sodium;
}

/** Begin: generate this phone's identity and its own fingerprint words. */
export async function beginCeremony(): Promise<Ceremony> {
  const s = await sod();
  const phone = generateDeviceIdentity(s);
  const phonePub = peerIdentity(s, phone);
  // Own words = fingerprint of this identity with itself, a stable self-id.
  ceremony = { phone, phonePub, ownWords: fingerprintWords(s, phonePub, phonePub) };
  return ceremony;
}

export function currentCeremony(): Ceremony | null {
  return ceremony;
}

/**
 * Accept a scanned QR: parse the daemon payload, pin it, and derive the six
 * confirmation words plus the shared mailbox. Both devices compute identical
 * words from the two pinned identities, defeating a MITM on the QR channel.
 */
export async function acceptScan(qr: string): Promise<Ceremony> {
  const s = await sod();
  if (!ceremony) await beginCeremony();
  const c = ceremony!;
  const scanned = pairingFromQrString(qr);
  c.scanned = scanned;
  c.confirmWords = fingerprintWords(s, c.phonePub, scanned.daemon);
  c.mailbox = mailboxId(s, c.phonePub, scanned.daemon);
  return c;
}

export function resetCeremony(): void {
  ceremony = null;
}
