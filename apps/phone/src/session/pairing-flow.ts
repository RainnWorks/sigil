/**
 * The pairing ceremony driver: the phone half of crates/proto's handshake, run
 * over the real blind-relay rendezvous. One module holds the in-progress state so
 * the crypto and the screens that drive it stay together.
 *
 * The ceremony, matching docs/design/pairing.md and crates/latch/src/pair.rs:
 *   1. scan       - decode the QR, reject a stale one, mint this phone's identity,
 *                   pin the daemon, derive the six SAS words and the rendezvous
 *                   mailbox (the bootstrap channel keyed by daemon id + secret).
 *   2. handshake  - build the authenticated PairingResponse (proof-of-secret MAC
 *                   over the transcript) and attach to the rendezvous mailbox to
 *                   send it, base64url. This is message 1; the daemon verifies
 *                   it, pins this phone, and shows its own six words.
 *   3. sas        - the human compares the six words on both screens (the backstop
 *                   against a leaked secret or a tag-path bug). A match proceeds.
 *   4. deliver    - wait on the same attach for the daemon's sealed DEK
 *                   (message 3), open it, recover the DEK, and store it behind
 *                   Face ID; then arm the live approval session.
 *
 * v3: the rendezvous mailbox rides the same stateless `/attach` rendezvous as
 * the steady-state mailbox (see `transport/relay-attach.ts`), just keyed
 * differently. One attach is held open across messages 1 and 3 - matching the
 * daemon's `RendezvousWs` (crates/relay-client), which makes one bounded-
 * lifetime attach for the whole ceremony and does not reconnect: if it drops
 * mid-pairing, the ceremony fails closed and the human re-runs it.
 *
 * Real key custody: the Ed25519 + X25519 private halves are generated on-device;
 * the DEK is written to the biometric-tier keystore item. See keystore.ts for the
 * on-device NEEDS-VERIFICATION notes.
 */
import {
  buildPairingResponse,
  type DeviceIdentity,
  type Envelope,
  envelopeFromWire,
  type EnvelopeWire,
  agreementSecretKey,
  fingerprintWords,
  generateDeviceIdentity,
  loadSodium,
  mailboxId,
  open,
  type PairingPayload,
  pairingFromQrString,
  pairingResponseToSubmitString,
  type PeerIdentity,
  peerIdentity,
  recoverDek,
  rendezvousMailbox,
  ReplayGuard,
  type Sodium,
} from "@/src/protocol";
import { relayBaseFromEndpoints } from "@/src/transport/relay-http";
import { AttachSocket, attachUrlForMailbox } from "@/src/transport/relay-attach";
import { generateShareKey, isSecureEnclaveAvailable } from "@/modules/latch-se";
import { armLiveSession } from "./controller";
import { savePairing } from "./keystore";

/**
 * The SE share key id. FIXED, and must equal the daemon's `DEFAULT_SE_KEY_ID`
 * ("phone-se.v2", crates/latch/src/threshold.rs): the Mac assigns this id locally
 * at pairing and echoes it in every per-request `ThresholdChallenge.seKeyId`, so
 * the phone must store `f` under exactly this id or `computePartial` cannot
 * reload it. Re-pairing overwrites `f` under the same id (recovery = rotation).
 */
const PHONE_SE_KEY_ID = "phone-se.v2";

/** QR / pairing-secret lifetime, matching proto `PAIRING_SECRET_TTL_MS` (180s). */
const PAIRING_SECRET_TTL_MS = 180_000;
/** How long to wait on the rendezvous mailbox for the sealed DEK. */
const DEK_WAIT_MS = 60_000;

export class PairingExpiredError extends Error {
  constructor() {
    super("This pairing QR has expired. Generate a fresh one on your Mac.");
    this.name = "PairingExpiredError";
  }
}

export interface Ceremony {
  phone: DeviceIdentity;
  phonePub: PeerIdentity;
  /** Fingerprint of this phone's own identity, for the "this phone is the key" explainer. */
  ownWords: string[];
  scanned?: PairingPayload;
  /** The six confirmation words, once a QR is scanned. */
  confirmWords?: string[];
  /** The steady-state routing mailbox `mailboxId(phone, daemon)`, once scanned. */
  mailbox?: Uint8Array;
  /** The relay base (normalized http(s)), once scanned. */
  relayBase?: string;
  /** The bootstrap rendezvous mailbox, once scanned. */
  rendezvous?: Uint8Array;
  /** The v2 SE share key id minted for this pairing (device-only; no SE => absent). */
  seKeyId?: string;
  /** F = f·G, standard base64 x963, carried on the PairingResponse as se_share_pub. */
  seSharePub?: string;
  /** True once the PairingResponse has been submitted (message 1 sent). */
  responseSubmitted?: boolean;
}

let sodium: Sodium | null = null;
let ceremony: Ceremony | null = null;
/**
 * The one attach held open across message 1 (submit) and message 3 (deliver).
 * Opened by `submitPairingResponse`, closed by `awaitDekDelivery` (success or
 * timeout) or `resetCeremony` (abandoned).
 */
let rendezvousSocket: AttachSocket | null = null;

async function sod(): Promise<Sodium> {
  if (!sodium) sodium = await loadSodium();
  return sodium;
}

/** Begin: generate this phone's identity and its own fingerprint words. */
export async function beginCeremony(): Promise<Ceremony> {
  const s = await sod();
  const phone = generateDeviceIdentity(s);
  const phonePub = peerIdentity(s, phone);
  ceremony = { phone, phonePub, ownWords: fingerprintWords(s, phonePub, phonePub) };
  return ceremony;
}

export function currentCeremony(): Ceremony | null {
  return ceremony;
}

/**
 * Accept a scanned QR: reject a stale one, pin the daemon, and derive the six
 * confirmation words, the steady-state mailbox, and the bootstrap rendezvous
 * mailbox. Both devices compute identical words from the two pinned identities,
 * defeating a MITM on the QR channel.
 */
export async function acceptScan(qr: string): Promise<Ceremony> {
  const s = await sod();
  if (!ceremony) await beginCeremony();
  const c = ceremony!;
  const scanned = pairingFromQrString(qr);
  if (Date.now() - scanned.createdAt > PAIRING_SECRET_TTL_MS) {
    throw new PairingExpiredError();
  }
  c.scanned = scanned;
  c.confirmWords = fingerprintWords(s, c.phonePub, scanned.daemon);
  c.mailbox = mailboxId(s, c.phonePub, scanned.daemon);
  c.relayBase = relayBaseFromEndpoints(scanned.endpoints);
  c.rendezvous = rendezvousMailbox(s, scanned.daemon, scanned.secret);
  c.responseSubmitted = false;
  return c;
}

/**
 * Message 1: build the authenticated PairingResponse and attach to the
 * rendezvous mailbox to send it (base64url). Sent before SAS, because the
 * daemon needs it to pin this phone and show its matching six words. Opens
 * {@link rendezvousSocket}, held across this call and the later
 * {@link awaitDekDelivery} - matching the daemon's one-bounded-lifetime-attach
 * `RendezvousWs`.
 *
 * v2: mint the Secure-Enclave share key `f` (if this device has an SE) FIRST, so
 * its public point `F` rides on this response as `se_share_pub`, bound into the
 * confirmation MAC (a relay can neither swap nor strip it without the pairing
 * secret). Minting needs no biometric; the Face ID gate is on later
 * key-agreement. On the Simulator (no SE) the phone pairs v1-only. The private
 * `f` never leaves the enclave; a mint failure degrades to a v1 pairing.
 */
export async function submitPairingResponse(): Promise<void> {
  const s = await sod();
  const c = ceremony;
  if (!c?.scanned || !c.rendezvous || !c.relayBase) {
    throw new Error("no scanned pairing to respond to");
  }
  if (isSecureEnclaveAvailable() && !c.seSharePub) {
    try {
      // Standard base64 (with padding) of the 65-byte x963 F, minted under the
      // daemon's fixed key id so per-request challenges resolve `f`.
      c.seSharePub = await generateShareKey(PHONE_SE_KEY_ID);
      c.seKeyId = PHONE_SE_KEY_ID;
    } catch {
      c.seSharePub = undefined;
      c.seKeyId = undefined;
    }
  }
  const resp = buildPairingResponse(s, c.scanned, c.phonePub, c.seSharePub);
  rendezvousSocket ??= new AttachSocket(attachUrlForMailbox(c.relayBase, c.rendezvous));
  await rendezvousSocket.send(pairingResponseToSubmitString(resp));
  c.responseSubmitted = true;
}

/**
 * Message 3: wait on the same attach for the daemon's sealed DEK, open it
 * (verify the daemon's signature, replay-check, decrypt), recover the DEK, store
 * it behind Face ID, persist the pairing (including the v2 SE key id, whose `F`
 * was already delivered on message 1), and arm the live approval session. Called
 * only after the human confirmed the SAS. Throws on timeout or a bad DEK envelope
 * (fail closed). Closes {@link rendezvousSocket} either way: the ceremony is
 * strictly one message per direction, so there is nothing left to wait for.
 */
export async function awaitDekDelivery(): Promise<void> {
  const s = await sod();
  const c = ceremony;
  if (!c?.scanned || !c.rendezvous || !c.relayBase || !c.mailbox || !c.confirmWords) {
    throw new Error("pairing is not ready to receive the DEK");
  }
  const socket = (rendezvousSocket ??= new AttachSocket(
    attachUrlForMailbox(c.relayBase, c.rendezvous),
  ));
  const wire = await socket.waitForDeliver(DEK_WAIT_MS);
  socket.close();
  rendezvousSocket = null;
  if (!wire) {
    throw new Error("timed out waiting for the Mac to deliver the key");
  }

  let env: Envelope;
  try {
    env = envelopeFromWire(JSON.parse(wire) as EnvelopeWire);
  } catch {
    throw new Error("the delivered key envelope was malformed");
  }

  // Open the DEK-delivery envelope: signed by the pinned daemon, sealed to this
  // phone. A fresh guard: this is the first (and only) message on this pairing.
  const payload = open<number[]>(s, env, {
    sender: c.scanned.daemon,
    recipientAgreementSecret: agreementSecretKey(s, c.phone),
    guard: new ReplayGuard(),
  });
  const dek = recoverDek(payload);

  // v2: the phone's SE share `F` was already delivered to the Mac ON message 1
  // (as `se_share_pub`, bound into the confirmation MAC — see
  // submitPairingResponse), so there is nothing to send here. Persist the SE key
  // id so per-request approvals can reload `f`; absent on a v1 (no-SE) pairing.
  const seKeyId = c.seKeyId;

  await savePairing(
    {
      phone: c.phone,
      daemonPub: c.scanned.daemon,
      mailbox: c.mailbox,
      relayBase: c.relayBase,
      sasWords: c.confirmWords,
      pairedAt: Date.now(),
      ...(seKeyId ? { seKeyId } : {}),
    },
    dek,
  );
  dek.fill(0);
  await armLiveSession();
}

export function resetCeremony(): void {
  rendezvousSocket?.close();
  rendezvousSocket = null;
  ceremony = null;
}
