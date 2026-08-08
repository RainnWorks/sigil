/**
 * The live session controller: the single place the app arms the real transport
 * and dispatches decisions over it. It ties together the keystore (the stored
 * pairing), the {@link PhoneRelay} transport, and the {@link SigilSession} crypto.
 *
 * Two tiers, kept apart exactly as the keystore stores them:
 *   - Arming is a read-path action: it loads the passcode-tier identity, starts
 *     polling, and opens/displays inbound requests. No biometric.
 *   - Approving is a release-path action: {@link liveApprove} runs the Secure
 *     Enclave key-agreement behind Face ID (for a threshold-sealed secret) or the
 *     Face ID gate alone (for a plain gate), and only then seals the response. The
 *     biometric IS the authorization; there is no path that seals an approve
 *     without it. Deny seals nothing sensitive and needs no biometric.
 *
 * When no pairing is stored (dev / demo) nothing is armed and the UI falls back
 * to its local-only store path with the mock transport.
 */
import {
  type ApprovalRequest,
  fingerprintWords,
  fromBase64,
  type LeaseListMessage,
  type LeaseRevokeMessage,
  loadSodium,
  peerIdentity,
  type PushRegisterMessage,
  shapeEcdh,
  type Sodium,
  toBase64,
} from "@/src/protocol";

import { computePartial, isSecureEnclaveAvailable } from "@/modules/sigil-se";
import { faceGate } from "@/src/lib/biometric";
import { LEASE_REPLY_TIMEOUT_MS } from "@/src/domain/leases";
import { store } from "@/src/state/store";
import { PhoneRelay } from "@/src/transport/phone-relay";
import { type LeaseControlReply, SigilSession } from "./session";
import { clearPairing, loadPairing, type StoredPairing } from "./keystore";

interface Live {
  session: SigilSession;
  transport: PhoneRelay;
}

/** A short, secret-free error string for a diagnostic log line. */
function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

let live: Live | null = null;

export function isArmed(): boolean {
  return live !== null;
}

/**
 * Arm the real relay session from the stored pairing. Idempotent. Returns whether
 * a session is now running (false when this phone is unpaired, so the caller uses
 * the local/demo path). Any failure fails closed to no session.
 */
export async function armLiveSession(): Promise<boolean> {
  if (live) return true;
  const pairing = await loadPairing();
  if (!pairing) return false;
  let sodium: Sodium;
  try {
    sodium = await loadSodium();
  } catch (e) {
    console.warn(`[session] arm failed: libsodium did not load: ${errText(e)}`);
    return false;
  }
  const transport = new PhoneRelay({
    base: pairing.relayBase,
    mailbox: pairing.mailbox,
    // Feed drain results into the store so the link dot reflects the last real
    // exchange with the relay (transport status only, never a party).
    onStatus: (connected) => store.noteTransport(connected),
  });
  const session = new SigilSession({
    sodium,
    phone: pairing.phone,
    daemonPub: pairing.daemonPub,
    pairingId: pairing.mailbox,
    transport,
    onLeaseReply: handleLeaseReply,
  });
  await session.start();
  live = { session, transport };
  // Reflect the real pairing into the store so the UI shows paired (not demo) and
  // stops routing into the pairing flow. This is the single point both boot-time
  // hydration and a just-completed ceremony pass through. Deliberately no machine
  // name here: the pairing pins keys, not hostnames, and the relay's address must
  // never stand in for the Mac (see `pairedMacName` for where the name comes from).
  store.reflectPairing({
    ownFingerprint: ownFingerprint(sodium, pairing),
    pairedAt: pairing.pairedAt,
  });
  // Drain once right away so the link dot reflects reality within a moment of
  // arming instead of waiting out the first backstop tick.
  void transport.wake();
  return true;
}

/** This phone's own public-key fingerprint words, for the pairing/device UI. */
function ownFingerprint(sodium: Sodium, pairing: StoredPairing): string {
  const pub = peerIdentity(sodium, pairing.phone);
  return fingerprintWords(sodium, pub, pub).join(" ");
}

/** Tear the live session down (app teardown). Keeps the stored pairing. */
export function disarmLiveSession(): void {
  live?.session.stop();
  live = null;
  clearLeaseTimers();
}

/**
 * Reset the pairing entirely: tear down the live session, erase the stored
 * identity from the keystore, and return the store to the unpaired empty state so
 * the app routes back into the pairing flow. Used by "Reset pairing".
 */
export async function unpair(): Promise<void> {
  disarmLiveSession();
  await clearPairing();
  store.clearPairingState();
}

export type PushRegisterOutcome = "sent" | "no-session" | "error";

/**
 * Hand this device's current APNs token to the daemon over the live session
 * (see {@link PushRegisterMessage}). Called once after arming and again on
 * every token rotation (`src/lib/push.ts`). Content-free: the daemon learns
 * only a token to wake this phone, nothing about pending requests. Fails
 * closed to a no-op when unarmed; the relay poll remains the backstop either
 * way, so a failed registration never blocks an approval.
 */
export async function sendPushRegister(token: string): Promise<PushRegisterOutcome> {
  if (!live) return "no-session";
  try {
    await live.session.sendToDaemon<PushRegisterMessage>({
      type: "pushRegister",
      token,
      platform: "apns",
    });
    return "sent";
  } catch (e) {
    console.warn(`[session] push token deposit failed: ${errText(e)}`);
    return "error";
  }
}

/**
 * Drain the relay right now, e.g. right after a notification tap, so the
 * approval sheet does not wait out the foreground backstop interval. A no-op
 * when unarmed.
 */
export async function nudgeTransport(): Promise<void> {
  await live?.transport.wake();
}

// ---- lease control ---------------------------------------------------------
//
// The phone half of PHONE LEASE CONTROL: ask the daemon what windows are open,
// and end one. Both are READ-PATH actions. Listing releases nothing, and revoking
// only ever narrows authority, so neither passes the biometric: the Face ID gate
// belongs to release (invariant #4), and putting it in front of the control that
// CLOSES a window would make containment heavier than consent, which is the same
// mistake as making deny heavier than approve.
//
// The reply timers live here rather than in the store, because this module is
// what asked the question. Their whole job is to decide the moment silence has to
// be reported as silence: a relay that drops the answer must leave the human
// looking at "this window may still be open", never at a closed row.

// The correlation ids this phone is currently waiting on. A reply that names an
// id we did not send is dropped: the daemon's contract says so, and it is what
// keeps a late answer to a previous screen-open from repainting a newer list.
let pendingListQueryId: string | null = null;
let leaseListTimer: ReturnType<typeof setTimeout> | null = null;
const leaseRevokeTimers = new Map<string, ReturnType<typeof setTimeout>>();

function clearLeaseTimers(): void {
  if (leaseListTimer) clearTimeout(leaseListTimer);
  leaseListTimer = null;
  pendingListQueryId = null;
  for (const t of leaseRevokeTimers.values()) clearTimeout(t);
  leaseRevokeTimers.clear();
}

function newQueryId(): string {
  return crypto.randomUUID();
}

/** Route a verified answer to the store and stand its timer down. */
function handleLeaseReply(msg: LeaseControlReply): void {
  if (msg.kind === "leaseList") {
    // An unsolicited or superseded answer changes nothing on screen.
    if (msg.reply.queryId !== pendingListQueryId) return;
    pendingListQueryId = null;
    if (leaseListTimer) clearTimeout(leaseListTimer);
    leaseListTimer = null;
    store.leaseListReceived(msg.reply.leases, Date.now());
    return;
  }
  const { queryId } = msg.reply;
  const t = leaseRevokeTimers.get(queryId);
  if (!t) return; // not a revoke this phone is waiting on
  clearTimeout(t);
  leaseRevokeTimers.delete(queryId);
  store.leaseRevokeConfirmed(queryId, msg.reply.revoked, Date.now());
  // The daemon's own guidance: a revoke is idempotent, so re-list rather than
  // treat one verdict as the new state of the world.
  void refreshLeases();
}

/**
 * Ask the daemon for its live lease windows. Unarmed or a failed send both land
 * in "cannot check right now": the phone records that it could not ask, and never
 * that there is nothing to see. Resolves once the question has left the device;
 * the answer arrives later through {@link handleLeaseReply}.
 */
export async function refreshLeases(): Promise<void> {
  if (!live) {
    store.leaseQueryFailed();
    return;
  }
  const queryId = newQueryId();
  store.leaseQueryStarted();
  try {
    await live.session.sendToDaemon<LeaseListMessage>({ type: "leaseList", queryId });
  } catch (e) {
    console.warn(`[lease] list request failed: ${errText(e)}`);
    store.leaseQueryFailed();
    return;
  }
  pendingListQueryId = queryId;
  // Hurry the answer down the ladder rather than waiting out the poll backstop.
  void live.transport.wake();
  if (leaseListTimer) clearTimeout(leaseListTimer);
  leaseListTimer = setTimeout(() => {
    leaseListTimer = null;
    // Only report silence if this is still the question we are waiting on.
    if (pendingListQueryId !== queryId) return;
    pendingListQueryId = null;
    store.leaseQueryFailed();
  }, LEASE_REPLY_TIMEOUT_MS);
}

/**
 * Revoke ONE live window, named by both identifiers the daemon sent for it. The
 * `instance` is what binds the revoke to the window the human actually read: a
 * grant key is stable across windows, so naming it alone could land on a window
 * granted after they looked.
 *
 * The row is NOT cleared here. It is marked in flight and stays put until the
 * daemon confirms, or until the reply window lapses and it is marked unconfirmed.
 * Optimistically clearing it would let a hostile or broken relay buy the claim
 * that a window closed simply by dropping one message, and the brief cites this
 * list as the containment for a rule-wide window.
 */
export async function revokeLease(grantHex: string, instance: string): Promise<void> {
  const queryId = newQueryId();
  const sentAt = Date.now();
  store.leaseRevokeStarted({ queryId, grantHex, instance, sentAt, unconfirmed: false });
  if (!live) {
    // Nothing left the device, so nothing can be assumed about the window.
    store.leaseRevokeUnconfirmed(queryId);
    return;
  }
  try {
    await live.session.sendToDaemon<LeaseRevokeMessage>({
      type: "leaseRevoke",
      queryId,
      grantHex,
      instance,
    });
  } catch (e) {
    console.warn(`[lease] revoke dispatch failed: ${errText(e)}`);
    store.leaseRevokeUnconfirmed(queryId);
    return;
  }
  void live.transport.wake();
  leaseRevokeTimers.set(
    queryId,
    setTimeout(() => {
      leaseRevokeTimers.delete(queryId);
      store.leaseRevokeUnconfirmed(queryId);
    }, LEASE_REPLY_TIMEOUT_MS),
  );
}

export type ApproveOutcome = "sent" | "refused" | "no-session" | "error";

/**
 * Options for an approve. `lease` is set only when the human chose "keep
 * approved for a window" on a leasable request (task #57); the daemon binds the
 * chosen `ttlMs` to the grant it already resolved. Absent => approve-once.
 */
export interface ApproveOptions {
  lease?: { ttlMs: number };
}

/**
 * Approve `request` over the live transport. Only if the biometric gate passes
 * does it seal an `ApprovalResponse` and dispatch it toward the daemon. Returns
 * "sent" once the decision has left this device, "refused" if the biometric did
 * not pass (nothing is sent), "no-session" when unarmed, "error" if the dispatch
 * itself threw.
 *
 * Two shapes, chosen by the request, never by a wire flag:
 *   - A request that opens a threshold-sealed secret carries a challenge, and the
 *     approve produces the phone's partial `Z_F` (see {@link liveApproveThreshold}).
 *   - A plain gate carries no challenge: nothing is sealed to open, so the approve
 *     carries no partial. The Face ID gate here IS the authorization (invariant
 *     #4); it releases no key material, only the decision.
 *
 * "sent" means exactly that the response left the phone. This function does not
 * learn, and must not infer, whether the Mac then unlocked or ran anything: the
 * phone is a zero-knowledge approver, so the outcome on the far side is not its
 * concern and is never reported back through this result.
 */
export async function liveApprove(
  request: ApprovalRequest,
  opts: ApproveOptions = {},
): Promise<ApproveOutcome> {
  if (!live) return "no-session";
  // A threshold challenge selects the secret-release path: the Secure Enclave
  // key-agreement (Z_F). Selected by the presence of the challenge, never by a
  // wire flag.
  if (request.threshold) return liveApproveThreshold(request, opts);

  // A plain gate: no secret to open, so no partial. Approving still REQUIRES the
  // biometric (invariant #4); it gates the decision itself, not any key release.
  const gate = await faceGate("Approve request");
  if (!gate.ok) return "refused";
  try {
    await live.session.respond(request, "approved", {
      ...(opts.lease ? { lease: opts.lease } : {}),
    });
    return "sent";
  } catch (e) {
    // The approve was sealed but the dispatch threw (transport/seal fault). The
    // error is a wire error, and this path carries no key material at all.
    console.warn(`[session] approve dispatch failed: ${errText(e)}`);
    return "error";
  }
}

/**
 * The threshold approve: derive the phone's partial `Z_F = x(f·E)` in the Secure
 * Enclave and seal it as a `ThresholdPartial`. The enclave key-agreement is
 * itself the Face ID gate, so there is no separate biometric and no unguarded
 * path. Fails closed to "refused" on a denied/failed biometric or an off-curve
 * `E`, and "error" if this device has no Secure Enclave (a v2 account cannot be
 * approved without it).
 *
 * The phone does not reason about what `threshold.accountId` is: it is an opaque
 * routing tag the crypto needs (which pinned key `f` to agree, echoed back for
 * correlation), never a provider/account concept the phone interprets or shows.
 */
async function liveApproveThreshold(
  request: ApprovalRequest,
  opts: ApproveOptions = {},
): Promise<ApproveOutcome> {
  if (!live) return "no-session";
  const ch = request.threshold;
  if (!ch) return "error";
  if (!isSecureEnclaveAvailable()) return "error";

  let zfB64: string;
  try {
    const sodium = await loadSodium();
    // The enclave key-agreement is the Face ID gate. It returns the RAW 32-byte
    // X-coordinate; the ECDH-output shaping (raw-x identity vs x963-sha256) is
    // applied here in the vector-locked TS combiner core, byte-exact with the
    // Mac's threshold.rs, so the phone never depends on CryptoKit's KDF
    // parameters (NV-7).
    const rawXB64 = await computePartial(ch.seKeyId, ch.ephemeralPub, "Approve request");
    const zf = shapeEcdh(sodium, fromBase64(rawXB64), ch.ecdhAlgo, fromBase64(ch.ephemeralPub));
    zfB64 = toBase64(zf);
  } catch {
    // Denied/failed Face ID, an off-curve E (R2), or a missing key: no partial.
    return "refused";
  }
  try {
    await live.session.respond(request, "approved", {
      partial: { accountId: ch.accountId, zf: zfB64 },
      ...(opts.lease ? { lease: opts.lease } : {}),
    });
    return "sent";
  } catch (e) {
    console.warn(`[session] threshold approve dispatch failed: ${errText(e)}`);
    return "error";
  }
}

export type DenyOutcome = "sent" | "no-session" | "error";

/**
 * Deny `request` over the live transport. Carries no partial, so a denial can
 * never release a secret, and needs no biometric (deny is always frictionless).
 */
export async function liveDeny(request: ApprovalRequest): Promise<DenyOutcome> {
  if (!live) return "no-session";
  try {
    await live.session.respond(request, "denied");
    return "sent";
  } catch (e) {
    console.warn(`[session] deny dispatch failed: ${errText(e)}`);
    return "error";
  }
}
