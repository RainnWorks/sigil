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
import { type OutstandingKind, OutstandingRequests } from "./outstanding";
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
// and end one.
//
// The two halves are gated differently, and the asymmetry is the point.
// LISTING passes a local biometric (design review F5). It releases nothing, but
// it changes what a stolen or coerced phone can produce on demand: a complete
// schedule of which auto-approve windows are live, on which rules, and how many
// seconds each has left, which is a map of what will release with no human tap.
// REVOKING is completely ungated, because a revoke is a deny, it can only ever
// narrow what the Mac will serve, and a deny is never made heavier than an
// approve.
//
// CORRELATION IS THE SECURITY PROPERTY HERE, not bookkeeping (design review F3).
// The envelope layer no longer gates on the counter; its replay protection is a
// freshness window plus a single-use id set held in RAM on both ends, and that
// set is empty again after any restart. A phone being killed or backgrounded is
// routine. So a relay can capture a genuine LeaseRevokeReply{revoked:true}, wait
// out a restart, suppress the human's next outgoing revoke, and deliver the
// captured reply into a fresh guard: unseen id, valid signature, inside the
// freshness window, because the message really is genuine. Without the map
// below, the phone would tell the human a window closed while it is open, which
// is strictly worse than the "revoke on your Mac" badge this feature replaced.
//
// So: every outbound question is recorded here under the envelope request id it
// was sent with, a reply is applied ONLY if it names an outstanding one, and the
// entry is CONSUMED on the match. The map dies with the process, which is exactly
// what makes a captured reply replayed into a fresh session match nothing.

// The questions this session has asked and not yet had answered. See
// OutstandingRequests for why this is the security mechanism rather than
// bookkeeping. Timers ride alongside, keyed by the same id.
const outstanding = new OutstandingRequests();
const leaseTimers = new Map<string, ReturnType<typeof setTimeout>>();

function armLeaseTimer(requestId: string, onLapse: () => void): void {
  leaseTimers.set(
    requestId,
    setTimeout(() => {
      leaseTimers.delete(requestId);
      outstanding.abandon(requestId);
      onLapse();
    }, LEASE_REPLY_TIMEOUT_MS),
  );
}

function clearLeaseTimers(): void {
  for (const t of leaseTimers.values()) clearTimeout(t);
  leaseTimers.clear();
  outstanding.clear();
}

/**
 * Claim an outstanding request, standing its timer down. False is the drop path,
 * and it is silent: an uncorrelated reply is not evidence about anything, so it
 * must not move the UI in either direction.
 */
function claim(inReplyTo: string, kind: OutstandingKind): boolean {
  if (!outstanding.claim(inReplyTo, kind)) return false;
  const t = leaseTimers.get(inReplyTo);
  if (t) clearTimeout(t);
  leaseTimers.delete(inReplyTo);
  return true;
}

/** Route a correlated answer to the store. Anything uncorrelated is dropped. */
function handleLeaseReply(msg: LeaseControlReply): void {
  if (msg.kind === "leaseList") {
    if (!claim(msg.reply.inReplyTo, "list")) return;
    store.leaseListReceived(msg.reply.leases, msg.reply.asOf, Date.now());
    return;
  }
  if (!claim(msg.reply.inReplyTo, "revoke")) return;
  store.leaseRevokeConfirmed(msg.reply.inReplyTo, msg.reply.revoked, Date.now());
}

export type LeaseQueryOutcome = "asked" | "refused" | "no-biometric" | "cannot-ask";

/**
 * Ask the daemon for a snapshot of its live windows, behind the biometric.
 *
 * A declined biometric returns "refused" and changes nothing: no question was
 * asked, so nothing new is unknown, and the screen must not raise "cannot check
 * right now" over it. Unarmed or a failed send land in "cannot ask": the phone
 * records that it could not ask, never that there is nothing to see. Resolves
 * once the question has left the device; the answer arrives later through
 * {@link handleLeaseReply}.
 */
export async function refreshLeases(): Promise<LeaseQueryOutcome> {
  if (!live) {
    store.leaseQueryFailed();
    return "cannot-ask";
  }
  // The gate goes BEFORE the send, so a declined check leaks nothing: no
  // question reaches the daemon and no answer is ever in flight.
  const gate = await faceGate("Show active leases");
  if (!gate.ok) {
    // No biometric enrolled is a different fact from a declined one, and the
    // screen says so rather than looking broken: this device cannot show the
    // list at all, and the Mac is where to look instead. Fail closed either way.
    store.leaseQueryCancelled(gate.reason === "unavailable");
    return gate.reason === "unavailable" ? "no-biometric" : "refused";
  }
  store.leaseQueryStarted();
  let requestId: string;
  try {
    requestId = await live.session.sendToDaemon<LeaseListMessage>({ type: "leaseList" });
  } catch (e) {
    console.warn(`[lease] list request failed: ${errText(e)}`);
    store.leaseQueryFailed();
    return "cannot-ask";
  }
  outstanding.issue(requestId, "list");
  armLeaseTimer(requestId, () => store.leaseQueryFailed());
  // Hurry the answer down the ladder rather than waiting out the poll backstop.
  void live.transport.wake();
  return "asked";
}

/**
 * Revoke ONE live window by the opaque id the daemon sent for it. No biometric
 * and no confirmation: revoking is a deny, and a deny is never made heavier than
 * an approve.
 *
 * The row is NOT cleared here. It is marked in flight and stays put until a
 * CORRELATED reply arrives, or until the reply window lapses and it becomes a
 * standing warning that outlives the snapshot. Optimistically clearing it would
 * let a relay buy the claim that a window closed simply by dropping one message,
 * and the brief cites this list as the containment for a rule-wide window.
 *
 * `scope` is carried only so a standing warning can name what it is about after
 * the snapshot behind it has been thrown away.
 */
export async function revokeLease(leaseId: string, scope: string | null): Promise<void> {
  const sentAt = Date.now();
  // A revoke that never left the device still needs an id to key its warning by,
  // and it must be one no reply can ever name: the prefix keeps it out of the
  // uuid shape `inReplyTo` is validated against, so nothing can confirm it.
  const unsent = `unsent:${crypto.randomUUID()}`;
  if (!live) {
    // Nothing left the device, so nothing can be assumed about the window. It is
    // recorded as an unconfirmed revoke, not as a failure to send, because from
    // the human's side those have the same consequence: unknown, so assume open.
    store.leaseRevokeStarted({ requestId: unsent, leaseId, scope, sentAt, unconfirmed: true });
    return;
  }
  let requestId: string;
  try {
    requestId = await live.session.sendToDaemon<LeaseRevokeMessage>({
      type: "leaseRevoke",
      leaseId,
    });
  } catch (e) {
    console.warn(`[lease] revoke dispatch failed: ${errText(e)}`);
    store.leaseRevokeStarted({ requestId: unsent, leaseId, scope, sentAt, unconfirmed: true });
    return;
  }
  store.leaseRevokeStarted({ requestId, leaseId, scope, sentAt, unconfirmed: false });
  outstanding.issue(requestId, "revoke");
  armLeaseTimer(requestId, () => store.leaseRevokeUnconfirmed(requestId));
  void live.transport.wake();
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
