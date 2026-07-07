/**
 * The APNs push doorbell glue: registers this device's native token with the
 * daemon, keeps the daemon's copy current across token rotations, and reacts
 * to a tapped notification by arming the session and forcing an immediate
 * relay drain so the approval sheet can present.
 *
 * Content-free by design: this module never reads a notification's content
 * and never acts on a notification action. A tap only wakes the transport; it
 * cannot approve anything by itself (approving always needs the Face ID gate
 * in `src/session/controller.ts`).
 *
 * Push is the primary wake; the relay's foreground backstop poll
 * (`phone-relay.ts`) covers permission-denied, delayed, and pre-registration
 * windows, so every failure path here fails closed to "poll keeps working"
 * rather than crashing.
 *
 * VISIBILITY (task #44): registration used to swallow every failure in empty
 * `catch {}` blocks, so a token that never reached the daemon was completely
 * invisible. Every step now logs under the stable `[push]` prefix (visible in
 * Metro and in Console.app / Xcode device logs for a TestFlight build) and
 * updates a small {@link PushDiag} the Settings screen surfaces. The raw token
 * value is NEVER logged or shown; only its length.
 */
import { useSyncExternalStore } from "react";
import { AppState, Platform } from "react-native";
import * as Notifications from "expo-notifications";

import { armLiveSession, isArmed, nudgeTransport, sendPushRegister } from "@/src/session/controller";

const TAG = "[push]";

/** Bounded deposit backoff: three attempts, so an arming or transient-relay */
/** race resolves without turning into a spam loop. */
const DEPOSIT_BACKOFF_MS = [0, 1_000, 2_500];

export type PushPhase =
  | "idle"
  | "permission"
  | "fetching"
  | "depositing"
  | "registered"
  | "blocked"
  | "failed";

/**
 * A provider-blind, secret-free snapshot of where doorbell registration stands,
 * for a status line the user can actually see. Never contains a token.
 */
export interface PushDiag {
  phase: PushPhase;
  /** A short status line. No em-dash, no emoji, no secrets. */
  message: string;
  at: number;
}

let diag: PushDiag = { phase: "idle", message: "", at: Date.now() };
const diagListeners = new Set<() => void>();

function setDiag(phase: PushPhase, message: string): void {
  diag = { phase, message, at: Date.now() };
  for (const l of diagListeners) l();
}

function getPushDiag(): PushDiag {
  return diag;
}

function subscribePushDiag(listener: () => void): () => void {
  diagListeners.add(listener);
  return () => diagListeners.delete(listener);
}

/** Reactive doorbell status for a dev/status surface (Settings). */
export function usePushDiag(): PushDiag {
  return useSyncExternalStore(subscribePushDiag, getPushDiag, getPushDiag);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Deposit the token with the daemon, retrying within a small bound. A
 * "no-session" outcome means the live session is still arming, an "error" means
 * a transient seal/relay fault; both are worth a couple more tries. Returns
 * whether the daemon acknowledged the send.
 */
async function depositWithRetry(token: string): Promise<boolean> {
  for (let i = 0; i < DEPOSIT_BACKOFF_MS.length; i++) {
    const wait = DEPOSIT_BACKOFF_MS[i] ?? 0;
    if (wait > 0) await delay(wait);
    const outcome = await sendPushRegister(token);
    console.log(`${TAG} deposit attempt ${i + 1}/${DEPOSIT_BACKOFF_MS.length}: ${outcome}`);
    if (outcome === "sent") return true;
  }
  return false;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Collapses concurrent invocations (arm + foreground + tap can all fire at
// once) onto one in-flight registration so we never double-request permission
// or race two deposits.
let registering = false;

/**
 * Request (or reuse) notification permission, register with APNs, fetch this
 * device's native token, and deposit it with the daemon over the live session.
 * Restricted to iOS: the locked wire contract fixes `platform` to `"apns"`.
 * Every failure fails closed to poll-only mode and is now LOGGED and reflected
 * in {@link PushDiag}, never swallowed.
 */
export async function registerPushToken(): Promise<void> {
  if (Platform.OS !== "ios") return;
  if (registering) return;
  registering = true;
  try {
    // 1. Permission. getDevicePushTokenAsync throws on iOS if the app has not
    //    registered for remote notifications; requesting permission here also
    //    drives that registration. Without a granted permission we stay on the
    //    relay poll.
    setDiag("permission", "Checking notification permission.");
    let perms = await Notifications.getPermissionsAsync();
    console.log(`${TAG} permission status: ${perms.status}`);
    if (perms.status !== "granted") {
      perms = await Notifications.requestPermissionsAsync();
      console.log(`${TAG} permission after request: ${perms.status}`);
    }
    if (perms.status !== "granted") {
      console.warn(`${TAG} notifications not permitted; relay poll remains the transport`);
      setDiag("blocked", "Notifications are off. Approvals still arrive by relay poll.");
      return;
    }

    // 2. Fetch the native APNs token. This is the step that throws with
    //    "no valid aps-environment entitlement string found" when the build is
    //    missing the aps-environment entitlement (see app.json) - previously
    //    swallowed, now surfaced.
    setDiag("fetching", "Registering the doorbell.");
    console.log(`${TAG} fetching APNs device token`);
    let token: string;
    try {
      const t = await Notifications.getDevicePushTokenAsync();
      token = t.data;
      console.log(`${TAG} token fetched, length ${token.length}`);
    } catch (e) {
      console.error(`${TAG} token fetch failed: ${errMsg(e)}`);
      setDiag("failed", "Could not register for push. Approvals still arrive by relay poll.");
      return;
    }

    // 3. Deposit with the daemon over the live session, bounded-retry.
    setDiag("depositing", "Handing the doorbell token to your Mac.");
    console.log(`${TAG} depositing token with daemon`);
    const ok = await depositWithRetry(token);
    if (ok) {
      console.log(`${TAG} token registered with daemon`);
      setDiag("registered", "Doorbell registered.");
    } else {
      console.warn(`${TAG} deposit failed after retries; relay poll remains the transport`);
      setDiag("failed", "Doorbell not confirmed yet. Approvals still arrive by relay poll.");
    }
  } catch (e) {
    // A defensive net around the whole flow: never let a doorbell failure crash
    // the app, but always leave a trace.
    console.error(`${TAG} registration failed unexpectedly: ${errMsg(e)}`);
    setDiag("failed", "Doorbell registration failed. Approvals still arrive by relay poll.");
  } finally {
    registering = false;
  }
}

/**
 * Subscribe to APNs token rotations (reinstall, restore, OS-issued rotation)
 * and re-register each new token with the daemon. Returns an unsubscribe.
 */
export function watchPushTokenRotation(): () => void {
  if (Platform.OS !== "ios") return () => {};
  const sub = Notifications.addPushTokenListener((token) => {
    console.log(`${TAG} token rotated, length ${token.data.length}`);
    void depositWithRetry(token.data).then((ok) => {
      if (ok) {
        setDiag("registered", "Doorbell registered.");
      } else {
        console.warn(`${TAG} rotated-token deposit failed after retries`);
        setDiag("failed", "Doorbell not confirmed yet. Approvals still arrive by relay poll.");
      }
    });
  });
  return () => sub.remove();
}

/**
 * Re-attempt registration when the app returns to the foreground while armed
 * and not yet registered. Covers the case where the first attempt raced ahead
 * of arming, or permission was granted in Settings after a refusal. Idempotent
 * (registerPushToken collapses concurrent calls) and a no-op once registered.
 */
export function watchPushForeground(): () => void {
  if (Platform.OS !== "ios") return () => {};
  const sub = AppState.addEventListener("change", (state) => {
    if (state === "active" && isArmed() && diag.phase !== "registered") {
      void registerPushToken();
    }
  });
  return () => sub.remove();
}

/** Arm (idempotent) and force a drain, so a tap never waits out the backstop. */
async function wakeFromTap(): Promise<void> {
  await armLiveSession();
  await nudgeTransport();
}

/**
 * Wire up notification-tap handling: a live listener for a tap while the app
 * is running (foreground or background), plus the cold-start launch response
 * for a tap that started the app. Returns an unsubscribe for the live
 * listener; the cold-start check runs once and needs no teardown.
 */
export function watchNotificationTaps(): () => void {
  const sub = Notifications.addNotificationResponseReceivedListener(() => {
    void wakeFromTap();
  });
  void Notifications.getLastNotificationResponseAsync().then((response) => {
    if (response) void wakeFromTap();
  });
  return () => sub.remove();
}
