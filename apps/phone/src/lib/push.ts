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
 * Push is the primary wake; the relay's 30s backstop poll (`phone-relay.ts`)
 * covers permission-denied, delayed, and pre-registration windows, so every
 * failure path here fails closed to "poll keeps working" rather than crashing.
 */
import { Platform } from "react-native";
import * as Notifications from "expo-notifications";

import { armLiveSession, nudgeTransport, sendPushRegister } from "@/src/session/controller";

/**
 * Ask for (or reuse) notification permission and hand the native APNs token
 * to the daemon over the live session. Restricted to iOS: the locked wire
 * contract fixes `platform` to `"apns"`, so there is nothing correct to send
 * from a platform that does not carry an APNs token. Any failure - permission
 * refused, no hardware token, unarmed session - fails closed to a no-op; the
 * relay poll remains the transport.
 */
export async function registerPushToken(): Promise<void> {
  if (Platform.OS !== "ios") return;
  try {
    let perms = await Notifications.getPermissionsAsync();
    if (perms.status !== "granted") {
      perms = await Notifications.requestPermissionsAsync();
    }
    if (perms.status !== "granted") return;
    const token = await Notifications.getDevicePushTokenAsync();
    await sendPushRegister(token.data);
  } catch {
    // Permission denial, no token, or no daemon reachable: poll-only mode
    // remains the floor. Never let a doorbell failure crash the app.
  }
}

/**
 * Subscribe to APNs token rotations (reinstall, restore, OS-issued rotation)
 * and re-register each new token with the daemon. Returns an unsubscribe.
 */
export function watchPushTokenRotation(): () => void {
  if (Platform.OS !== "ios") return () => {};
  const sub = Notifications.addPushTokenListener((token) => {
    void sendPushRegister(token.data);
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
