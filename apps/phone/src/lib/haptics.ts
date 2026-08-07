/**
 * Haptics for the moments that matter: a decision committing and a control
 * engaging. iOS only; a no-op elsewhere.
 */
import * as Haptics from "expo-haptics";

const onIos = process.env.EXPO_OS === "ios";

/** A decision (approve/deny) has committed. */
export async function hapticCommit(kind: "approved" | "denied"): Promise<void> {
  if (!onIos) return;
  await Haptics.notificationAsync(
    kind === "approved"
      ? Haptics.NotificationFeedbackType.Success
      : Haptics.NotificationFeedbackType.Warning,
  );
}

/** A light tick as a control engages. */
export async function hapticTick(): Promise<void> {
  if (!onIos) return;
  await Haptics.selectionAsync();
}
