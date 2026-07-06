import { useRouter } from "expo-router";
import { View } from "react-native";
import { Gesture, GestureDetector } from "react-native-gesture-handler";
import Animated, {
  Easing,
  runOnJS,
  useAnimatedStyle,
  useSharedValue,
  withTiming,
} from "react-native-reanimated";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { hapticSeal } from "@/src/lib/haptics";
import { store, useSelector } from "@/src/state/store";

const SEAL_MS = 400;

/**
 * Lockdown: hold to seal. Sealing denies everything pending and refuses
 * everything new until Face ID plus a hold releases it. One weightier 400ms
 * movement from cobalt to rust, per the brief's motion budget.
 */
export default function LockdownRoute() {
  const p = useTheme();
  const router = useRouter();
  const locked = useSelector((s) => s.arm === "lockedDown");

  async function seal(): Promise<void> {
    await hapticSeal();
    store.lockdown();
    router.back();
  }

  async function release(): Promise<void> {
    const gate = await faceGate("Release lockdown");
    if (!gate.ok) return;
    await hapticSeal();
    store.clearLockdown();
    router.back();
  }

  return (
    <View style={{ flex: 1, padding: space.xl, gap: space.xl, justifyContent: "center" }}>
      <View style={{ alignItems: "center", gap: space.md }}>
        <Sf name={locked ? "lock.fill" : "lock.open"} color={locked ? p.deny : p.cobalt} size={44} />
        <Sans size={20} weight="semibold" style={{ textAlign: "center" }}>
          {locked ? "Locked down" : "Lock down"}
        </Sans>
        <Sans size={15} tone="muted" style={{ textAlign: "center", maxWidth: 300 }}>
          {locked
            ? "No requests will be served. Everything pending was denied."
            : "Deny everything pending and refuse everything new until you release it."}
        </Sans>
      </View>

      <HoldToSeal locked={locked} onSeal={seal} onRelease={release} />
    </View>
  );
}

function HoldToSeal({
  locked,
  onSeal,
  onRelease,
}: {
  locked: boolean;
  onSeal: () => void;
  onRelease: () => void;
}) {
  const p = useTheme();
  const fill = useSharedValue(0);

  const gesture = Gesture.LongPress()
    .minDuration(SEAL_MS)
    .maxDistance(9999)
    .onBegin(() => {
      fill.value = withTiming(1, { duration: SEAL_MS, easing: Easing.out(Easing.quad) });
    })
    .onStart(() => {
      runOnJS(locked ? onRelease : onSeal)();
    })
    .onFinalize((_e, success) => {
      if (!success) fill.value = withTiming(0, { duration: 200 });
    });

  const fillStyle = useAnimatedStyle(() => ({ opacity: fill.value }));
  const base = locked ? p.deny : p.cobalt;
  const target = locked ? p.cobalt : p.deny;

  return (
    <GestureDetector gesture={gesture}>
      <View
        style={{
          height: 60,
          borderRadius: radius.capsule,
          backgroundColor: base,
          alignItems: "center",
          justifyContent: "center",
          overflow: "hidden",
        }}
      >
        <Animated.View
          style={[
            { position: "absolute", left: 0, right: 0, top: 0, bottom: 0, backgroundColor: target },
            fillStyle,
          ]}
        />
        <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
          {locked ? "Hold to release" : "Hold to seal"}
        </Sans>
      </View>
    </GestureDetector>
  );
}
