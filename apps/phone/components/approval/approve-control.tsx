/**
 * The one bespoke control in the product: the approve capsule. Risk scales the
 * approve gesture and nothing else.
 *   routine  -> tap
 *   elevated -> slide to approve
 *   critical -> hold 1.5s, ring fills
 * Native haptics fire when a gesture crosses its arming threshold; the Face ID
 * gate runs in the parent before the decision registers, so `onApprove` here
 * only signals intent. `busy` freezes the control while the gate is up; if the
 * gate fails the parent flips `busy` off and the control resets itself.
 */
import { useEffect } from "react";
import { LayoutChangeEvent, Pressable, StyleSheet, View } from "react-native";
import { Gesture, GestureDetector } from "react-native-gesture-handler";
import Animated, {
  Easing,
  runOnJS,
  useAnimatedStyle,
  useSharedValue,
  withSpring,
  withTiming,
} from "react-native-reanimated";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { GlassSurface } from "@/components/ui/glass";
import { useTheme } from "@/theme/colors";
import { radius } from "@/theme/tokens";
import { hapticThreshold, hapticTick } from "@/src/lib/haptics";
import { type RiskLevel } from "@/src/protocol";

const H = 56;
const KNOB = 46;
const PAD = 5;
const HOLD_MS = 1500;

interface Props {
  risk: RiskLevel;
  busy: boolean;
  onApprove: () => void;
}

export function ApproveControl({ risk, busy, onApprove }: Props) {
  if (risk === "routine") return <TapApprove busy={busy} onApprove={onApprove} />;
  if (risk === "elevated") return <SlideApprove busy={busy} onApprove={onApprove} />;
  return <HoldApprove busy={busy} onApprove={onApprove} />;
}

function TapApprove({ busy, onApprove }: { busy: boolean; onApprove: () => void }) {
  const p = useTheme();
  return (
    <Pressable
      disabled={busy}
      onPress={() => {
        void hapticTick();
        onApprove();
      }}
      style={{
        height: H,
        borderRadius: radius.capsule,
        overflow: "hidden",
        alignItems: "center",
        justifyContent: "center",
        opacity: busy ? 0.6 : 1,
      }}
    >
      {/* iOS 26 Liquid Glass, tinted cobalt; falls back to a solid cobalt capsule. */}
      <GlassSurface
        style={StyleSheet.absoluteFill}
        fallbackColor={p.cobalt}
        tintColor={p.cobalt}
        isInteractive
      />
      <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
        {busy ? "Approving…" : "Approve"}
      </Sans>
    </Pressable>
  );
}

function SlideApprove({ busy, onApprove }: { busy: boolean; onApprove: () => void }) {
  const p = useTheme();
  const x = useSharedValue(0);
  const width = useSharedValue(0);
  const armed = useSharedValue(false);

  useEffect(() => {
    if (!busy) x.value = withSpring(0, { damping: 18, stiffness: 180 });
  }, [busy, x]);

  const maxX = () => width.value - KNOB - PAD * 2;

  const pan = Gesture.Pan()
    .enabled(!busy)
    .onUpdate((e) => {
      const m = maxX();
      x.value = Math.max(0, Math.min(m, e.translationX));
      const past = x.value >= m * 0.85;
      if (past && !armed.value) {
        armed.value = true;
        runOnJS(hapticThreshold)();
      } else if (!past && armed.value) {
        armed.value = false;
      }
    })
    .onEnd(() => {
      const m = maxX();
      if (x.value >= m * 0.85) {
        x.value = withTiming(m, { duration: 120 });
        runOnJS(onApprove)();
      } else {
        x.value = withSpring(0, { damping: 18, stiffness: 180 });
      }
      armed.value = false;
    });

  const knobStyle = useAnimatedStyle(() => ({ transform: [{ translateX: x.value }] }));
  const labelStyle = useAnimatedStyle(() => ({
    opacity: width.value > 0 ? 1 - x.value / Math.max(1, maxX()) : 1,
  }));

  return (
    <View
      onLayout={(e: LayoutChangeEvent) => {
        width.value = e.nativeEvent.layout.width;
      }}
      style={{
        height: H,
        borderRadius: radius.capsule,
        backgroundColor: p.cobalt,
        justifyContent: "center",
        paddingHorizontal: PAD,
        overflow: "hidden",
        opacity: busy ? 0.6 : 1,
      }}
    >
      <Animated.View style={[{ position: "absolute", width: "100%", alignItems: "center" }, labelStyle]}>
        <Sans size={16} weight="medium" style={{ color: p.cobaltInk }}>
          {busy ? "Approving…" : "Slide to approve"}
        </Sans>
      </Animated.View>
      <GestureDetector gesture={pan}>
        <Animated.View
          style={[
            {
              width: KNOB,
              height: KNOB,
              borderRadius: KNOB / 2,
              backgroundColor: p.cobaltInk,
              alignItems: "center",
              justifyContent: "center",
            },
            knobStyle,
          ]}
        >
          <Sf name="chevron.right" color={p.cobalt} size={20} weight="bold" />
        </Animated.View>
      </GestureDetector>
    </View>
  );
}

function HoldApprove({ busy, onApprove }: { busy: boolean; onApprove: () => void }) {
  const p = useTheme();
  const fill = useSharedValue(0);

  useEffect(() => {
    if (!busy) fill.value = withTiming(0, { duration: 180 });
  }, [busy, fill]);

  const hold = Gesture.LongPress()
    .enabled(!busy)
    .minDuration(HOLD_MS)
    .maxDistance(9999)
    .onBegin(() => {
      fill.value = withTiming(1, { duration: HOLD_MS, easing: Easing.linear });
      runOnJS(hapticTick)();
    })
    .onStart(() => {
      runOnJS(hapticThreshold)();
      runOnJS(onApprove)();
    })
    .onFinalize((_e, success) => {
      if (!success) fill.value = withTiming(0, { duration: 220 });
    });

  const fillStyle = useAnimatedStyle(() => ({ width: `${fill.value * 100}%` }));

  return (
    <GestureDetector gesture={hold}>
      <View
        style={{
          height: H,
          borderRadius: radius.capsule,
          borderWidth: 1.5,
          borderColor: p.cobalt,
          alignItems: "center",
          justifyContent: "center",
          overflow: "hidden",
          opacity: busy ? 0.6 : 1,
        }}
      >
        <Animated.View
          style={[
            { position: "absolute", left: 0, top: 0, bottom: 0, backgroundColor: p.cobalt },
            fillStyle,
          ]}
        />
        <Sans size={17} weight="semibold" style={{ color: p.cobalt }}>
          {busy ? "Approving…" : "Hold to approve"}
        </Sans>
      </View>
    </GestureDetector>
  );
}
