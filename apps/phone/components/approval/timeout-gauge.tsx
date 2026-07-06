/**
 * The brass timeout gauge: a real clock depleting to expiry. The arc is animated
 * off the JS render loop with Reanimated (a single withTiming to zero over the
 * remaining lifetime, linear), so a slow frame never desyncs it. The numeric
 * center re-renders about four times a second from the wall clock.
 *
 * Reduced motion collapses the whole gauge to a numeric countdown, per the brief.
 */
import { useEffect } from "react";
import { View } from "react-native";
import Animated, {
  Easing,
  useAnimatedProps,
  useSharedValue,
  withTiming,
} from "react-native-reanimated";
import Svg, { Circle } from "react-native-svg";

import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { clock } from "@/src/lib/format";
import { useCountdown } from "@/src/lib/use-countdown";

const AnimatedCircle = Animated.createAnimatedComponent(Circle);

const SIZE = 52;
const STROKE = 3.5;
const R = (SIZE - STROKE) / 2 - 1;
const C = 2 * Math.PI * R;

export function TimeoutGauge({
  expiresAt,
  timeoutMs,
  reduceMotion,
  frozen,
}: {
  expiresAt: number;
  timeoutMs: number;
  reduceMotion: boolean;
  /** When approved/denied/expired, stop the clock and hold the readout. */
  frozen?: boolean;
}) {
  const p = useTheme();
  const { remainingMs, fraction, phase } = useCountdown(expiresAt, timeoutMs);
  const color = phase === "expired" ? p.faint : p.brass;

  const progress = useSharedValue(fraction);

  useEffect(() => {
    if (frozen) return;
    progress.value = fraction;
    const remaining = Math.max(0, expiresAt - Date.now());
    progress.value = withTiming(0, { duration: remaining, easing: Easing.linear });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expiresAt, frozen]);

  const arcProps = useAnimatedProps(() => ({
    strokeDashoffset: C * (1 - progress.value),
  }));

  const readout = phase === "expired" ? "0:00" : clock(remainingMs);

  if (reduceMotion) {
    return (
      <View
        style={{
          minWidth: SIZE,
          height: SIZE,
          borderRadius: 12,
          borderCurve: "continuous",
          paddingHorizontal: 10,
          justifyContent: "center",
          alignItems: "center",
          borderWidth: 1,
          borderColor: color,
        }}
      >
        <Mono size={15} weight="semibold" style={{ color }}>
          {readout}
        </Mono>
      </View>
    );
  }

  return (
    <View style={{ width: SIZE, height: SIZE, justifyContent: "center", alignItems: "center" }}>
      <Svg width={SIZE} height={SIZE} style={{ transform: [{ rotate: "-90deg" }] }}>
        <Circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={R}
          fill="none"
          stroke={p.line}
          strokeWidth={STROKE}
        />
        <AnimatedCircle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={R}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={C}
          animatedProps={arcProps}
        />
      </Svg>
      <View style={{ position: "absolute", inset: 0, justifyContent: "center", alignItems: "center" }}>
        <Mono size={12} weight="medium" style={{ color }}>
          {readout}
        </Mono>
      </View>
    </View>
  );
}
