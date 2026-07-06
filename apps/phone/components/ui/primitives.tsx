/**
 * Small shared layout primitives: hairline separators, grouped cards, section
 * headers, and a state pill. Native materials over custom skin.
 */
import { type ReactNode } from "react";
import { type StyleProp, View, type ViewStyle } from "react-native";

import { stateColor, type DecisionState, useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { Mono, Sans } from "./text";

export function Hairline({ inset = 0 }: { inset?: number }) {
  const p = useTheme();
  return (
    <View
      style={{ height: 1, backgroundColor: p.line, marginLeft: inset }}
    />
  );
}

export function Card({
  children,
  style,
}: {
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  const p = useTheme();
  return (
    <View
      style={[
        {
          backgroundColor: p.surface,
          borderRadius: radius.card,
          borderCurve: "continuous",
          overflow: "hidden",
        },
        style,
      ]}
    >
      {children}
    </View>
  );
}

export function SectionHeader({ children }: { children: ReactNode }) {
  return (
    <Sans
      size={12}
      weight="semibold"
      tone="muted"
      style={{
        textTransform: "uppercase",
        letterSpacing: 0.6,
        marginBottom: space.sm,
        marginLeft: space.xs,
      }}
    >
      {children}
    </Sans>
  );
}

export function StatePill({ state, label }: { state: DecisionState; label: string }) {
  const p = useTheme();
  const color = stateColor(p, state);
  return (
    <View
      style={{
        flexDirection: "row",
        alignItems: "center",
        gap: 6,
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: radius.capsule,
        backgroundColor: color + "22",
      }}
    >
      <View style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: color }} />
      <Mono size={12} weight="medium" style={{ color }}>
        {label}
      </Mono>
    </View>
  );
}
