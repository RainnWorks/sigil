/**
 * Text primitives for the two voices: SF Pro (UI voice, honors Dynamic Type) and
 * SF Mono (content voice: paths, fingerprints, process chains, timestamps, all
 * tabular). Everything technical is Mono; everything spoken is Sans.
 */
import { Text, type TextProps } from "react-native";

import { useTheme } from "@/theme/colors";

type Tone = "label" | "muted" | "faint" | "cobalt" | "brass" | "ok" | "deny";

interface BaseProps extends TextProps {
  size?: number;
  weight?: "regular" | "medium" | "semibold" | "bold";
  tone?: Tone;
}

const weightMap = {
  regular: "400",
  medium: "500",
  semibold: "600",
  bold: "700",
} as const;

function useToneColor(tone: Tone): string {
  const p = useTheme();
  switch (tone) {
    case "label":
      return p.label;
    case "muted":
      return p.muted;
    case "faint":
      return p.faint;
    case "cobalt":
      return p.cobalt;
    case "brass":
      return p.brass;
    case "ok":
      return p.ok;
    case "deny":
      return p.deny;
  }
}

export function Sans({ size = 16, weight = "regular", tone = "label", style, ...rest }: BaseProps) {
  const color = useToneColor(tone);
  return (
    <Text
      {...rest}
      style={[{ color, fontSize: size, fontWeight: weightMap[weight] }, style]}
    />
  );
}

export function Mono({ size = 13, weight = "regular", tone = "label", style, ...rest }: BaseProps) {
  const color = useToneColor(tone);
  return (
    <Text
      {...rest}
      style={[
        {
          color,
          fontSize: size,
          fontWeight: weightMap[weight],
          fontFamily: "ui-monospace",
          fontVariant: ["tabular-nums"],
        },
        style,
      ]}
    />
  );
}
