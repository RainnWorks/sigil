/**
 * A Liquid Glass surface that degrades safely. On iOS 26 (where the Liquid Glass
 * design is available) it renders a real `GlassView`; everywhere else — older iOS,
 * or when the user has Reduce Transparency on — it falls back to a plain view with
 * a solid `fallbackColor`, so the layout and touch targets are identical and there
 * is no visual regression. `style` carries layout only (size, radius, clipping);
 * the background comes from the glass effect or `fallbackColor`, never from `style`.
 */
import { type ReactNode } from "react";
import { Platform, type StyleProp, View, type ViewStyle } from "react-native";
import { GlassView, isLiquidGlassAvailable, type GlassStyle } from "expo-glass-effect";

/** Whether real Liquid Glass is available on this device right now. */
export function glassAvailable(): boolean {
  if (Platform.OS !== "ios") return false;
  try {
    return isLiquidGlassAvailable();
  } catch {
    return false;
  }
}

export function GlassSurface({
  style,
  fallbackColor,
  tintColor,
  glassStyle = "regular",
  isInteractive = false,
  children,
}: {
  style?: StyleProp<ViewStyle>;
  /** Solid background used only when glass is unavailable. */
  fallbackColor: string;
  /** Tint applied to the glass (and ignored by the fallback). */
  tintColor?: string;
  glassStyle?: GlassStyle;
  isInteractive?: boolean;
  children?: ReactNode;
}) {
  if (glassAvailable()) {
    return (
      <GlassView
        glassEffectStyle={glassStyle}
        tintColor={tintColor}
        isInteractive={isInteractive}
        style={style}
      >
        {children}
      </GlassView>
    );
  }
  return <View style={[style, { backgroundColor: fallbackColor }]}>{children}</View>;
}
