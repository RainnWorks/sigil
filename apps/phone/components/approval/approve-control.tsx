/**
 * The approve capsule. TAP-ONLY: no slide, no hold anywhere (task #57). The
 * hardware-gated Face ID gate in the parent is the real authorization, so this
 * control only signals intent with a light haptic; risk is conveyed by the risk
 * dot on the reason line, not by making the gesture harder. Deny is likewise a
 * single tap, so refusing is never heavier than allowing.
 *
 * Two variants let the sheet offer, when a request is leasable, an "Approve
 * once" primary beside a "Keep approved for <window>" secondary:
 *   primary   -> solid cobalt Liquid Glass capsule
 *   secondary -> cobalt outline capsule
 * `busy` freezes the control while the gate is up; if the gate fails the parent
 * flips `busy` off and the control is live again.
 */
import { Pressable, StyleSheet } from "react-native";

import { Sans } from "@/components/ui/text";
import { GlassSurface } from "@/components/ui/glass";
import { useTheme } from "@/theme/colors";
import { radius } from "@/theme/tokens";
import { hapticTick } from "@/src/lib/haptics";

interface Props {
  label: string;
  busy: boolean;
  onApprove: () => void;
  variant?: "primary" | "secondary";
}

export function ApproveControl({ label, busy, onApprove, variant = "primary" }: Props) {
  const p = useTheme();
  const secondary = variant === "secondary";
  return (
    <Pressable
      disabled={busy}
      onPress={() => {
        void hapticTick();
        onApprove();
      }}
      style={{
        height: secondary ? 48 : 56,
        borderRadius: radius.capsule,
        overflow: "hidden",
        alignItems: "center",
        justifyContent: "center",
        borderWidth: secondary ? 1.5 : 0,
        borderColor: secondary ? p.cobalt : "transparent",
        opacity: busy ? 0.6 : 1,
      }}
    >
      {/* iOS 26 Liquid Glass, tinted cobalt; falls back to a solid cobalt capsule.
          The secondary variant is a plain outline, no glass fill. */}
      {secondary ? null : (
        <GlassSurface
          style={StyleSheet.absoluteFill}
          fallbackColor={p.cobalt}
          tintColor={p.cobalt}
          isInteractive
        />
      )}
      <Sans
        size={secondary ? 16 : 17}
        weight="semibold"
        style={{ color: secondary ? p.cobalt : p.cobaltInk }}
      >
        {busy ? "Approving…" : label}
      </Sans>
    </Pressable>
  );
}
