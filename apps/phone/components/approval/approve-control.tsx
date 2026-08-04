/**
 * The approve capsule. TAP-ONLY: no slide, no hold anywhere (task #57). The
 * hardware-gated Face ID gate in the parent is the real authorization, so this
 * control only signals intent with a light haptic; the reason line carries an
 * optional heads-up dot, and the gesture itself is never made harder. Deny is
 * likewise a single tap, so refusing is never heavier than allowing.
 *
 * Two variants let the sheet offer, when a request is leasable, a "Keep approved
 * for <window>" primary above an "Approve once" secondary:
 *   primary   -> solid cobalt Liquid Glass capsule
 *   secondary -> cobalt outline capsule
 * Both are the same single tap behind the same Face ID gate; the variant sets
 * emphasis only, never how hard the gesture is.
 * `busy` freezes every capsule while the gate is up and `committing` marks the
 * one that was tapped, so "Approving…" names which authorization is in flight
 * rather than lighting up both. If the gate fails the parent clears both and the
 * controls are live again.
 */
import { Pressable, StyleSheet } from "react-native";

import { Sans } from "@/components/ui/text";
import { GlassSurface } from "@/components/ui/glass";
import { useTheme } from "@/theme/colors";
import { radius } from "@/theme/tokens";
import { hapticTick } from "@/src/lib/haptics";

interface Props {
  label: string;
  /** An approve is in flight: every capsule freezes, whichever was tapped. */
  busy: boolean;
  /**
   * THIS capsule is the one that was tapped, so it alone says "Approving…" and
   * stays lit while the others dim. The two capsules authorize different things
   * (one invocation vs a window), so the in-flight state must name which.
   */
  committing?: boolean;
  onApprove: () => void;
  variant?: "primary" | "secondary";
}

export function ApproveControl({
  label,
  busy,
  committing = false,
  onApprove,
  variant = "primary",
}: Props) {
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
        // The committing capsule stays lit (it is the one reporting); any other
        // dims out of the way rather than looking equally in flight.
        opacity: !busy ? 1 : committing ? 1 : 0.4,
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
        {committing ? "Approving…" : label}
      </Sans>
    </Pressable>
  );
}
