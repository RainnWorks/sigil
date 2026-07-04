/**
 * Deny is always one calm tap, sized so it never competes with approve but is
 * always instant, and it needs no biometric. A long press reveals the harder
 * option: "Deny and block <process> for 1 hour". Refusing must never be harder
 * than allowing.
 */
import { useState } from "react";
import { Pressable, View } from "react-native";
import Animated, { FadeIn, FadeOut } from "react-native-reanimated";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { hapticTick } from "@/src/lib/haptics";

export function DenyControl({
  process,
  disabled,
  onDeny,
  onDenyAndBlock,
}: {
  process: string;
  disabled?: boolean;
  onDeny: () => void;
  onDenyAndBlock: () => void;
}) {
  const p = useTheme();
  const [revealed, setRevealed] = useState(false);

  return (
    <View style={{ gap: space.sm }}>
      <Pressable
        disabled={disabled}
        onPress={() => {
          void hapticTick();
          onDeny();
        }}
        onLongPress={() => {
          void hapticTick();
          setRevealed(true);
        }}
        delayLongPress={350}
        style={{
          height: 48,
          borderRadius: radius.capsule,
          borderWidth: 1,
          borderColor: p.deny + "a6",
          alignItems: "center",
          justifyContent: "center",
          opacity: disabled ? 0.5 : 1,
        }}
      >
        <Sans size={16} weight="medium" style={{ color: p.deny }}>
          Deny
        </Sans>
      </Pressable>

      {revealed ? (
        <Animated.View entering={FadeIn.duration(160)} exiting={FadeOut.duration(120)}>
          <Pressable
            disabled={disabled}
            onPress={() => {
              void hapticTick();
              setRevealed(false);
              onDenyAndBlock();
            }}
            style={{
              height: 44,
              borderRadius: radius.capsule,
              backgroundColor: p.deny + "1f",
              flexDirection: "row",
              gap: 8,
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Sf name="nosign" color={p.deny} size={16} />
            <Sans size={15} weight="medium" style={{ color: p.deny }}>
              Deny and block {process} for 1 hour
            </Sans>
          </Pressable>
        </Animated.View>
      ) : null}
    </View>
  );
}
