import { useLocalSearchParams, useRouter } from "expo-router";
import { Pressable, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { resetCeremony } from "@/src/session/pairing-flow";

/**
 * Terminal pairing state: paired, or aborted on a fingerprint mismatch.
 */
export default function DoneScreen() {
  const p = useTheme();
  const router = useRouter();
  const { ok } = useLocalSearchParams<{ ok?: string }>();
  const paired = ok === "1";

  return (
    <View style={{ flex: 1, padding: space.xl, justifyContent: "center", alignItems: "center", gap: space.lg }}>
      <Sf
        name={paired ? "checkmark.seal.fill" : "xmark.seal.fill"}
        color={paired ? p.ok : p.deny}
        size={56}
      />
      <Sans size={22} weight="semibold" style={{ textAlign: "center" }}>
        {paired ? "Paired" : "Not paired"}
      </Sans>
      <Sans size={16} tone="muted" style={{ textAlign: "center", maxWidth: 320 }}>
        {paired
          ? "This phone now decides for your Mac. When it asks, the request arrives here, sealed and signed; nothing proceeds without you."
          : "The words did not match, so nothing was pinned. That mismatch is exactly what pairing is designed to catch. Start again from the Mac."}
      </Sans>

      <Pressable
        onPress={() => {
          if (!paired) resetCeremony();
          router.dismissAll();
        }}
        style={{
          height: 52,
          minWidth: 200,
          paddingHorizontal: space.xl,
          borderRadius: radius.capsule,
          backgroundColor: paired ? p.cobalt : "transparent",
          borderWidth: paired ? 0 : 1,
          borderColor: p.line,
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Sans size={17} weight="semibold" style={{ color: paired ? p.cobaltInk : p.label }}>
          {paired ? "Done" : "Close"}
        </Sans>
      </Pressable>
    </View>
  );
}
