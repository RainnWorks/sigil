import { useState } from "react";
import { useRouter } from "expo-router";
import * as Notifications from "expo-notifications";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";

/**
 * Notification-permission priming. Explains the content-free doorbell before the
 * OS prompt, so the permission ask lands in context.
 */
export default function PairingPriming() {
  const p = useTheme();
  const router = useRouter();
  const [asked, setAsked] = useState(false);

  async function primeThenContinue(): Promise<void> {
    try {
      await Notifications.requestPermissionsAsync();
    } catch {
      // Permission denial is not fatal: poll-only mode remains the floor.
    }
    setAsked(true);
    router.push("/pairing/keys");
  }

  return (
    <ScrollView contentContainerStyle={{ padding: space.xl, gap: space.xl }}>
      <View style={{ gap: space.md }}>
        <Sf name="bell.badge" color={p.cobalt} size={40} />
        <Sans size={22} weight="semibold">
          A quiet doorbell
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          When a secret is requested, your Mac sends a content-free push: &quot;Approval
          requested,&quot; nothing more. The details are fetched on-device and never touch Apple.
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          Allow notifications so requests reach you when you are away from the desk. You can approve
          from the lock screen, but never with one tap; every approve still passes Face ID.
        </Sans>
      </View>

      <Pressable
        onPress={primeThenContinue}
        style={{
          height: 52,
          borderRadius: radius.capsule,
          backgroundColor: p.cobalt,
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
          {asked ? "Continue" : "Allow notifications"}
        </Sans>
      </Pressable>
      <Pressable onPress={() => router.push("/pairing/keys")} style={{ alignItems: "center" }}>
        <Sans size={15} tone="muted">
          Not now
        </Sans>
      </Pressable>
    </ScrollView>
  );
}
