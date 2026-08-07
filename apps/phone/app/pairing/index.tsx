import { useState } from "react";
import { useRouter } from "expo-router";
import * as Notifications from "expo-notifications";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";

/**
 * The pairing landing: states the contract before any mechanics. Two parties
 * only: the Mac asks, the human on this phone decides. The transport that
 * carries requests is deliberately absent from this screen; it is plumbing,
 * never a party. The notification ask rides second, framed as how the Mac
 * reaches you, so the OS prompt lands in context.
 *
 * The pairing is a durable trust relationship: the device identity and its
 * threshold share survive app updates, so the copy here promises a standing
 * arrangement, never a per-version connection. If a future migration ever
 * needs the human again, it is framed as one light re-authorize tap, never as
 * starting over.
 */
export default function PairingLanding() {
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
        <Sf name="laptopcomputer.and.iphone" color={p.cobalt} size={40} />
        <Sans size={22} weight="semibold">
          Your Mac asks. You decide.
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          Pairing makes this phone the trusted approver for your Mac. When something there wants a
          secret released or a command run, the request comes here, and nothing proceeds until you
          approve it with Face ID. Denying is always one tap. You pair once; it holds until you
          reset it.
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          Allow notifications so a request can reach you anywhere. The push itself is content-free:
          &quot;Approval requested,&quot; nothing more. The details arrive sealed and open only on
          this phone.
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
