import { useEffect, useRef, useState } from "react";
import { useColorScheme } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { Stack, useRouter } from "expo-router";
import { DarkTheme, DefaultTheme, ThemeProvider } from "expo-router/react-navigation";
import { StatusBar } from "expo-status-bar";

import { paletteFor } from "@/theme/tokens";
import { DEMO, store, useSelector } from "@/src/state/store";
import { armLiveSession } from "@/src/session/controller";
import { registerPushToken, watchNotificationTaps, watchPushTokenRotation } from "@/src/lib/push";
import {
  demoReadRequest,
  demoRoutineRequest,
  demoSshRequest,
  demoThresholdRequest,
} from "@/src/state/demo";

/**
 * Root layout. A Stack holding the tab group plus the modal surfaces: the
 * approval sheet (form sheet with detents, glass on iOS 26), lockdown (a form
 * sheet you hold to seal), and the pairing ceremony (its own stack).
 */
export default function RootLayout() {
  const scheme = useColorScheme();
  const p = paletteFor(scheme);
  const router = useRouter();
  const paired = useSelector((s) => s.paired);
  const [hydrated, setHydrated] = useState(false);
  // Auto-present: the count of requests still awaiting a decision. When the first
  // one arrives we pop the approval sheet straight away (no tapping in); we reset
  // the latch once the queue drains so the next arrival re-presents.
  const liveCount = useSelector(
    (s) => s.pending.filter((r) => r.state === "fresh" || r.state === "expiring").length,
  );
  const presentedRef = useRef(false);

  useEffect(() => {
    // Boot from the REAL state: if this phone has a stored pairing, arm the relay
    // session (which reflects `paired` into the store); if not, stay unpaired.
    // `hydrated` gates the routing below so we don't flash the pairing flow before
    // the keystore has been read. Once armed, hand the daemon this device's push
    // token so it can wake this phone through APNs instead of the relay poll.
    void armLiveSession().then((armed) => {
      setHydrated(true);
      if (armed) void registerPushToken();
    });

    // Demo seed is OFF unless the explicit dev flag is set, so no Release build
    // ever shows canned pending requests. Exercises the same crypto path as real.
    if (DEMO && store.getState().pending.length === 0) {
      store.seedPending([
        demoReadRequest(),
        demoThresholdRequest(),
        demoSshRequest(),
        demoRoutineRequest(),
      ]);
    }
  }, []);

  useEffect(() => {
    // Re-register on every token rotation, and wake (arm + drain) on a tap,
    // whether the app was foregrounded, backgrounded, or launched by the tap.
    // Both are safe no-ops while unarmed.
    const offRotation = watchPushTokenRotation();
    const offTaps = watchNotificationTaps();
    return () => {
      offRotation();
      offTaps();
    };
  }, []);

  useEffect(() => {
    // Once we know the real pairing state, an unpaired phone routes straight into
    // the pairing ceremony. A paired phone stays on its tabs.
    if (hydrated && !paired) {
      router.replace("/pairing");
    }
  }, [hydrated, paired, router]);

  useEffect(() => {
    // Auto-present the approval sheet the instant a request lands, so the human
    // never has to hunt for it. Latch on presentRef so we present once per burst
    // (not on every state tick), and re-arm when the queue empties.
    if (!hydrated || !paired) return;
    if (liveCount > 0 && !presentedRef.current) {
      presentedRef.current = true;
      router.push("/approval");
    } else if (liveCount === 0) {
      presentedRef.current = false;
    }
  }, [hydrated, paired, liveCount, router]);

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <ThemeProvider value={scheme === "dark" ? DarkTheme : DefaultTheme}>
          <StatusBar style="auto" />
          <Stack screenOptions={{ headerShown: false }}>
            <Stack.Screen name="(tabs)" />
            <Stack.Screen
              name="approval"
              options={{
                presentation: "formSheet",
                sheetGrabberVisible: true,
                sheetAllowedDetents: [0.6, 1.0],
                sheetLargestUndimmedDetentIndex: -1,
                contentStyle: { backgroundColor: p.bg },
                headerShown: false,
              }}
            />
            <Stack.Screen
              name="lockdown"
              options={{
                presentation: "formSheet",
                sheetGrabberVisible: true,
                sheetAllowedDetents: [0.45],
                contentStyle: { backgroundColor: p.bg },
                headerShown: false,
              }}
            />
            <Stack.Screen
              name="pairing"
              options={{ presentation: "modal", headerShown: false }}
            />
          </Stack>
        </ThemeProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
