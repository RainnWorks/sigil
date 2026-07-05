import { useEffect, useState } from "react";
import { useColorScheme } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { Stack, useRouter } from "expo-router";
import { DarkTheme, DefaultTheme, ThemeProvider } from "expo-router/react-navigation";
import { StatusBar } from "expo-status-bar";

import { paletteFor } from "@/theme/tokens";
import { DEMO, store, useSelector } from "@/src/state/store";
import { armLiveSession } from "@/src/session/controller";
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

  useEffect(() => {
    // Boot from the REAL state: if this phone has a stored pairing, arm the relay
    // session (which reflects `paired` into the store); if not, stay unpaired.
    // `hydrated` gates the routing below so we don't flash the pairing flow before
    // the keystore has been read.
    void armLiveSession().finally(() => setHydrated(true));

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
    // Once we know the real pairing state, an unpaired phone routes straight into
    // the pairing ceremony. A paired phone stays on its tabs.
    if (hydrated && !paired) {
      router.replace("/pairing");
    }
  }, [hydrated, paired, router]);

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
