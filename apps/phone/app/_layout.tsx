import { useEffect } from "react";
import { useColorScheme } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { Stack } from "expo-router";
import { DarkTheme, DefaultTheme, ThemeProvider } from "expo-router/react-navigation";
import { StatusBar } from "expo-status-bar";

import { paletteFor } from "@/theme/tokens";
import { store } from "@/src/state/store";
import { demoReadRequest, demoRoutineRequest, demoSshRequest } from "@/src/state/demo";

/**
 * Root layout. A Stack holding the tab group plus the modal surfaces: the
 * approval sheet (form sheet with detents, glass on iOS 26), lockdown (a form
 * sheet you hold to seal), and the pairing ceremony (its own stack).
 */
export default function RootLayout() {
  const scheme = useColorScheme();
  const p = paletteFor(scheme);

  useEffect(() => {
    // Dev seed so the approval sheet and its states are reachable with no daemon.
    // The mock transport exercises the same requests through real crypto; this
    // is the pure-UI path. Remove for production.
    if (__DEV__ && store.getState().pending.length === 0) {
      store.seedPending([demoReadRequest(), demoSshRequest(), demoRoutineRequest()]);
    }
  }, []);

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
