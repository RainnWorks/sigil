import { Stack } from "expo-router/stack";

import { useTheme } from "@/theme/colors";

export default function PairingStack() {
  const p = useTheme();
  return (
    <Stack
      screenOptions={{
        headerShadowVisible: false,
        headerStyle: { backgroundColor: p.bg },
        headerTitleStyle: { color: p.label },
        headerTintColor: p.cobalt,
        contentStyle: { backgroundColor: p.bg },
      }}
    >
      <Stack.Screen name="index" options={{ title: "Pair your Mac" }} />
      <Stack.Screen name="keys" options={{ title: "This phone is the key" }} />
      <Stack.Screen name="scan" options={{ title: "Scan the Mac", headerTransparent: true, headerStyle: { backgroundColor: "transparent" } }} />
      <Stack.Screen name="confirm" options={{ title: "Confirm", gestureEnabled: false }} />
      <Stack.Screen name="done" options={{ title: "", headerBackVisible: false, gestureEnabled: false }} />
    </Stack>
  );
}
