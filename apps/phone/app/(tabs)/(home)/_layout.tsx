import { Stack } from "expo-router/stack";

import { useTheme } from "@/theme/colors";

export default function HomeStack() {
  const p = useTheme();
  return (
    <Stack
      screenOptions={{
        headerTransparent: true,
        headerShadowVisible: false,
        headerLargeTitle: true,
        headerLargeTitleShadowVisible: false,
        headerLargeStyle: { backgroundColor: "transparent" },
        headerBlurEffect: "none",
        headerTitleStyle: { color: p.label },
      }}
    >
      <Stack.Screen name="index" options={{ title: "Sigil" }} />
    </Stack>
  );
}
