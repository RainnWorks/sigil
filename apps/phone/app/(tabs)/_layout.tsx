import { NativeTabs } from "expo-router/unstable-native-tabs";

import { paletteFor } from "@/theme/tokens";
import { useScheme } from "@/theme/colors";
import { useSelector } from "@/src/state/store";

/**
 * The four native tabs. Home carries a brass badge with the count of live
 * pending requests. Admin surfaces (pairing, leases) are reached from inside
 * these tabs, not as tabs of their own.
 */
export default function TabsLayout() {
  const scheme = useScheme();
  const tint = paletteFor(scheme).cobalt;
  const pendingCount = useSelector(
    (s) => s.pending.filter((r) => r.state === "fresh" || r.state === "expiring").length,
  );

  return (
    <NativeTabs tintColor={tint} minimizeBehavior="onScrollDown">
      <NativeTabs.Trigger name="(home)">
        <NativeTabs.Trigger.Icon sf="dot.radiowaves.up.forward" md="sensors" />
        <NativeTabs.Trigger.Label>Home</NativeTabs.Trigger.Label>
        {pendingCount > 0 ? (
          <NativeTabs.Trigger.Badge>{String(pendingCount)}</NativeTabs.Trigger.Badge>
        ) : null}
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="(history)">
        <NativeTabs.Trigger.Icon sf="list.bullet.rectangle" md="history" />
        <NativeTabs.Trigger.Label>History</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="(devices)">
        <NativeTabs.Trigger.Icon sf="laptopcomputer" md="devices" />
        <NativeTabs.Trigger.Label>Devices</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="(settings)">
        <NativeTabs.Trigger.Icon sf="gearshape" md="settings" />
        <NativeTabs.Trigger.Label>Settings</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
    </NativeTabs>
  );
}
