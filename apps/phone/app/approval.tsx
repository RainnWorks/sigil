import { useRouter } from "expo-router";
import { View } from "react-native";

import { Sans } from "@/components/ui/text";
import { ApprovalSheet } from "@/components/approval/approval-sheet";
import { space } from "@/theme/tokens";
import { useAppState } from "@/src/state/store";

/**
 * The approval sheet route, presented as a native form sheet with detents. Shows
 * the first live (fresh / expiring) request. Decided requests leave the queue and
 * live on only in history, so once the queue drains the sheet auto-dismisses;
 * this route shows "Nothing to approve" only in the brief window before it closes.
 */
export default function ApprovalRoute() {
  const router = useRouter();
  const s = useAppState();

  const pending =
    s.pending.find((r) => r.state === "fresh" || r.state === "expiring") ?? s.pending[0];

  if (!pending) {
    return (
      <View style={{ flex: 1, alignItems: "center", justifyContent: "center", padding: space.xl }}>
        <Sans tone="muted">Nothing to approve.</Sans>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, paddingTop: space.lg }}>
      {/* Keyed by request id: when a decision advances the sheet to the next
          pending request, this remounts fresh (local busy/committed/gate state
          reset) instead of carrying the previous request's state over. */}
      <ApprovalSheet
        key={pending.request.requestId}
        pending={pending}
        onDone={() => router.back()}
      />
    </View>
  );
}
