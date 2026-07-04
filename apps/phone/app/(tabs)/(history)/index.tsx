import { useLayoutEffect, useMemo, useState } from "react";
import { useNavigation } from "expo-router";
import { ScrollView, View } from "react-native";

import { Mono } from "@/components/ui/text";
import { Sans } from "@/components/ui/text";
import { Card, Hairline } from "@/components/ui/primitives";
import { stateColor, useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { relativeTime } from "@/src/lib/format";
import { type HistoryEntry } from "@/src/domain/types";
import { useAppState } from "@/src/state/store";

/**
 * Dense reverse-chron audit mirror. Decision-colored rows, searchable over names
 * and processes. Never stores or shows secret values.
 */
export default function HistoryScreen() {
  const navigation = useNavigation();
  const [query, setQuery] = useState("");
  const s = useAppState();

  useLayoutEffect(() => {
    navigation.setOptions({
      headerSearchBarOptions: {
        placeholder: "Search names, processes",
        onChangeText: (e: { nativeEvent: { text: string } }) => setQuery(e.nativeEvent.text),
      },
    });
  }, [navigation]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return s.history;
    return s.history.filter(
      (h) =>
        h.label.toLowerCase().includes(q) ||
        h.process.toLowerCase().includes(q) ||
        h.account.toLowerCase().includes(q) ||
        h.cwd.toLowerCase().includes(q),
    );
  }, [query, s.history]);

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, paddingBottom: 48 }}
    >
      <Card>
        {rows.length === 0 ? (
          <View style={{ padding: space.lg }}>
            <Sans tone="muted">No matching decisions.</Sans>
          </View>
        ) : (
          rows.map((h, i) => (
            <View key={h.id}>
              {i > 0 ? <Hairline inset={space.lg} /> : null}
              <Row entry={h} />
            </View>
          ))
        )}
      </Card>
    </ScrollView>
  );
}

function Row({ entry }: { entry: HistoryEntry }) {
  const p = useTheme();
  const state =
    entry.decision === "approved" ? "approved" : entry.decision === "denied" ? "denied" : "expired";
  const color = stateColor(p, state);
  const glyph = entry.decision === "approved" ? "✓" : entry.decision === "denied" ? "✗" : "⠿";
  return (
    <View style={{ flexDirection: "row", gap: space.md, padding: space.lg, alignItems: "flex-start" }}>
      <Mono size={14} weight="bold" style={{ color, width: 14 }}>
        {glyph}
      </Mono>
      <View style={{ flex: 1 }}>
        <Mono size={14} weight="medium">
          {entry.label}
        </Mono>
        <Mono size={12} tone="muted">
          {entry.process} · {entry.cwd}
        </Mono>
        {entry.note ? (
          <Mono size={12} style={{ color }}>
            &quot;{entry.note}&quot;
          </Mono>
        ) : null}
      </View>
      <View style={{ alignItems: "flex-end", gap: 2 }}>
        <Mono size={12} tone="faint">
          {relativeTime(entry.at)}
        </Mono>
        <Mono size={11} tone="faint">
          {entry.via}
        </Mono>
      </View>
    </View>
  );
}
