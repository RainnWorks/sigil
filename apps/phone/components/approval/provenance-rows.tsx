/**
 * Provenance rows in SF Mono, hairline-separated: the process chain, cwd,
 * machine, and time the daemon resolved and signed. All daemon-verified; a
 * caller's claims about its own ancestry are ignored upstream.
 */
import { View } from "react-native";

import { Hairline } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/text";
import { space } from "@/theme/tokens";
import { processChain, relativeTime } from "@/src/lib/format";
import { type Provenance } from "@/src/protocol";

function Row({ k, v }: { k: string; v: string }) {
  return (
    <View
      style={{
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "baseline",
        gap: space.lg,
        paddingVertical: 8,
      }}
    >
      <Mono size={13} tone="faint">
        {k}
      </Mono>
      <Mono size={13} tone="muted" selectable style={{ flexShrink: 1, textAlign: "right" }}>
        {v}
      </Mono>
    </View>
  );
}

export function ProvenanceRows({ provenance, now }: { provenance: Provenance; now: number }) {
  return (
    <View>
      <Row k="process" v={processChain(provenance.processChain)} />
      <Hairline />
      <Row k="cwd" v={provenance.cwd} />
      <Hairline />
      <Row k="machine" v={provenance.machine} />
      <Hairline />
      <Row k="when" v={relativeTime(provenance.requestedAt, now)} />
    </View>
  );
}
