/**
 * Provenance rows in SF Mono, hairline-separated: the process chain, cwd,
 * machine, and time the daemon resolved and signed. All daemon-verified; a
 * caller's claims about its own ancestry are ignored upstream.
 *
 * The one exception is the optional `relay says` row. That address is the
 * RELAY's claim, not the daemon's: it is unsigned, a hostile relay can forge or
 * strip it, and it gates nothing. It is shown the way the SSH destination is
 * shown, only as verified as it truly is, so the key names the speaker rather
 * than dressing hearsay up as provenance. It renders only when present; absence
 * is silent, never "unknown".
 */
import { View } from "react-native";

import { Hairline } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/text";
import { space } from "@/theme/tokens";
import { processChain, relativeTime } from "@/src/lib/format";
import { type RelayOrigin } from "@/src/domain/types";
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

export function ProvenanceRows({
  provenance,
  now,
  relayOrigin,
}: {
  provenance: Provenance;
  now: number;
  relayOrigin?: RelayOrigin;
}) {
  return (
    <View>
      <Row k="process" v={processChain(provenance.processChain)} />
      <Hairline />
      <Row k="cwd" v={provenance.cwd} />
      <Hairline />
      <Row k="machine" v={provenance.machine} />
      <Hairline />
      <Row k="when" v={relativeTime(provenance.requestedAt, now)} />
      {relayOrigin ? (
        <>
          <Hairline />
          {/* The attribution lives in the KEY, so the value stays a bare address
              for the two-second read (and an IPv6 literal gets the full width).
              Same mono idiom as its siblings and deliberately no other signal:
              no icon, no color, no state tint. Not merely because a tint could
              read as verified, but because this is the ONE value on the sheet
              the adversary controls. Giving it a color vocabulary would hand
              the relay a lever on the phone's alarm language: it could paint
              caution on requests it dislikes, or strip the row to make anything
              look clean. It gets one flat, attributed row and no more. */}
          <Row k="relay says" v={relayOrigin.ip} />
        </>
      ) : null}
    </View>
  );
}
