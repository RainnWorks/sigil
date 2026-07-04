/**
 * The recessed readout well. For a secret read it shows each requested ref's
 * display segments — the item name brightest, separators dim — rendered from
 * the provider-agnostic SecretRef and never by parsing the opaque reference. For
 * SSH it shows key label, host, and challenge fingerprint, the two things worth
 * verifying.
 */
import { Fragment } from "react";
import { View } from "react-native";

import { Mono } from "@/components/ui/text";
import { Hairline } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { segmentSecretRef } from "@/src/lib/format";
import { type SecretRef, type SshChallenge } from "@/src/protocol";

function Well({ children }: { children: React.ReactNode }) {
  const p = useTheme();
  return (
    <View
      style={{
        backgroundColor: p.well,
        borderRadius: radius.well,
        borderCurve: "continuous",
        borderWidth: 1,
        borderColor: p.line,
        padding: space.lg,
        gap: space.md,
      }}
    >
      {children}
    </View>
  );
}

function RefLine({ secretRef }: { secretRef: SecretRef }) {
  const p = useTheme();
  const segments = segmentSecretRef(secretRef);
  return (
    <Mono size={17} selectable style={{ lineHeight: 26 }}>
      {segments.map((s, i) => (
        <Mono
          key={i}
          size={17}
          weight={s.emphasis === "bright" ? "semibold" : "regular"}
          style={{
            color: s.emphasis === "bright" ? p.label : s.emphasis === "sep" ? p.faint : p.muted,
          }}
        >
          {s.text}
        </Mono>
      ))}
    </Mono>
  );
}

/**
 * A command may resolve several secrets; each gets its own hairline-separated
 * line in the one well.
 */
export function SecretReadout({ secrets }: { secrets: SecretRef[] }) {
  return (
    <Well>
      {secrets.map((ref, i) => (
        <Fragment key={i}>
          {i > 0 ? <Hairline /> : null}
          <RefLine secretRef={ref} />
        </Fragment>
      ))}
    </Well>
  );
}

export function SshReadout({ ssh }: { ssh: SshChallenge }) {
  const p = useTheme();
  return (
    <Well>
      <View style={{ flexDirection: "row", justifyContent: "space-between", gap: space.md }}>
        <Mono size={13} tone="faint">
          key
        </Mono>
        <Mono size={15} weight="semibold" selectable>
          {ssh.keyLabel}
        </Mono>
      </View>
      <Hairline />
      <View style={{ flexDirection: "row", justifyContent: "space-between", gap: space.md }}>
        <Mono size={13} tone="faint">
          host
        </Mono>
        <Mono size={15} selectable style={{ color: p.label }}>
          {ssh.host}
        </Mono>
      </View>
      <Hairline />
      <View style={{ gap: 4 }}>
        <Mono size={13} tone="faint">
          challenge
        </Mono>
        <Mono size={13} selectable tone="muted" style={{ lineHeight: 20 }}>
          {ssh.fingerprint}
        </Mono>
      </View>
    </Well>
  );
}
