import { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import { Pressable, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { currentCeremony, resetCeremony } from "@/src/session/pairing-flow";

type Phase = "handshaking" | "confirm" | "pairing" | "error";

/**
 * The fingerprint confirmation: both devices show the same six words derived
 * from the two pinned identities. Match pins the daemon and completes the
 * handshake; Don't match aborts, because a mismatch is the signature of a
 * man-in-the-middle on the QR channel.
 */
export default function ConfirmScreen() {
  const p = useTheme();
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>("handshaking");
  const [words, setWords] = useState<string[]>([]);

  useEffect(() => {
    const c = currentCeremony();
    if (!c?.confirmWords) {
      setPhase("error");
      return;
    }
    setWords(c.confirmWords);
    // Brief "handshaking" beat before asking for the human check.
    const t = setTimeout(() => setPhase("confirm"), 700);
    return () => clearTimeout(t);
  }, []);

  function onMatch(): void {
    setPhase("pairing");
    // On device: complete the sealed handshake with the daemon over the ladder.
    setTimeout(() => router.replace({ pathname: "/pairing/done", params: { ok: "1" } }), 900);
  }

  function onMismatch(): void {
    resetCeremony();
    router.replace({ pathname: "/pairing/done", params: { ok: "0" } });
  }

  if (phase === "error") {
    return (
      <View style={{ flex: 1, padding: space.xl, justifyContent: "center", gap: space.md }}>
        <Sans size={18} weight="semibold" tone="deny">
          Pairing lost its place
        </Sans>
        <Sans tone="muted">Start again from the Mac&apos;s QR code.</Sans>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, padding: space.xl, gap: space.xl, justifyContent: "center" }}>
      <View style={{ alignItems: "center", gap: space.sm }}>
        {phase === "handshaking" || phase === "pairing" ? (
          <Sf name="dot.radiowaves.left.and.right" color={p.cobalt} size={36} />
        ) : (
          <Sf name="checkmark.shield" color={p.cobalt} size={36} />
        )}
        <Sans size={20} weight="semibold" style={{ textAlign: "center" }}>
          {phase === "handshaking"
            ? "Handshaking…"
            : phase === "pairing"
              ? "Pairing…"
              : "Do both screens match?"}
        </Sans>
        <Sans size={15} tone="muted" style={{ textAlign: "center", maxWidth: 320 }}>
          Confirm both devices show these six words.
        </Sans>
      </View>

      <Card style={{ padding: space.xl, alignItems: "center" }}>
        <Mono size={20} weight="semibold" selectable style={{ lineHeight: 32, textAlign: "center" }}>
          {words.join(" · ")}
        </Mono>
      </Card>

      {phase === "confirm" ? (
        <View style={{ gap: space.md }}>
          <Pressable
            onPress={onMatch}
            style={{
              height: 52,
              borderRadius: radius.capsule,
              backgroundColor: p.cobalt,
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
              They match
            </Sans>
          </Pressable>
          <Pressable
            onPress={onMismatch}
            style={{
              height: 48,
              borderRadius: radius.capsule,
              borderWidth: 1,
              borderColor: p.deny + "a6",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Sans size={16} weight="medium" style={{ color: p.deny }}>
              Don&apos;t match
            </Sans>
          </Pressable>
        </View>
      ) : null}
    </View>
  );
}
