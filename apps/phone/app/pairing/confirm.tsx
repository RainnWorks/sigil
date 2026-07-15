import { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import { Pressable, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import {
  currentCeremony,
  describePairingError,
  finishPairing,
  LOST_PLACE_COPY,
  resetCeremony,
  submitPairingResponse,
} from "@/src/session/pairing-flow";

type Phase = "handshaking" | "confirm" | "completing" | "error";

/**
 * The fingerprint confirmation and the live rendezvous. On mount the phone sends
 * its authenticated PairingResponse to the daemon (message 1) over the relay;
 * both devices then show the same six words derived from the two pinned
 * identities. "They match" persists the pairing and arms the session (the
 * ceremony delivers no key). "Don't match" aborts, because a mismatch is the
 * signature of a man-in-the-middle on the QR channel.
 */
export default function ConfirmScreen() {
  const p = useTheme();
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>("handshaking");
  const [words, setWords] = useState<string[]>([]);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let alive = true;
    (async () => {
      const c = currentCeremony();
      if (!c?.confirmWords) {
        if (alive) {
          setError(LOST_PLACE_COPY);
          setPhase("error");
        }
        return;
      }
      if (alive) setWords(c.confirmWords);
      try {
        // Message 1: prove possession of the one-time secret and let the daemon
        // pin this phone, so its screen can show the matching words.
        await submitPairingResponse();
        if (alive) setPhase("confirm");
      } catch (e) {
        if (alive) {
          setError(describePairingError(e));
          setPhase("error");
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function onMatch(): Promise<void> {
    setPhase("completing");
    try {
      // The ceremony delivers no key: persist the pairing and arm the live
      // session (finishPairing does both). Arming reflects the freshly persisted
      // pairing into the store (paired: true, armed) so the root layout keeps us
      // on the tabs instead of bouncing back into the pairing stack.
      await finishPairing();
      router.replace({ pathname: "/pairing/done", params: { ok: "1" } });
    } catch (e) {
      setError(describePairingError(e));
      setPhase("error");
    }
  }

  function onMismatch(): void {
    resetCeremony();
    router.replace({ pathname: "/pairing/done", params: { ok: "0" } });
  }

  if (phase === "error") {
    return (
      <View style={{ flex: 1, padding: space.xl, justifyContent: "center", gap: space.md }}>
        <Sans size={18} weight="semibold" tone="deny">
          Pairing did not complete
        </Sans>
        <Sans tone="muted">{error}</Sans>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, padding: space.xl, gap: space.xl, justifyContent: "center" }}>
      <View style={{ alignItems: "center", gap: space.sm }}>
        {phase === "handshaking" || phase === "completing" ? (
          <Sf name="dot.radiowaves.left.and.right" color={p.cobalt} size={36} />
        ) : (
          <Sf name="checkmark.shield" color={p.cobalt} size={36} />
        )}
        <Sans size={20} weight="semibold" style={{ textAlign: "center" }}>
          {phase === "handshaking"
            ? "Handshaking…"
            : phase === "completing"
              ? "Completing…"
              : "Do both screens match?"}
        </Sans>
        <Sans size={15} tone="muted" style={{ textAlign: "center", maxWidth: 320 }}>
          Your Mac should be showing the same six words.
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
