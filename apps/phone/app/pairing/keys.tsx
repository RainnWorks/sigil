import { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { beginCeremony, currentCeremony } from "@/src/session/pairing-flow";

type Step = "generating" | "ready" | "sealing" | "sealed" | "error";

/**
 * The key-generation ceremony: mint Ed25519 + X25519 on-device, then take a
 * Face ID confirmation authorizing the pairing itself, with a plain-language
 * explanation and this phone's own public-key fingerprint. The phone holds no
 * unwrap key: it keeps only its own identity and, on capable hardware, a
 * Secure Enclave share minted later in the ceremony; approving supplies a
 * per-request partial, never a stored key.
 */
export default function KeysScreen() {
  const p = useTheme();
  const router = useRouter();
  const [step, setStep] = useState<Step>("generating");
  const [words, setWords] = useState<string[]>([]);
  const [errMsg, setErrMsg] = useState<string>("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const c = currentCeremony() ?? (await beginCeremony());
        if (!alive) return;
        setWords(c.ownWords);
        setStep("ready");
      } catch (err) {
        if (alive) {
          setErrMsg(err instanceof Error ? err.message : String(err));
          setStep("error");
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function confirmPairing(): Promise<void> {
    setStep("sealing");
    const gate = await faceGate("Pair this phone");
    if (!gate.ok) {
      setStep("ready");
      return;
    }
    setStep("sealed");
  }

  return (
    <ScrollView contentContainerStyle={{ padding: space.xl, gap: space.xl }}>
      <View style={{ gap: space.md }}>
        <Sf name="key.horizontal.fill" color={p.cobalt} size={40} />
        <Sans size={22} weight="semibold">
          This phone is the key
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          Sigil just generated this phone&apos;s own keys, and none of them leave it. The share
          that unlocks a sealed secret is held in this device&apos;s secure hardware and cannot be
          exported, even by Sigil; the keys that identify this phone to your Mac are kept in the
          system keychain. Your Mac keeps only ciphertext, so for a sealed secret your approval
          supplies the missing half of the cryptography, not a permission flag.
        </Sans>
      </View>

      <View style={{ gap: space.sm }}>
        <Sans size={13} tone="faint">
          This phone&apos;s fingerprint
        </Sans>
        <Card style={{ padding: space.lg }}>
          {step === "generating" ? (
            <Mono tone="muted">generating…</Mono>
          ) : step === "error" ? (
            <Mono tone="deny" selectable style={{ lineHeight: 22 }}>
              {errMsg || "could not generate keys on this device"}
            </Mono>
          ) : (
            <Mono size={16} selectable style={{ lineHeight: 24 }}>
              {words.join(" · ")}
            </Mono>
          )}
        </Card>
      </View>

      {step === "sealed" ? (
        <View style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
          <Sf name="checkmark.seal.fill" color={p.ok} size={20} />
          <Sans size={15} style={{ color: p.ok }}>
            Confirmed. This phone is ready to pair.
          </Sans>
        </View>
      ) : null}

      <View style={{ gap: space.sm }}>
        <Pressable
          disabled={step === "generating" || step === "error"}
          onPress={step === "sealed" ? () => router.push("/pairing/scan") : confirmPairing}
          style={{
            height: 52,
            borderRadius: radius.capsule,
            backgroundColor: p.cobalt,
            alignItems: "center",
            justifyContent: "center",
            opacity: step === "generating" || step === "error" ? 0.5 : 1,
          }}
        >
          <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
            {step === "sealing" ? "Confirming…" : step === "sealed" ? "Scan the Mac" : "Confirm with Face ID"}
          </Sans>
        </Pressable>
      </View>
    </ScrollView>
  );
}
