import { useRef, useState } from "react";
import { useRouter } from "expo-router";
import { CameraView, useCameraPermissions } from "expo-camera";
import { Pressable, View } from "react-native";

import { Sans } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { acceptScan } from "@/src/session/pairing-flow";

/**
 * QR scan: the camera reads the daemon's pairing QR (a base64url PairingPayload).
 * A malformed or non-Latch QR is ignored; the scanner keeps looking.
 */
export default function ScanScreen() {
  const p = useTheme();
  const router = useRouter();
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  const handled = useRef(false);

  if (!permission) {
    return <View style={{ flex: 1, backgroundColor: "#000" }} />;
  }

  if (!permission.granted) {
    return (
      <View style={{ flex: 1, padding: space.xl, gap: space.lg, justifyContent: "center" }}>
        <Sans size={18} weight="semibold">
          Camera access
        </Sans>
        <Sans size={15} tone="muted">
          Latch uses the camera once, to scan the pairing QR shown on your Mac.
        </Sans>
        <Pressable
          onPress={requestPermission}
          style={{
            height: 50,
            borderRadius: radius.capsule,
            backgroundColor: p.cobalt,
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Sans size={16} weight="semibold" style={{ color: p.cobaltInk }}>
            Allow camera
          </Sans>
        </Pressable>
      </View>
    );
  }

  async function onScan(data: string): Promise<void> {
    if (handled.current) return;
    handled.current = true;
    try {
      await acceptScan(data);
      router.replace("/pairing/confirm");
    } catch {
      handled.current = false;
      setError("That QR is not a Latch pairing code.");
    }
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <CameraView
        style={{ flex: 1 }}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        onBarcodeScanned={({ data }) => void onScan(data)}
      />
      <View style={{ position: "absolute", left: 0, right: 0, bottom: 60, alignItems: "center", gap: space.sm }}>
        <View
          style={{
            paddingHorizontal: space.lg,
            paddingVertical: space.md,
            borderRadius: radius.control,
            borderCurve: "continuous",
            backgroundColor: "#000000aa",
          }}
        >
          <Sans size={15} style={{ color: "#fff", textAlign: "center" }}>
            {error ?? "Point at the QR on your Mac"}
          </Sans>
        </View>
      </View>
    </View>
  );
}
