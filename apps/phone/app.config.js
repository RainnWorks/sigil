// Dynamic Expo config for Sigil.
//
// The official build ships Rainnworks' Apple identity; every value below reads
// an env var and falls back to the current Rainnworks default, so `expo config`
// / `expo prebuild` with no env set resolves byte-for-byte to what the static
// app.json used to produce. A self-hoster who wants the background push doorbell
// on THEIR OWN Apple account rebuilds with these vars set to their own ids.
// See docs/design/self-host-build.md for the full guide and knock-mode picture.
//
// The relay URL is deliberately NOT here: the phone learns it per-pairing from
// the QR's `endpoints` (src/transport/relay-http.ts -> relayBaseFromEndpoints),
// so switching relays never needs a rebuild.

/** Read an env var, trimming, or fall back to the Rainnworks default. */
const env = (name, fallback) => {
  const raw = process.env[name];
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  return trimmed.length > 0 ? trimmed : fallback;
};

const APP_NAME = env("SIGIL_APP_NAME", "Sigil");
const APP_SLUG = env("SIGIL_APP_SLUG", "sigil");
const SCHEME = env("SIGIL_SCHEME", "sigil");
const IOS_BUNDLE_ID = env("SIGIL_IOS_BUNDLE_ID", "works.rainn.sigil");
const IOS_TEAM_ID = env("SIGIL_IOS_TEAM_ID", "53W966FBFP");
const ANDROID_PACKAGE = env("SIGIL_ANDROID_PACKAGE", "works.rainn.sigil");
// aps-environment entitlement. An app-store / TestFlight build is always signed
// "production"; a development build is "development". Defaulting to production
// matches what the official beta lane already signs (Release + app-store export).
const APNS_ENV = env("SIGIL_APNS_ENV", "production");

const faceIdUsage =
  `${APP_NAME} uses Face ID to release the unwrap key that authorizes a secret. Denying never needs it.`;
const cameraUsage =
  `${APP_NAME} uses the camera once, to scan the pairing QR shown on your Mac.`;
const localNetworkUsage =
  `${APP_NAME} connects to the relay running on your Mac over your local Wi-Fi to receive and answer approval requests.`;

module.exports = {
  expo: {
    name: APP_NAME,
    slug: APP_SLUG,
    scheme: SCHEME,
    version: "0.1.0",
    orientation: "portrait",
    userInterfaceStyle: "automatic",
    newArchEnabled: true,
    ios: {
      supportsTablet: false,
      bundleIdentifier: IOS_BUNDLE_ID,
      appleTeamId: IOS_TEAM_ID,
      entitlements: {
        "aps-environment": APNS_ENV,
      },
      infoPlist: {
        NSFaceIDUsageDescription: faceIdUsage,
        NSCameraUsageDescription: cameraUsage,
        ITSAppUsesNonExemptEncryption: false,
        NSLocalNetworkUsageDescription: localNetworkUsage,
        NSAppTransportSecurity: {
          NSAllowsLocalNetworking: true,
        },
      },
    },
    android: {
      package: ANDROID_PACKAGE,
      permissions: ["CAMERA", "USE_BIOMETRIC", "POST_NOTIFICATIONS"],
    },
    plugins: [
      "expo-router",
      "expo-secure-store",
      "expo-local-authentication",
      "expo-notifications",
      [
        "expo-camera",
        {
          cameraPermission: cameraUsage,
        },
      ],
    ],
    experiments: {
      typedRoutes: true,
      reactCompiler: true,
    },
  },
};
