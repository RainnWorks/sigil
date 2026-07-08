# Self-hosting the Sigil approver app

The official Sigil build ships under the Rainnworks Apple identity (bundle
`works.rainn.sigil`, team `53W966FBFP`) and, for the background push doorbell,
leans on Rainnworks' shared relay which holds the APNs signing key. A third
party can rebuild the app end-to-end under their OWN Apple identity and their
OWN relay. This document is the guide.

Nothing here changes the official build: every knob below is an env var read at
config time by `apps/phone/app.config.js`, and each one defaults to the current
Rainnworks value. Building with no env set resolves to exactly what the old
static `app.json` produced (confirmed: `expo config` yields bundle
`works.rainn.sigil`, team `53W966FBFP`, `aps-environment: production`).

## What is and is not baked into the app

Baked in at build time (needs a rebuild to change): the Apple/Android identity
(bundle id, team, package, `aps-environment` entitlement) and the app name /
slug / scheme. These are what the env vars below control.

NOT baked in: the relay URL. The phone learns its relay per-pairing, from the
`endpoints` list in the pairing QR your Mac shows (`crates/latch/src/pair.rs`
sets `endpoints = [relay_url]`; the phone reads it in
`apps/phone/src/transport/relay-http.ts` -> `relayBaseFromEndpoints`). So you
point Sigil at a different relay by pairing against a Mac configured for that
relay, never by rebuilding the app. One rebuilt app can talk to any relay.

Also not baked in: any Expo push service or EAS project id. Sigil registers the
device's native APNs token (`getDevicePushTokenAsync`) with your daemon, which
hands it to the relay; there is no Expo push token and no `extra.eas.projectId`
in the config, so you do not need an Expo/EAS account.

## Build-time env vars

Set these before `expo prebuild` (and thus before the fastlane `beta` lane).
All default to the Rainnworks value.

| Env var | Default | What it sets |
| --- | --- | --- |
| `SIGIL_APP_NAME` | `Sigil` | Display name and the generated Xcode project/scheme name |
| `SIGIL_APP_SLUG` | `sigil` | Expo slug |
| `SIGIL_SCHEME` | `sigil` | Deep-link URL scheme |
| `SIGIL_IOS_BUNDLE_ID` | `works.rainn.sigil` | iOS `CFBundleIdentifier`. Must equal the APNs topic your relay pushes to (see below) |
| `SIGIL_IOS_TEAM_ID` | `53W966FBFP` | Apple Developer team that signs the iOS build |
| `SIGIL_ANDROID_PACKAGE` | `works.rainn.sigil` | Android application id |
| `SIGIL_APNS_ENV` | `production` | The `aps-environment` entitlement. `production` for TestFlight / App Store / a real APNs push path; `development` for a debug build against Apple's sandbox |

The camera, Face ID, and local-network usage strings interpolate
`SIGIL_APP_NAME`, so a rebrand reads consistently (e.g. renaming to `Doorward`
yields "Doorward uses Face ID to release the unwrap key...").

## What you need on the Apple side

- An Apple Developer account (a team id for `SIGIL_IOS_TEAM_ID`) and a bundle id
  registered under it for `SIGIL_IOS_BUNDLE_ID`, with the Push Notifications
  capability enabled.
- An APNs authentication key (a `.p8`), its Key ID, and your Team ID. This key
  is a publisher secret; it lives on the RELAY, never on a user's Mac and never
  in the app. See the relay's `DEPLOY.md`.

## The background doorbell: three options

The push doorbell is a content-free "Approval requested" notification that wakes
the phone to drain the real, sealed request from its mailbox. It is always
best-effort: every rung fails open to the phone's own poll backstop, so a broken
or absent doorbell degrades to "you get the approval a poll-tick later", never
to a missed approval. Correctness never depends on push.

Because APNs requires the signing key's team and the push topic to match the
target app, the relay that sends your doorbell must be configured for YOUR
identity. Pick one:

### (a) Direct: your own relay holds your own APNs key

Self-host the relay (Docker or the Cloudflare Worker; see `relay/README.md` and
`relay/DEPLOY.md`), give it your APNs `.p8` via the `APNS_KEY_P8` secret, and
rebuild the app with your `SIGIL_IOS_BUNDLE_ID`. Your relay signs the ES256 JWT
and POSTs the doorbell straight to Apple for your app. This is the fully
self-hosted path.

Caveat to hand to whoever owns the relay: `relay/shared/push.ts` currently
hardcodes the APNs identity it pushes with:

```
const APNS_TOPIC   = "works.rainn.sigil"; // must equal SIGIL_IOS_BUNDLE_ID
const APNS_TEAM_ID = "53W966FBFP";        // must equal your Apple team
const APNS_KEY_ID  = "5PCK76SDBA";        // must equal your APNs key's Key ID
```

For a self-hosted doorbell these three must be parameterized to match your
bundle id, team, and key id (a relay-side change, out of scope for the app).
Until they are, a self-hosted relay will still run and every deposit still
succeeds, but the push will target the wrong topic and Apple will drop it, so
you fall through to poll-only.

### (b) Upstream: your relay forwards the doorbell to a relay that holds a key

A topology where your relay does not hold an APNs key itself but forwards the
wake to an upstream relay that does. This is not implemented in the current
relay (`push.ts` has exactly one push path, its own; `platform: "fcm"` is a
logged stub). Listed here as the intended shape if an upstream-forward knock
mode is added; check `relay/README.md` for whether it has landed before relying
on it.

### (c) Poll-only: no doorbell at all

Ship with no APNs key anywhere. The relay runs fine without `APNS_KEY_P8` (the
doorbell is simply disabled and every deposit still 200s), and the phone's
backstop poll (`apps/phone/src/transport/phone-relay.ts`, ~30s) picks up pending
approvals on its next tick. You lose only "instant" wake; you keep the entire
approval flow. This needs no Apple push setup and no `aps-environment` beyond
what signing requires. The simplest way to self-host.

## Android

Push on Android is not wired: `apps/phone/src/lib/push.ts` is iOS-only and the
relay's `platform: "fcm"` branch is a stub. An Android self-hoster is on the
poll-only path (option c) today; add `SIGIL_ANDROID_PACKAGE`, a Firebase
project, `google-services.json`, and an FCM sender on the relay to change that.

## Building

The fastlane `beta` lane (`fastlane/Fastfile`) runs `expo prebuild -p ios` then
`gym`. It reads `app.config.js` transparently, so the default env reproduces the
current native project. One thing to know if you change `SIGIL_APP_NAME`: the
lane refers to the generated project by name (`Sigil.xcodeproj`,
`Sigil.xcworkspace`, scheme `Sigil`). Renaming the app renames those artifacts,
so either keep `SIGIL_APP_NAME=Sigil` or adjust the lane's project/scheme names
to match. The default (unset) build is unaffected.

Do not commit a generated `ios/` or `android/` directory; both are gitignored
(`apps/phone/.gitignore`) and regenerated from `app.config.js` on every build.
