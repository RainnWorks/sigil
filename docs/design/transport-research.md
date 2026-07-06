# Transport research: can the relay become near-zero custom code?

Status: research only (2026-07-06). No app/daemon/relay code changed. Goal:
shrink Sigil's custom transport by pulling in an existing library / managed
service, instead of hand-rolling the relay + push. Every option below is judged
against the seven constraints the transport actually has to satisfy.

## The transport has two separable halves

Naming this split is the whole answer, so it comes first.

1. **The mailbox** (rung 3 of the ladder). A blind, anonymous, bidirectional
   store-and-forward point for sealed libsodium envelopes. Daemon dials it
   OUTBOUND over WebSocket (no inbound port on the Mac); phone POSTs and pulls
   over HTTPS (phone has no inbound connection). Carries daemon->phone approval
   requests and phone->daemon sealed approvals + partials. A few KB, bursty,
   user-initiated. Today: the ~100-line Worker / Bun relay in `relay/`.
2. **The doorbell.** A content-free push ("approval requested", nothing more) to
   OUR app (`works.rainn.sigil`) on iOS (APNs) and Android (FCM), so the phone wakes
   and FETCHES the real sealed request from the mailbox. Push is the primary
   delivery now; a lazy ~30s foreground poll is the fallback.

These are structurally different problems. Push is **cloud->device only** and
one-directional; it cannot carry the phone->daemon approval back, and on iOS the
payload is throttled/undocumented for background data. The mailbox is the
bidirectional rendezvous. **No single service does both halves well**, so the
research answer is not "replace the relay with X" but "which half, if either,
can a pulled-in thing absorb without breaking blind/anonymous/no-middleman."

## The seven constraints (the scoring rubric)

1. Blind / E2E: sees only opaque ciphertext, no key-distribution role, cannot
   read/forge/replay meaningfully.
2. Anonymous: no accounts/identities; mailbox address = hash of the two paired
   pubkeys (self-authenticating, unguessable).
3. Bidirectional, small, infrequent (few-KB, bursty).
4. Doorbell push to OUR custom app, both iOS + Android, content-free.
5. Daemon connects OUTBOUND; phone fetches. No inbound port anywhere.
6. Self-hostable option AND ideally a hosted option; a BLIND middleman is
   acceptable, an untrusted-with-plaintext one is not.
7. Minimize custom code.

## Comparison table

Legend: Y = satisfies, N = fails, ~ = partial / with caveats. "Custom code
remaining" is what Sigil would still have to write and maintain after adopting
the option.

| Option | 1 Blind | 2 Anon | 3 Bidir | 4 Push to our app | 5 Outbound/fetch | 6 Self-host + cloud | Custom code remaining | Cost | Maturity |
|---|---|---|---|---|---|---|---|---|---|
| **Current relay** (CF Worker + DO, or Bun) | Y | Y | Y | N (separate doorbell) | Y | Y (CF free tier now, or Bun on a box) | The relay (~100 lines, already written) **+ doorbell** | $0 relay | Shipped, tested |
| **FCM as the ENTIRE transport** | ~ (Google sees payload; ciphertext only) | N (FCM token = device identity) | **N** (cloud->device only; no phone->daemon path) | Y (Android native; iOS via APNs cert on FCM) | ~ (device-side only) | N (Google only) | Doorbell + a **second** channel for phone->daemon (i.e. a mailbox anyway) | $0 | Mature |
| **FCM/APNs as the DOORBELL only** (recommended) | Y (content-free nudge) | ~ (push token is device-scoped, never touches relay) | n/a (doorbell) | **Y** | Y | N/A (push is inherently cloud) | ~1 file: APNs JWT signer + FCM HTTP v1 sender | $0 (Apple Dev already paid) | Mature |
| **ntfy** (self-host Go binary) | N on iOS | N on iOS | Y | **N for our app** (official iOS app is bound to ntfy.sh's Apple account; self-host iOS MUST relay through ntfy.sh, which then sees topic + message) | Y | ~ (self-host, but iOS still needs ntfy.sh upstream) | Fork ntfy-iOS to `works.rainn.sigil` + run own upstream w/ own APNs = MORE code than the relay | $0 | Mature (Android); iOS custom-app unsupported |
| **NATS / JetStream** (single binary / Synadia) | Y (opaque subjects/payloads) | ~ (subject can be a hash, but auth wants creds) | Y | **N** (no mobile push; add APNs/FCM yourself) | ~ (phone would hold a NATS conn or request/reply on wake) | Y (single binary self-host; Synadia cloud) | Doorbell (still) + NATS client on 3 platforms + run/operate a NATS server | $0 self-host / Synadia paid | Very mature |
| **MQTT managed** (HiveMQ / EMQX Cloud) | ~ (opaque payloads; broker sees them) | N (accounts / client IDs) | Y (retained msgs, QoS) | **N** (no push; add APNs/FCM) | ~ (persistent broker conn) | Y (self-host EMQX; managed cloud) | Doorbell + MQTT client on 3 platforms + broker | Managed paid | Very mature |
| **Ably / Pusher Beams / PubNub** | N (not blind by design; opaque payload possible) | N (API keys / accounts) | Y | ~ (Beams/PubNub push to custom app **via YOUR APNs/FCM** — so they hold your push token; violates "APNs token never touches the relay") | Y | **N** (no self-host) | Doorbell config + SDK on 3 platforms | Paid tiers | Mature |
| **Expo Push Service** (+ expo-server-sdk) | ~ (Expo relays your push) | N | n/a (doorbell only) | ~ (works, but adds Expo as a push middleman holding tokens; can bypass to raw APNs/FCM) | Y | N/A | Thin (expo-server-sdk) but adds a middleman for the nudge | $0 | Mature |
| **Web Push / VAPID** | Y | ~ | n/a | **N** (native iOS/Android apps cannot use Web Push; PWA-only on iOS 16.4+) | N/A | N/A | N/A | $0 | N/A for native |
| **CF Durable Objects / Queues** | Y | Y | Y | N (separate doorbell) | Y | ~ (CF only for the hosted form; Bun for self-host) | This IS the current relay substrate | $0 free tier | Shipped |
| **Matrix / libp2p / Signal sealed-sender** | Y | ~ | Y | N | ~ | Y | Heavy client stack on 3 platforms + server; solves a much bigger problem (federation / mesh / metadata privacy at scale) than a personal 1-mailbox doorbell | varies | Heavy |

## Resolving the central tension: is FCM-as-everything a valid simplification?

The brief's tempting shortcut is: skip the relay entirely, let the daemon use
`firebase-admin` to send a data message straight to the phone's FCM token, and
let Google be the single blind middleman for the whole flow. Three independent
facts kill it as a *complete* transport, and together they explain why the
two-part split is not incidental but forced:

- **Directionality.** FCM (and APNs) are cloud->device only. The phone's sealed
  approval + partial has to get **back** to the daemon. FCM offers no
  device->daemon path. So even in the best case you still need a second channel
  for phone->daemon — and a blind, anonymous, outbound-daemon channel for a
  few-KB sealed blob is precisely a mailbox. FCM cannot remove the mailbox; it
  can only ever be the doorbell.
- **iOS background-data reliability.** Silent/background data pushes on iOS are
  throttled by undocumented heuristics (roughly "a few per hour"), and Low Power
  Mode blocks them entirely; **visible** alert pushes are prioritized. This is
  exactly why the brief already chose a *visible, content-free* doorbell + a
  phone-initiated fetch rather than shipping the request inside the push. Trying
  to make FCM the transport would mean shipping the sealed envelope inside a
  background data message — the least reliable iOS path — and it caps at 4 KB
  (2 KB for topic sends), which our envelopes bump against.
- **Anonymity.** An FCM/APNs token *is* a device identity, and a hosted relay
  that routed by it would hold that identity. The design deliberately keeps the
  push token off the relay: the daemon pushes the doorbell **directly** to
  Apple/Google, and the anonymous mailbox never learns the token. Folding
  everything into FCM would collapse that separation.

So the resolution is: **FCM/APNs is the right tool for the doorbell and the
wrong tool for the mailbox.** Google-as-blind-middleman is acceptable *for a
content-free nudge* (it sees only "something is waiting"), and it is already how
the doorbell works. It is not acceptable and not even technically adequate as
the whole bidirectional transport.

## What is irreducible

- **The doorbell is irreducibly our own push code.** Push to a custom bundle
  (`works.rainn.sigil`) requires OUR OWN APNs `.p8` (Apple Developer Program, already
  committed and paid for TestFlight) and OUR OWN FCM project. No third party can
  make that disappear, because the app identity is ours. The good news: it is
  tiny and does not need a heavyweight SDK:
  - iOS: sign a short-lived ES256 JWT over the `.p8` (Team ID + Key ID), POST to
    `api.push.apple.com/3/device/<token>` over HTTP/2. `apns2` wraps this, or
    ~30 lines of `jose`/`jsonwebtoken` + Node/Bun `http2`.
  - Android: mint a service-account OAuth token with `google-auth-library`
    (scope `cloud-platform`), POST to the FCM HTTP v1 `send` endpoint. Skip the
    full `firebase-admin` dependency; the raw HTTP v1 call is a few lines.
  - Total: ~1 file, two small senders, both content-free.
- **The mailbox is irreducibly a blind rendezvous point.** Both endpoints are
  behind NAT with no inbound port (constraint 5), so rung 3 structurally needs a
  third point they both reach: the daemon dials out, the phone fetches. That is
  the relay. It cannot be pushed onto FCM (directionality) and every managed
  realtime service that *could* host it (NATS, MQTT, Ably, PubNub, ntfy) is a
  **net-heavier dependency** than the ~100 lines it would replace, and most also
  break blind (broker sees payloads), anonymous (accounts/API keys), self-host,
  or no-token-on-relay. The current Worker/Bun relay is already at the floor.

## Recommendation

**Keep the two-part split. Do not pull in a mailbox service. Keep the doorbell
as our own thin APNs/FCM sender.**

Concretely:

1. **Mailbox: keep the existing `relay/` (Worker + Bun), it is already the
   minimum.** It is ~100 lines driven by one shared protocol, blind, anonymous,
   bidirectional, outbound-daemon, and self-hostable. Two deployment options,
   both effectively free:
   - **Self-host (purist default):** `bun run bun/server.ts` on any box Tom
     controls. Zero third parties. This is the strongest answer to
     "no untrusted party in the middle."
   - **Cloud (convenience):** Cloudflare Worker + one Durable Object per mailbox.
     Newly relevant: **Durable Objects now run on the Workers *free* plan** (with
     the SQLite storage backend; 100k requests/day, 13k GB-s/day), so the hosted
     relay is $0 for a single user, not the previously-assumed paid plan.
   - No candidate service beats this on the rubric; each would *add* a runtime
     dependency and break at least one of blind/anonymous/self-host. So the
     "pull in a library for the mailbox" idea is a net loss and should be
     declined explicitly.
2. **Doorbell: write the ~1-file APNs + FCM sender in the daemon** (our `.p8`
   and FCM service account), content-free, sent directly by the daemon so the
   push token never touches the relay. Prefer small focused libs (`apns2` or
   `jose`+`http2` for APNs; `google-auth-library` + a raw HTTP v1 POST for FCM)
   over heavyweight SDKs (`firebase-admin`). This is task #44 / the standing
   "APNs doorbell" work and is the irreducible custom code.
3. **Reject FCM-as-entire-transport, ntfy-for-iOS, and the managed realtime
   services**, for the reasons in the table and the tension section: FCM can't
   carry phone->daemon; ntfy's iOS custom-app push is unsupported (self-host
   iOS must relay through ntfy.sh, which then sees topic + message — not blind,
   not anonymous); Ably/Pusher/PubNub aren't self-hostable and would hold the
   push token; NATS/MQTT add a broker + client stack and still need our own
   doorbell.

### How the recommendation scores against the core values

- **Blind / no-middleman:** self-hosted Bun relay = zero third parties; CF form =
  a blind carrier of opaque envelopes (the accepted residual). The doorbell nudge
  to Apple/Google carries no request content. Unchanged from today's posture.
- **Anonymous:** mailbox = hash of two pinned keys, no accounts; push token stays
  off the relay. Unchanged.
- **Custom code:** already near the floor — the mailbox is ~100 lines you keep,
  the doorbell is ~1 file you must write regardless of any service. The exercise's
  honest conclusion is that the relay is *not* the fat to trim; the irreducible
  doorbell is the only new code, and it is small.

## One correction to the premise, worth saying plainly

The framing was "make the custom relay super small by pulling in a service." The
research says the relay is **already** small and is the wrong thing to optimize:
every service that could host the mailbox is heavier and less blind/anonymous
than the code it replaces. The only genuinely irreducible custom code is the
**doorbell** (own APNs `.p8` + FCM), and no service removes it because the app
bundle is ours. Net simplification available: **$0**, and adopting any candidate
would *increase* dependency weight and *decrease* blindness/anonymity. Keep the
tiny relay; write the tiny doorbell; pull in only the small JWT/OAuth helpers
that make the doorbell shorter.

## Sources

- ntfy self-hosted iOS requires relaying through ntfy.sh upstream; custom-app
  push unsupported: <https://github.com/binwiederhier/ntfy/issues/1680>,
  <https://docs.ntfy.sh/config/>,
  <https://www.vanwerkhoven.org/blog/2025/my-ntfy-self-hosted-push-notification-setup/>
- FCM payload limits (4 KB / 2 KB topics) + iOS background-data throttling:
  <https://firebase.google.com/docs/cloud-messaging/throttling-and-quotas>,
  <https://firebase.google.com/docs/cloud-messaging/scale-fcm>
- APNs token-based `.p8` provider requirements (Team ID, Key ID, bundle; 2 keys
  max; keys don't expire):
  <https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns>
- Expo is push-service-agnostic; can send via raw FCM/APNs with device tokens:
  <https://docs.expo.dev/push-notifications/sending-notifications-custom/>
- NATS single-binary, opaque subjects, no built-in mobile push:
  <https://nats.io/about/>, <https://www.synadia.com/cloud>
- Ably/Pusher/PubNub push goes through their service via your APNs/FCM; not
  self-hostable: <https://ably.com/compare/pubnub-vs-pusher>,
  <https://websocket.org/comparisons/managed-services/>
- Native iOS apps cannot use Web Push/VAPID (PWA-only on iOS 16.4+):
  <https://www.magicbell.com/blog/ios-now-supports-web-push-notifications-and-why-you-should-care>
- Durable Objects now on the Workers free plan (SQLite backend); outbound-WS
  hibernation still unsupported (15-min alive per outbound connection):
  <https://developers.cloudflare.com/durable-objects/platform/pricing/>,
  <https://developers.cloudflare.com/durable-objects/best-practices/websockets/>,
  <https://github.com/cloudflare/workerd/issues/4864>
- Minimal doorbell libs: `apns2` (HTTP/2 token auth), `google-auth-library` +
  FCM HTTP v1: <https://firebase.google.com/docs/cloud-messaging/send/v1-api>
