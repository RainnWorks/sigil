# Sigil relay on a GCP e2-micro, fronted by Cloudflare

Turnkey, reusable scaffolding to self-host the native Rust relay
(`crates/sigil-relay`) on a Google Cloud `e2-micro` Always Free VM, with
Cloudflare in front of your relay hostname. Bring your own project id, domain,
and APNs key; every deployment-specific value below is an environment variable or
a placeholder.

This is **additive**. It does not remove the TypeScript relay and does not touch
the live Cloudflare Worker deploy. The managed Worker keeps serving until a human
confirms the Rust relay is live and healthy. The removal of the TS relay and the
CI cutover are a separate, later step, described under "After cutover" at the end.

Throughout, substitute your own values for the placeholders:

- `your-project-id` - your GCP project id
- `you@example.com` - the Google account you provision under
- `relay.example.com` - your relay's public hostname (the `RELAY_HOST` var)

## Architecture

```
  phone / daemon
        |
        v  HTTPS (443)
  Cloudflare  (orange-cloud proxy, SSL mode Full (strict))
        |
        v  HTTPS (443), allowed ONLY from Cloudflare IP ranges
  GCP e2-micro VM
    Caddy :443  -- terminates TLS with a Cloudflare Origin Certificate
        |
        v  plain HTTP
    sigil-relay :8080  (systemd, KNOCK_MODE=direct, your APNs key)
```

The origin IP is never directly reachable: the GCP firewall admits `:443` only
from Cloudflare's published ranges, and `:22` only from the operator. Port
`:8080` is not opened to the internet at all; only Caddy, on the box, reaches the
relay.

## What YOU (the operator) provide vs what is scripted

Provided by you (never in this repo):

- The GCP **project id** (`PROJECT`, required, no committed default).
- The relay **hostname** (`RELAY_HOST`, e.g. `relay.example.com`).
- The **APNs signing key** `.p8`. Its identity (topic/team/key id) defaults to
  the official Rainnworks values but is env-configurable via `APNS_TOPIC` /
  `APNS_TEAM_ID` / `APNS_KEY_ID` in `relay.env` (see `relay.env.example`), so a
  self-hoster can point at their own Apple app without recompiling. Placed on the
  box as `/etc/sigil/apns.p8`, mode `600`.
- The **Cloudflare Origin Certificate** and its private key for your relay
  hostname. Placed on the box as `/etc/sigil/origin.crt` and
  `/etc/sigil/origin.key`, mode `600`.

Scripted here:

- `provision.sh` creates the VM, the static IP, and the firewall rules.
- `build-musl.sh` produces the static relay binary.
- `setup.sh` installs the binary, the systemd unit, the env file, Caddy, and the
  Caddyfile on the box, then starts everything.

## gcloud isolation (recommended)

If this machine's default `~/.config/gcloud` belongs to a different Google
account or org, keep this work in a separate gcloud config so your default
account and project are never disturbed:

```sh
export CLOUDSDK_CONFIG="$HOME/.config/gcloud-sigil"
gcloud auth login                    # sign in as you@example.com
gcloud config set project your-project-id
```

A convenient permanent alias for the isolated CLI:

```sh
alias sgcloud='CLOUDSDK_CONFIG="$HOME/.config/gcloud-sigil" gcloud'
```

Everything below assumes `CLOUDSDK_CONFIG` points at the isolated config for the
duration of the session. `provision.sh` inherits it and warns if it is unset; set
`EXPECTED_ACCOUNT=you@example.com` to have it hard-refuse to run under the wrong
login.

## Prerequisites

- The GCP project must have **billing enabled**. The e2-micro is Always Free, but
  a billing account must be attached for the free tier to apply.
- **Always Free is ONE `e2-micro` per billing account**, and only in
  `us-west1`, `us-central1`, or `us-east1`. A second free instance, or one in
  any other region, is billed. The default zone here (`us-central1-a`) is
  eligible.
- Locally: `gcloud` CLI and `curl`. On the build host: Docker (for the musl
  build) or a rustup toolchain.

## Runbook

### (a) Provision the VM and firewall

```sh
export CLOUDSDK_CONFIG="$HOME/.config/gcloud-sigil"
PROJECT=your-project-id EXPECTED_ACCOUNT=you@example.com ./provision.sh
```

Optional overrides: `ZONE` (default `us-central1-a`), `INSTANCE` (default
`sigil-relay`), `OPERATOR_IP` (the single IP allowed to SSH; auto-detected if
unset). The script reserves a static IP, fetches Cloudflare's live IP ranges and
opens `:443` to them only, opens `:22` to your IP only, creates the e2-micro, and
prints the external IP plus the follow-up steps. It is idempotent-ish: existing
resources are reused, not recreated.

### (b) Cloudflare

1. **Origin Certificate.** In the Cloudflare dashboard for your zone:
   SSL/TLS > Origin Server > Create Certificate. Generate a certificate for your
   relay hostname (the default 15-year validity is fine; it is trusted only by
   Cloudflare's edge, which is all we need). Save the certificate PEM and the
   private key; these become `origin.crt` and `origin.key` on the box.
2. **SSL mode.** SSL/TLS > Overview > set the mode to **Full (strict)**. This
   makes Cloudflare validate the origin cert, which the Origin Certificate
   satisfies.
3. **DNS.** Add a **proxied** (orange cloud) record pointing at the VM IP that
   `provision.sh` printed:
   - `A   relay   <external-ip>`   (Proxied)
   - If the VM has an external IPv6, add `AAAA relay <v6>` (Proxied) too.
   The orange cloud is what forces all traffic through Cloudflare, which is the
   only source the origin firewall admits.

### (c) Stage the secrets on the box

```sh
gcloud compute ssh sigil-relay --zone=us-central1-a   # uses CLOUDSDK_CONFIG
# on the box:
sudo install -d -m 0700 /etc/sigil
sudo install -m 0600 /dev/stdin /etc/sigil/apns.p8    < AuthKey.p8
sudo install -m 0600 /dev/stdin /etc/sigil/origin.crt < origin.crt
sudo install -m 0600 /dev/stdin /etc/sigil/origin.key < origin.key
```

(Copy the three files up however you prefer; `gcloud compute scp` works too. Just
land them in `/etc/sigil` at mode `600`.)

### (d) Build the binary and run setup

Build the static binary (see also `build-musl.sh` and its header for all three
build modes):

```sh
./build-musl.sh --docker     # easiest on macOS; ~2 MB static binary
```

Copy it and this directory onto the box, then run setup as root with your
`RELAY_HOST`:

```sh
gcloud compute scp ./sigil-relay sigil-relay:~/ --zone=us-central1-a
gcloud compute scp --recurse . sigil-relay:~/gcp --zone=us-central1-a
gcloud compute ssh sigil-relay --zone=us-central1-a
# on the box:
cd ~/gcp && sudo RELAY_HOST=relay.example.com RELAY_BIN=~/sigil-relay ./setup.sh
```

`setup.sh` creates the `sigil` user, installs `/usr/local/bin/sigil-relay`, the
systemd unit, `/etc/sigil/relay.env` (from `relay.env.example`, `KNOCK_MODE=direct`),
Caddy, and the Caddyfile (with `RELAY_HOST` substituted for its `__RELAY_HOST__`
token), then enables and starts `sigil-relay` and `caddy`.

### (e) Verify

```sh
curl https://relay.example.com/health     # {"ok":true,"service":"sigil-relay"}
curl https://relay.example.com/version    # {"version":"...","git_commit":"..."}
```

On the box, the origin directly (bypassing Cloudflare and Caddy):

```sh
curl http://127.0.0.1:8080/health
```

### (f) Point a pairing at it and confirm a doorbell

Relay endpoints are configured per pairing (the daemon and phone each store the
relay base URL), so there is no global flag to flip. Point one test pairing's
relay at `https://relay.example.com`, trigger a gated command, and confirm the
phone receives the push doorbell and the approval round-trips. Because
`KNOCK_MODE=direct` and the `.p8` is installed, the relay signs and sends the
APNs wake itself.

## About the bind address

The relay binds `BIND_ADDR:PORT`, where `BIND_ADDR` defaults to `0.0.0.0` (all
interfaces) when unset; see `crates/sigil-relay/src/main.rs`. This deployment
sets `BIND_ADDR=127.0.0.1` in `relay.env` so the relay listens on loopback only
and Caddy reaches it at `127.0.0.1:8080`. That is defense-in-depth: the **GCP
firewall** already keeps the relay off the internet by never opening `:8080`
(only `:443` from Cloudflare and `:22` from the operator), and the loopback bind
means `:8080` is unreachable off the box even if that firewall were
misconfigured. An unparsable `BIND_ADDR` falls back to `0.0.0.0` with a warning.

## Files

| File | Role |
|------|------|
| `provision.sh` | GCP: static IP, Cloudflare-only `:443` firewall, operator `:22`, the e2-micro. |
| `build-musl.sh` | Produce the static `x86_64-unknown-linux-musl` relay binary (rustup, Docker, or on-VM). |
| `setup.sh` | On the box: user, binary, unit, env, Caddy, start. |
| `sigil-relay.service` | Hardened systemd unit. |
| `relay.env.example` | The exact env vars the relay reads, commented. |
| `Caddyfile` | TLS via the CF Origin Cert, reverse-proxy to `127.0.0.1:8080`. |

---

## After cutover (NOT done now; do only after a human confirms the Rust relay is live)

Once your relay hostname's `/health` is served by the GCP box, a real approval
has round-tripped through it, and it has been stable long enough to trust, retire
the TypeScript relay and retarget CI. None of this is done by this scaffolding.

1. **Retarget CI.** In `.github/workflows/release.yml`, the `relay-deploy` job
   currently runs `wrangler deploy` from `relay/`. Replace it with a step that
   builds and ships the Rust relay to the VM (or drop the Cloudflare deploy job
   entirely if the Worker is being decommissioned). The `relay-docker` job that
   pushes the `sigil-relay` image to GHCR can stay or be repurposed. Do this only
   as the deliberate cutover commit.
2. **Remove the TS relay** once nothing references it:
   - `relay/src/` (the Cloudflare Worker + Durable Object)
   - `relay/bun/` (the Bun variant)
   - `relay/wrangler.jsonc` and the Cloudflare-specific config
   - `relay/test/`, `relay/longpoll-adversarial.test.ts`, `relay/vitest.config.ts`,
     and the Worker/Bun test tooling
   - `relay/package.json`, `relay/package-lock.json`, `relay/node_modules`
   - Keep `relay/landing.html` **only if still needed**: the Rust relay
     `include_str!`s it from `../../relay/landing.html`, so it must survive as
     long as the native relay is built. Keep `relay/shared/` similarly only if
     something still imports it; otherwise remove.
3. **Docs.** Update `docs/design/rust-relay.md` and `relay/README.md` to state
   that the native relay is now the managed default, and remove the "Worker
   remains the managed default" framing.
4. **Cloudflare.** Delete the Worker/route for your relay hostname and the
   `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` GitHub secrets if the Worker
   is fully decommissioned.
