#!/usr/bin/env bash
#
# provision.sh - stand up the GCP e2-micro Always-Free VM that hosts the native
# Sigil relay (sigil-relay), and the firewall that keeps its origin reachable
# ONLY from Cloudflare (plus SSH from the operator).
#
# This script talks to Google Cloud only. It does NOT install anything on the
# box and it holds NO secrets. After it finishes it prints the exact Cloudflare
# and on-box follow-up steps (see README.md for the full runbook).
#
# Prerequisites on the machine you run this from:
#   - gcloud CLI, authenticated (`gcloud auth login`) with rights on the project
#   - curl (used to fetch Cloudflare's published IP ranges live)
#
# gcloud ISOLATION (recommended): if this machine's default ~/.config/gcloud
# belongs to a DIFFERENT Google account or org, run everything under an isolated
# gcloud config so your default account/project is never touched:
#
#   export CLOUDSDK_CONFIG="$HOME/.config/gcloud-sigil"
#   gcloud auth login                       # as you@example.com
#   gcloud config set project your-project-id
#   CLOUDSDK_CONFIG="$HOME/.config/gcloud-sigil" ./provision.sh
#
# provision.sh inherits whatever CLOUDSDK_CONFIG is exported; it does not set it.
# Set EXPECTED_ACCOUNT to have it refuse to run under the wrong login (fail safe).
#
# Usage:
#   PROJECT=your-project-id ./provision.sh
#   PROJECT=your-project-id ZONE=us-central1-a INSTANCE=sigil-relay OPERATOR_IP=203.0.113.7 ./provision.sh
#
# Env vars:
#   PROJECT      (required) your GCP project id. No default is committed.
#   ZONE         (default us-central1-a) MUST be in a free-tier region.
#   INSTANCE     (default sigil-relay) the VM name.
#   OPERATOR_IP  (optional) the single IP allowed to SSH (tcp:22). If unset the
#                script tries to detect your current public IP; if that fails it
#                skips the SSH rule and tells you to add it by hand (fail safe:
#                it never opens :22 to 0.0.0.0/0).
#
# Free-tier note: exactly ONE e2-micro is Always Free per billing account, and
# only in us-west1, us-central1, or us-east1. A second free instance, or one in
# any other region, is billed. The default zone here (us-central1-a) is eligible.

set -euo pipefail

# ---- parameters ----
PROJECT="${PROJECT:-}"
ZONE="${ZONE:-us-central1-a}"
INSTANCE="${INSTANCE:-sigil-relay}"
OPERATOR_IP="${OPERATOR_IP:-}"
# Optional guard: if set, refuse to run unless the active gcloud account matches
# (protects against provisioning under the wrong default login).
EXPECTED_ACCOUNT="${EXPECTED_ACCOUNT:-}"

# Derived. The static address and firewall rules are named off the instance so a
# second deployment (different INSTANCE) does not collide.
ADDRESS_NAME="${INSTANCE}-ip"
FW_CF_V4="${INSTANCE}-allow-cf-https-v4"
FW_CF_V6="${INSTANCE}-allow-cf-https-v6"
FW_SSH="${INSTANCE}-allow-ssh"
NETWORK_TAG="${INSTANCE}"

# Free-tier-eligible boot disk: standard persistent disk, within the 30 GB
# monthly free allowance. Debian 12 (bookworm) LTS.
MACHINE_TYPE="e2-micro"
BOOT_DISK_SIZE="30GB"
BOOT_DISK_TYPE="pd-standard"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"

if [ -z "$PROJECT" ]; then
  echo "ERROR: set PROJECT to your GCP project id, e.g.:" >&2
  echo "  PROJECT=your-project-id ./provision.sh" >&2
  exit 1
fi

REGION="${ZONE%-*}"
case "$REGION" in
  us-west1|us-central1|us-east1) ;;
  *)
    echo "WARNING: region '$REGION' is NOT an e2-micro Always Free region." >&2
    echo "         Free tier covers only us-west1, us-central1, us-east1." >&2
    echo "         This instance will be BILLED. Ctrl-C now to abort." >&2
    ;;
esac

GC="gcloud --project=$PROJECT"

# ---- gcloud isolation guard ----
if [ -z "${CLOUDSDK_CONFIG:-}" ]; then
  echo "WARNING: CLOUDSDK_CONFIG is not set. You may be using this machine's" >&2
  echo "         DEFAULT gcloud config. If that is a different account, isolate:" >&2
  echo "           export CLOUDSDK_CONFIG=\"\$HOME/.config/gcloud-sigil\"" >&2
  echo "         and authenticate inside it before running this script." >&2
fi
ACTIVE_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
echo "active gcloud account: ${ACTIVE_ACCOUNT:-<none>}  (config: ${CLOUDSDK_CONFIG:-default})"
if [ -n "$EXPECTED_ACCOUNT" ] && [ "$ACTIVE_ACCOUNT" != "$EXPECTED_ACCOUNT" ]; then
  echo "ERROR: active account '$ACTIVE_ACCOUNT' != EXPECTED_ACCOUNT" >&2
  echo "       '$EXPECTED_ACCOUNT'. Refusing to run (fail safe)." >&2
  exit 1
fi

echo "== Sigil relay provisioning =="
echo "  project:  $PROJECT"
echo "  zone:     $ZONE (region $REGION)"
echo "  instance: $INSTANCE"
echo

# ---- 1. reserve a static external IP (idempotent) ----
if $GC compute addresses describe "$ADDRESS_NAME" --region="$REGION" >/dev/null 2>&1; then
  echo "static IP '$ADDRESS_NAME' already exists, reusing it."
else
  echo "reserving static IP '$ADDRESS_NAME' in $REGION ..."
  $GC compute addresses create "$ADDRESS_NAME" --region="$REGION"
fi
STATIC_IP="$($GC compute addresses describe "$ADDRESS_NAME" --region="$REGION" \
  --format='value(address)')"
echo "  external IP: $STATIC_IP"
echo

# ---- 2. Cloudflare source ranges (fetched live, fail closed) ----
echo "fetching Cloudflare published IP ranges ..."
CF_V4="$(curl -fsS https://www.cloudflare.com/ips-v4 || true)"
CF_V6="$(curl -fsS https://www.cloudflare.com/ips-v6 || true)"
if [ -z "$CF_V4" ] || [ -z "$CF_V6" ]; then
  echo "ERROR: could not fetch Cloudflare IP ranges from cloudflare.com/ips-v4 and" >&2
  echo "       /ips-v6. Refusing to create the firewall with a stale or empty list" >&2
  echo "       (fail closed). Retry when you have network access." >&2
  exit 1
fi
# Comma-join the newline lists for gcloud --source-ranges.
CF_V4_CSV="$(echo "$CF_V4" | paste -sd, -)"
CF_V6_CSV="$(echo "$CF_V6" | paste -sd, -)"
echo "  IPv4 ranges: $(echo "$CF_V4" | wc -l | tr -d ' ')"
echo "  IPv6 ranges: $(echo "$CF_V6" | wc -l | tr -d ' ')"
echo

# ---- 3. firewall: allow tcp:443 from Cloudflare only ----
# Two rules (one per IP family) keep the source lists unambiguous. Both target
# only the instance's network tag, so nothing else in the VPC is exposed.
create_or_update_fw() {
  local name="$1" ranges="$2"
  if $GC compute firewall-rules describe "$name" >/dev/null 2>&1; then
    echo "firewall '$name' exists, updating source ranges ..."
    $GC compute firewall-rules update "$name" --source-ranges="$ranges"
  else
    echo "creating firewall '$name' ..."
    $GC compute firewall-rules create "$name" \
      --direction=INGRESS \
      --action=ALLOW \
      --rules=tcp:443 \
      --source-ranges="$ranges" \
      --target-tags="$NETWORK_TAG"
  fi
}
create_or_update_fw "$FW_CF_V4" "$CF_V4_CSV"
create_or_update_fw "$FW_CF_V6" "$CF_V6_CSV"
echo

# ---- 4. firewall: allow tcp:22 from the operator only ----
if [ -z "$OPERATOR_IP" ]; then
  OPERATOR_IP="$(curl -fsS https://api.ipify.org || true)"
  if [ -n "$OPERATOR_IP" ]; then
    echo "detected operator public IP: $OPERATOR_IP"
  fi
fi
if [ -n "$OPERATOR_IP" ]; then
  SSH_RANGE="${OPERATOR_IP}/32"
  if $GC compute firewall-rules describe "$FW_SSH" >/dev/null 2>&1; then
    echo "firewall '$FW_SSH' exists, updating source range to $SSH_RANGE ..."
    $GC compute firewall-rules update "$FW_SSH" --source-ranges="$SSH_RANGE"
  else
    echo "creating firewall '$FW_SSH' (tcp:22 from $SSH_RANGE) ..."
    $GC compute firewall-rules create "$FW_SSH" \
      --direction=INGRESS \
      --action=ALLOW \
      --rules=tcp:22 \
      --source-ranges="$SSH_RANGE" \
      --target-tags="$NETWORK_TAG"
  fi
else
  echo "WARNING: no OPERATOR_IP given and public-IP detection failed." >&2
  echo "         NOT opening tcp:22 (fail safe). Add it later with:" >&2
  echo "           $GC compute firewall-rules create $FW_SSH \\" >&2
  echo "             --direction=INGRESS --action=ALLOW --rules=tcp:22 \\" >&2
  echo "             --source-ranges=YOUR.IP.ADDR.ESS/32 --target-tags=$NETWORK_TAG" >&2
fi
echo

# ---- 5. the instance (idempotent) ----
if $GC compute instances describe "$INSTANCE" --zone="$ZONE" >/dev/null 2>&1; then
  echo "instance '$INSTANCE' already exists in $ZONE, leaving it as-is."
else
  echo "creating e2-micro instance '$INSTANCE' in $ZONE ..."
  $GC compute instances create "$INSTANCE" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$BOOT_DISK_SIZE" \
    --boot-disk-type="$BOOT_DISK_TYPE" \
    --address="$STATIC_IP" \
    --tags="$NETWORK_TAG" \
    --no-service-account \
    --no-scopes
fi
echo

# ---- 6. next steps ----
cat <<EOF
== Done. External IP: $STATIC_IP ==

Cloudflare follow-up (see README.md step (b)):
  1. Create an Origin Certificate for relay.example.com (SSL/TLS > Origin Server
     > Create Certificate). Save the cert and private key; you will place them on
     the box as /etc/sigil/origin.crt and /etc/sigil/origin.key.
  2. Set SSL/TLS mode to Full (strict).
  3. Add a PROXIED (orange cloud) DNS record for relay.example.com:
       A     relay   $STATIC_IP     (proxied)
     If you gave the VM an external IPv6, add a proxied AAAA too. The orange
     cloud is what makes Cloudflare the only thing that ever touches the origin.

On-box follow-up (see README.md steps (c)-(d)):
  gcloud --project=$PROJECT compute ssh $INSTANCE --zone=$ZONE
  # copy the .p8 + origin.crt + origin.key into /etc/sigil (chmod 600), then:
  sudo RELAY_HOST=relay.example.com ./setup.sh

Firewall summary:
  tcp:443  <- Cloudflare ranges only ($FW_CF_V4, $FW_CF_V6)
  tcp:22   <- operator IP only ($FW_SSH)
  :8080    NOT opened to the internet at all; only Caddy on the box reaches it.
EOF
