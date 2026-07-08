#!/usr/bin/env bash
#
# setup.sh - VM-side, run ONCE on the box (as root: `sudo ./setup.sh`) after the
# operator has copied the secrets into /etc/sigil. Creates the sigil service
# user, installs the relay binary + systemd unit + env file, installs Caddy and
# its config, then enables and starts both services.
#
# This script installs NO secrets and contains NONE. It expects the operator to
# have already placed these three files on the box (each chmod 600), see
# README.md step (c):
#   /etc/sigil/apns.p8     the Rainnworks APNs signing key (.p8 PEM)
#   /etc/sigil/origin.crt  the Cloudflare Origin Certificate for relay.rainn.works
#   /etc/sigil/origin.key  the matching private key
#
# It expects the relay binary to be reachable at ./sigil-relay (next to this
# script) OR at the path in $RELAY_BIN. Build it per README.md "Build the relay
# binary" (build-musl.sh), scp it onto the box, then run this script from the
# same directory.
#
# Re-running is safe: it overwrites the unit/env/Caddyfile from the copies in
# this directory and restarts the services.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root: sudo ./setup.sh" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
RELAY_BIN="${RELAY_BIN:-$HERE/sigil-relay}"
SIGIL_USER="sigil"
SIGIL_HOME="/var/lib/sigil"
ETC_DIR="/etc/sigil"

# ---- 1. service user (non-root, no login, no shell) ----
if id "$SIGIL_USER" >/dev/null 2>&1; then
  echo "user '$SIGIL_USER' already exists."
else
  echo "creating system user '$SIGIL_USER' ..."
  useradd --system --home-dir "$SIGIL_HOME" --create-home \
    --shell /usr/sbin/nologin "$SIGIL_USER"
fi

# ---- 2. /etc/sigil (0700, owned by sigil) for secrets + env ----
install -d -m 0700 -o "$SIGIL_USER" -g "$SIGIL_USER" "$ETC_DIR"

# Warn (do not fail) if the operator has not staged the secrets yet.
for f in apns.p8 origin.crt origin.key; do
  if [ ! -f "$ETC_DIR/$f" ]; then
    echo "WARNING: $ETC_DIR/$f is missing. Copy it in (chmod 600) before the" >&2
    echo "         relay can ring doorbells / Caddy can serve TLS." >&2
  fi
done

# ---- 3. relay binary -> /usr/local/bin/sigil-relay ----
if [ ! -x "$RELAY_BIN" ]; then
  echo "ERROR: relay binary not found or not executable at: $RELAY_BIN" >&2
  echo "       Build it (see README.md / build-musl.sh), scp it next to this" >&2
  echo "       script, or set RELAY_BIN=/path/to/sigil-relay." >&2
  exit 1
fi
echo "installing relay binary -> /usr/local/bin/sigil-relay ..."
install -m 0755 -o root -g root "$RELAY_BIN" /usr/local/bin/sigil-relay

# ---- 4. env file (from the example if the operator has not made one) ----
if [ ! -f "$ETC_DIR/relay.env" ]; then
  echo "installing $ETC_DIR/relay.env from relay.env.example ..."
  install -m 0640 -o "$SIGIL_USER" -g "$SIGIL_USER" \
    "$HERE/relay.env.example" "$ETC_DIR/relay.env"
else
  echo "$ETC_DIR/relay.env already exists, leaving it."
fi

# ---- 5. systemd unit ----
echo "installing systemd unit ..."
install -m 0644 -o root -g root "$HERE/sigil-relay.service" \
  /etc/systemd/system/sigil-relay.service

# ---- 6. Caddy (official Debian/Ubuntu package repo) ----
if command -v caddy >/dev/null 2>&1; then
  echo "caddy already installed."
else
  echo "installing Caddy ..."
  apt-get update
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy
fi

# ---- 7. Caddyfile ----
echo "installing /etc/caddy/Caddyfile ..."
install -d -m 0755 /etc/caddy
install -m 0644 -o root -g root "$HERE/Caddyfile" /etc/caddy/Caddyfile
# Caddy runs as the 'caddy' user; let it read the origin cert + key.
if id caddy >/dev/null 2>&1; then
  chgrp caddy "$ETC_DIR" "$ETC_DIR/origin.crt" "$ETC_DIR/origin.key" 2>/dev/null || true
  chmod 0750 "$ETC_DIR" 2>/dev/null || true
  chmod 0640 "$ETC_DIR/origin.crt" "$ETC_DIR/origin.key" 2>/dev/null || true
fi

# ---- 8. enable + start both services ----
echo "enabling and starting services ..."
systemctl daemon-reload
systemctl enable --now sigil-relay.service
systemctl restart caddy

echo
echo "== setup complete =="
systemctl --no-pager --lines=0 status sigil-relay.service || true
echo
echo "Verify from your workstation:"
echo "  curl https://relay.rainn.works/health"
echo "  curl https://relay.rainn.works/version"
echo "Local (on the box) origin check, bypassing Caddy:"
echo "  curl http://127.0.0.1:8080/health"
