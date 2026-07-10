#!/usr/bin/env bash
#
# build-musl.sh - produce a static x86_64-unknown-linux-musl release binary of
# the Sigil relay, ready to scp onto the e2-micro (which is x86_64 Debian).
#
# Three ways to get the binary; pick one.
#
# (A) On a rustup host (Linux, or macOS cross-compiling) with musl std:
#       rustup target add x86_64-unknown-linux-musl
#       ./build-musl.sh
#     Cross-compiling from Apple Silicon macOS can be fiddly (the musl std must
#     resolve and `ring` needs a musl C toolchain); if it fights you, use (B).
#
# (B) Docker-based musl build (no rustup on the host needed; recommended on
#     macOS). Uses the repo's own Dockerfile, which already builds a static musl
#     binary in rust:1-alpine, then copies it out:
#       docker build -f crates/sigil-relay/Dockerfile -t sigil-relay <repo-root>
#       cid=$(docker create sigil-relay)
#       docker cp "$cid:/sigil-relay" ./sigil-relay
#       docker rm "$cid"
#     (This script does exactly that when invoked with `--docker`.)
#
# (C) Build ON the VM itself (simplest end-to-end, no cross-compile):
#       # on the box, one-time:
#       sudo apt-get update && sudo apt-get install -y build-essential
#       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#       source "$HOME/.cargo/env"
#       # from a checkout of the repo on the box:
#       cargo build --release --locked -p sigil-relay
#       sudo install -m 0755 target/release/sigil-relay /usr/local/bin/sigil-relay
#     e2-micro has 1 GB RAM; an LTO release link can be tight. If the linker is
#     OOM-killed, add swap first:
#       sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile \
#         && sudo mkswap /swapfile && sudo swapon /swapfile
#
# Expected artifact size: roughly 2 MB, stripped (the design notes measure
# ~1.7 MB on aarch64-apple-darwin; the musl x86_64 build lands in the same
# ballpark). It is fully static: `ldd` reports "not a dynamic executable".
#
# Usage:
#   ./build-musl.sh            # native/cross rustup build (mode A)
#   ./build-musl.sh --docker   # Docker-based musl build (mode B)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
TARGET="x86_64-unknown-linux-musl"
OUT="$HERE/sigil-relay"

if [ "${1:-}" = "--docker" ]; then
  echo "building via Docker (rust:1-alpine musl) ..."
  docker build -f "$REPO_ROOT/crates/sigil-relay/Dockerfile" -t sigil-relay "$REPO_ROOT"
  cid="$(docker create sigil-relay)"
  trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:/sigil-relay" "$OUT"
  echo "wrote $OUT"
else
  if ! command -v rustup >/dev/null 2>&1; then
    echo "ERROR: rustup not found. Use './build-musl.sh --docker' instead, or" >&2
    echo "       build on the VM (mode C in this script's header)." >&2
    exit 1
  fi
  echo "adding target $TARGET (idempotent) ..."
  rustup target add "$TARGET"
  echo "building -p sigil-relay --release --locked --target $TARGET ..."
  ( cd "$REPO_ROOT" && cargo build --release --locked -p sigil-relay --target "$TARGET" )
  cp "$REPO_ROOT/target/$TARGET/release/sigil-relay" "$OUT"
  echo "wrote $OUT"
fi

echo
ls -lh "$OUT"
echo "Now scp it to the box next to setup.sh, e.g.:"
echo "  gcloud compute scp $OUT sigil-relay:~/ --zone=us-central1-a"
