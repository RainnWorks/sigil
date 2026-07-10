#!/usr/bin/env bash
# Cross-compile and package the `sigil` + `sigil-config` binaries for one
# macOS target triple. Run on a macOS runner with the target already added
# (e.g. via `dtolnay/rust-toolchain` with `targets: <triple>`); this script
# only builds and tars, it does not install toolchains.
#
# Usage: scripts/release/package-cli.sh <target-triple> <version> [out-dir]
#   scripts/release/package-cli.sh aarch64-apple-darwin v0.1.0 dist
#
# Produces <out-dir>/sigil-<version>-<target>.tar.gz and a .sha256 next to it.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <target-triple> <version> [out-dir]" >&2
  exit 1
fi

TARGET="$1"
VERSION="$2"
OUT_DIR="${3:-dist}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

cargo build --release --target "$TARGET" -p sigil

BIN_DIR="target/$TARGET/release"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp "$BIN_DIR/sigil" "$BIN_DIR/sigil-config" "$STAGE/"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/sigil-${VERSION}-${TARGET}.tar.gz"
tar -czf "$TARBALL" -C "$STAGE" sigil sigil-config

# macOS ships `shasum`, not `sha256sum`; this always runs on a macOS runner
# since these are Darwin-only targets.
( cd "$OUT_DIR" && shasum -a 256 "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo "wrote $TARBALL"
