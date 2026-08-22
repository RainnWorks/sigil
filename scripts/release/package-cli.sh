#!/usr/bin/env bash
# Cross-compile and package the `sigil` + `sigil-config` binaries for one
# target triple. Run on a runner with the target already added (e.g. via
# `dtolnay/rust-toolchain` with `targets: <triple>`); this script only builds
# and tars, it does not install toolchains.
#
# Both Apple and Linux targets go through here. Anything target-specific that
# the toolchain cannot infer (the musl linker settings, for instance) belongs
# in the caller's environment, not in this script: it passes CARGO_*/CC_*/
# RUSTFLAGS through untouched.
#
# Usage: scripts/release/package-cli.sh <target-triple> <version> [out-dir]
#   scripts/release/package-cli.sh aarch64-apple-darwin v0.1.0 dist
#   scripts/release/package-cli.sh x86_64-unknown-linux-musl v0.1.0 dist
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

# macOS ships `shasum` and no `sha256sum`; Linux ships `sha256sum` and often no
# `shasum`. Both write the same "<digest>  <name>" line, which is the only part
# render-homebrew-formula.sh and SHA256SUMS.txt depend on.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
else
  SHA256=(shasum -a 256)
fi

( cd "$OUT_DIR" && "${SHA256[@]}" "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo "wrote $TARBALL"
