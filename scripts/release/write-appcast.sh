#!/usr/bin/env bash
# Write the Sparkle appcast for one release of the Sigil Mac app.
#
# Usage: scripts/release/write-appcast.sh <dmg> <version> <key-file> <out-file>
#   scripts/release/write-appcast.sh build/mac/Sigil-0.2.0.dmg 0.2.0 key.txt appcast.xml
#
# <key-file> holds the Sparkle private key (the RW_SPARKLE_PRIVATE_KEY
# organization secret, one key for every RainnWorks app). Before signing
# anything this checks that the key matches the SUPublicEDKey the app ships,
# because a signature under the wrong key produces an update every installed
# copy silently refuses.
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <dmg> <version> <key-file> <out-file>" >&2
  exit 1
fi

DMG="$1"
VERSION="$2"
KEY_FILE="$3"
OUT="$4"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SPARKLE_VERSION="2.10.0"
SPARKLE_SHA256="c2bf58aa8387266ac179357b1415d6f2635f044da8be41042af32425dae6da0c"
SPARKLE_DIR=".build/sparkle-$SPARKLE_VERSION"
INFO_PLIST="apps/mac/Sigil/App/Info.plist"
FEED_BASE="https://github.com/RainnWorks/sigil/releases"

[[ -f "$DMG" ]] || { echo "no such file: $DMG" >&2; exit 1; }

if [[ ! -x "$SPARKLE_DIR/bin/sign_update" ]]; then
  mkdir -p "$SPARKLE_DIR"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "https://github.com/sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION/Sparkle-$SPARKLE_VERSION.tar.xz" \
    -o "$tmp/sparkle.tar.xz"
  echo "$SPARKLE_SHA256  $tmp/sparkle.tar.xz" | shasum -a 256 -c - >/dev/null
  tar -xf "$tmp/sparkle.tar.xz" -C "$SPARKLE_DIR"
fi

shipped="$(/usr/libexec/PlistBuddy -c 'Print :SUPublicEDKey' "$INFO_PLIST")"
derived="$(node scripts/release/sparkle-public-key.mjs "$KEY_FILE")"
if [[ "$shipped" != "$derived" ]]; then
  echo "the signing key does not match SUPublicEDKey in $INFO_PLIST." >&2
  echo "every installed copy would refuse this update, so nothing was signed." >&2
  exit 1
fi

signature="$("$SPARKLE_DIR/bin/sign_update" --ed-key-file "$KEY_FILE" "$DMG")"

cat > "$OUT" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Sigil</title>
    <item>
      <title>Sigil $VERSION</title>
      <pubDate>$(date -u "+%a, %d %b %Y %H:%M:%S +0000")</pubDate>
      <link>$FEED_BASE/tag/v$VERSION</link>
      <sparkle:version>$VERSION</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>26.0</sparkle:minimumSystemVersion>
      <enclosure url="$FEED_BASE/download/v$VERSION/$(basename "$DMG")" type="application/octet-stream" $signature />
    </item>
  </channel>
</rss>
XML

echo "wrote $OUT"
