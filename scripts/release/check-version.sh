#!/usr/bin/env bash
# Check that a release tag agrees with every version the repo ships.
#
# Usage: scripts/release/check-version.sh v0.2.0
#
# Three places name the version, and a release where they disagree produces a
# DMG, a Homebrew formula and an appcast that point at different things:
#   Cargo.toml            the CLI and every crate
#   apps/mac/project.yml  the Mac app, which Sparkle compares against the appcast
#   the tag               what the download URLs are built from
set -euo pipefail

TAG="${1:-}"
[[ -n "$TAG" ]] || { echo "usage: $0 <tag>" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

want="${TAG#v}"

cargo_version="$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *=/{gsub(/[" ]/,"");sub(/^version=/,"");print;exit}' Cargo.toml)"
mac_version="$(awk '/^ *MARKETING_VERSION:/{gsub(/[" ]/,"");sub(/^MARKETING_VERSION:/,"");print;exit}' apps/mac/project.yml)"

fail=0
for pair in "Cargo.toml:$cargo_version" "apps/mac/project.yml:$mac_version"; do
  file="${pair%%:*}"
  found="${pair#*:}"
  if [[ "$found" != "$want" ]]; then
    echo "$file says $found, tag $TAG says $want" >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "bump every version to match the tag, or tag the version the repo already has." >&2
  exit 1
fi

echo "version $want"
