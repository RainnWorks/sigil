# Releasing Sigil

One tag ships everything: the CLI, the Mac app, the relay, and the iPhone build.

```sh
# 1. Set the version in both places, commit, then tag.
#    Cargo.toml            [workspace.package] version
#    apps/mac/project.yml  MARKETING_VERSION
git commit -am "Version 0.2.0"
git tag v0.2.0 && git push origin v0.2.0
```

The `version` job checks those two files against the tag before anything is
built, so a half-bumped release stops in about thirty seconds instead of
producing files that point at each other wrongly.

## What the tag runs

| Job | Produces | Needs |
|---|---|---|
| `version` | the version every other job uses | nothing |
| `cli` | `sigil` and `sigil-config`, one tarball per architecture, with checksums | nothing |
| `cli (checksums + homebrew formula)` | `SHA256SUMS.txt` and `sigil.rb` | nothing |
| `ios` | a TestFlight build | `RW_ASC_*` |
| `mac` | a notarized, stapled `Sigil-<version>.dmg` and `appcast.xml` | `RW_ASC_*`, `RW_SIGNING_*`, `RW_SPARKLE_PRIVATE_KEY` |
| `relay` | a static musl binary and a GHCR image | nothing for the image |
| `relay (deploy to gcp)` | the running relay, restarted | `RELAY_DEPLOY_*` |
| `github release` | the release, with every artifact attached | nothing |
| `homebrew tap` | `Formula/sigil.rb` and `Casks/sigil-app.rb` in the tap | `RW_TAP_DEPLOY_KEY` |

A job whose secret is missing logs a warning and does nothing, so the release
still happens. The secrets are RainnWorks organization secrets, visible to every
repository in the organization; see
[RainnWorks/apple-signing](https://github.com/RainnWorks/apple-signing).

## How people get the update

**The CLI** comes from the tap:

```sh
brew install rainnworks/tap/sigil
brew upgrade rainnworks/tap/sigil
```

The name has to be qualified. An unrelated app already holds `sigil` in
homebrew-cask, so a bare `brew install sigil` reaches that one instead.

**The Mac app** updates itself. Every release carries an `appcast.xml` that
names the new DMG and carries a signature; the app reads it from
`releases/latest/download/appcast.xml` and offers the update. The cask is
marked `auto_updates true`, so `brew upgrade` leaves the app alone and lets
Sparkle do it.

```sh
brew install --cask rainnworks/tap/sigil-app
```

## The Sparkle key

One Ed25519 key signs updates for every RainnWorks app. The private half is the
`RW_SPARKLE_PRIVATE_KEY` organization secret; the public half is `SUPublicEDKey`
in `apps/mac/Sigil/App/Info.plist`.

`scripts/release/write-appcast.sh` derives the public key from the secret and
refuses to sign when it does not match the one in the app. That check exists
because the failure it prevents is silent: an update signed with the wrong key
downloads, fails its signature check, and every installed copy simply stays on
the old version.

If the key is ever replaced, the new public key has to reach users in a release
signed by the old key, before the old key stops being used.

## Doing it by hand

The Mac lane runs on a Mac, with the secrets pulled from 1Password:

```sh
rw-apple exec -- bundle exec fastlane mac release
```

It writes `build/mac/Sigil-<version>.dmg`. The appcast needs the Sparkle key,
which only CI holds, so a hand-built DMG is for testing the build, not for
shipping.
