# Release pipeline

Four shippable artifacts, one tag: `git tag v0.2.0 && git push origin v0.2.0`
runs `.github/workflows/release.yml`, which builds and (where its secrets
exist) publishes all four. `.github/workflows/ci.yml` is the separate,
secret-free gate that runs on every push and PR: `cargo test`/clippy/fmt,
the relay's typecheck+tests, the phone's tsc + protocol cross-check, unsigned
debug builds of the Mac and iOS apps, and the house-rule lint (zero em-dash,
zero emoji in product-facing strings - `scripts/lint/house-rules.py`).

Every publishing job in release.yml is gated on the secret(s) it needs: if a
secret is missing, that job logs a warning and no-ops the rest of its steps
(reports success, not failure) so merging this pipeline before any secret is
configured is safe - nothing crashes, the CLI release and whatever else is
configured still ship.

## Secrets checklist

Add these under **Settings -> Secrets and variables -> Actions -> Repository
secrets**. Each row is exactly where to get the value.

| Secret | Used by | Where to get it |
|---|---|---|
| `ASC_KEY_ID` | iOS TestFlight upload | App Store Connect -> Users and Access -> Integrations -> App Store Connect API -> create a key. This is the key's "Key ID" column. |
| `ASC_ISSUER_ID` | iOS TestFlight upload | Same ASC API page, "Issuer ID" shown at the top. |
| `ASC_API_KEY_P8` | iOS TestFlight upload | Download the `.p8` file when you create the key above (Apple lets you download it **once**). Paste the whole file contents, including the `-----BEGIN/END PRIVATE KEY-----` lines. This key must belong to the **Rainnworks** team (the one `apps/phone/app.json`'s `appleTeamId` already points at). |
| `IOS_TEAM_ID` | iOS TestFlight upload | `53W966FBFP` (Rainnworks, already in `apps/phone/app.json`). |
| `MAC_ASC_KEY_ID` | macOS notarization | Same App Store Connect page as above, but create this key under whichever Apple Developer account currently holds the `Latch` app's Developer ID Application certificate. Right now (see `fastlane/Fastfile`'s comment and task #35) that is **Rowm LTD**, not Rainnworks - check `security find-identity -v -p codesigning` on a Mac that has it if unsure. |
| `MAC_ASC_ISSUER_ID` | macOS notarization | Same page, "Issuer ID". |
| `MAC_ASC_API_KEY_P8` | macOS notarization | Same download-once `.p8` flow as `ASC_API_KEY_P8`, under the Rowm LTD account. |
| `MAC_TEAM_ID` | macOS notarization | The Rowm LTD team id (visible in the same ASC page, or `security find-identity -v -p codesigning` locally - it's the 10-character id in the cert name, e.g. `YK42U4LDMG`). |
| `CLOUDFLARE_API_TOKEN` | Relay Worker deploy | Cloudflare dashboard -> My Profile -> API Tokens -> Create Token -> "Edit Cloudflare Workers" template, scoped to the account that will host `latch-relay`. |
| `CLOUDFLARE_ACCOUNT_ID` | Relay Worker deploy | Cloudflare dashboard -> any Workers page -> Account ID shown in the right sidebar. |
| `APNS_KEY_P8` | Relay's push doorbell (not this pipeline - `wrangler secret put`, see below) | 1Password, Engineering vault, item `bs6pgv35lpazziews7zsvd6y7e` ("Latch APNs Auth Key, Key ID 5PCK76SDBA"). Get the document contents. |

`GITHUB_TOKEN` (GHCR push) needs no setup: GitHub injects it automatically,
and the workflow's `permissions: packages: write` is already granted.

### The one secret this pipeline does not set

`APNS_KEY_P8` is not a GitHub Actions secret at all - it is a Cloudflare
Worker secret, set once directly against the deployed Worker:

```sh
cd relay
npx wrangler secret put APNS_KEY_P8
```

`relay-deploy` in release.yml only runs `wrangler deploy`; it never touches
Worker secrets (see `relay/wrangler.jsonc`'s own comment on this - the key is
deliberately kept out of anything committed or CI-managed). Do this once,
by hand, after the first deploy; see `relay/DEPLOY.md` for the full runbook.

## Why two Apple Developer teams right now

The iOS app (`apps/phone`) already signs under Rainnworks (`53W966FBFP`,
`works.rainn.sigil` - see `apps/phone/app.json`). The macOS app
(`apps/mac`) still signs under the old Rowm LTD team (`co.rowm.latch` in
`apps/mac/project.yml`) - task #35 tracks migrating it. Until that lands,
`fastlane/Fastfile` and this checklist deliberately use separate
`MAC_ASC_*`/`MAC_TEAM_ID` secrets instead of reusing the iOS ones. Once #35
ships, point `MAC_*` at the same values as the iOS secrets and delete the
duplicates.

## Homebrew tap (optional, not automated)

`release.yml`'s `cli-release-assets` job renders `sigil.rb` (a Homebrew
formula for the `latch` + `latch-config` binaries, sha256-pinned to that
release's tarballs) and attaches it to the GitHub Release as an artifact.
Nothing in this pipeline pushes it anywhere. To make `brew install` work:

1. Create a new repo named `homebrew-tap` under the Rainnworks (or your)
   GitHub account/org - Homebrew's tap naming convention requires that exact
   prefix, e.g. `rainnworks/homebrew-tap`.
2. Add a `Formula/` directory.
3. After each release, copy the `sigil.rb` asset from the GitHub Release into
   `Formula/sigil.rb` in that repo and commit/push it.
4. `brew tap rainnworks/tap && brew install sigil` then works for anyone.

Steps 3 could be automated later (a small script or a workflow step that
pushes to the tap repo with a PAT that has write access to it), but that
needs a repo that does not exist yet, so it is left manual for now.

## What each artifact is and where it lands

| Artifact | Built by | Ships to |
|---|---|---|
| Sigil (iOS) | `fastlane ios beta` (`fastlane/Fastfile`) | TestFlight, internal testing group (no auto-submit to review - `skip_submission: true`) |
| Latch.dmg (macOS) | `fastlane mac release` (`fastlane/Fastfile`) | GitHub Release asset |
| `latch` + `latch-config` (CLI) | `scripts/release/package-cli.sh` | GitHub Release assets (`latch-<version>-<target>.tar.gz` + `.sha256`, both macOS archs) + a rendered, unpublished Homebrew formula |
| `latch-relay` (Worker) | `wrangler deploy` | Cloudflare, `latch-relay.<subdomain>.workers.dev` or your custom domain (see `relay/DEPLOY.md`) |
| `sigil-relay` (Docker image) | `docker/build-push-action` | `ghcr.io/<repo-owner>/sigil-relay:<tag>` and `:latest` |

## Local validation without secrets

Everything below runs clean with nothing configured:

```sh
# Rust
cargo test && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check

# Relay
cd relay && npm run typecheck && npm run typecheck:bun && npm run test && npm run test:bun

# Phone
cd apps/phone && bun run typecheck && bun run proto:selftest
cargo run -p latch-proto --bin export-vectors   # from repo root, before proto:vectors
cd apps/phone && bun run proto:vectors

# House-rule lint
python3 scripts/lint/house-rules.py --verbose

# Fastlane parses (lists both lanes, touches no Apple account)
cd fastlane && bundle install && bundle exec fastlane lanes

# Mac: exactly apps/mac/README.md's own unsigned build command
cd apps/mac && xcodegen generate && \
  xcodebuild -project Latch.xcodeproj -scheme Latch -configuration Debug \
    -destination 'platform=macOS' build CODE_SIGNING_ALLOWED=NO

# CLI packaging (uses your machine's own target, no cross-compile needed to smoke test)
./scripts/release/package-cli.sh "$(rustc -vV | sed -n 's/host: //p')" v0.0.0-test dist
```
