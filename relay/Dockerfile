# Sigil blind relay: Bun self-host image.
#
# Build with the relay/ directory itself as the build context, so nothing
# outside relay/ (the rest of the monorepo, crates/, apps/) ever enters the
# image:
#   cd relay && docker build -t sigil-relay .
# or via the accompanying docker-compose.yml, which already points its
# context here:
#   cd relay && docker compose up --build
#
# The relay has zero runtime npm dependencies: bun/server.ts and shared/*.ts
# import nothing but Bun and Web builtins (fetch, WebCrypto, node:fs). This
# stays a single minimal stage; there is no build step to separate out.

FROM oven/bun:1-slim

WORKDIR /app

# Copied first so `bun install` layer-caches independently of source edits.
COPY package.json package-lock.json ./
RUN bun install --production --frozen-lockfile

COPY bun ./bun
COPY shared ./shared
COPY landing.html ./landing.html

# The official Bun image ships a non-root "bun" user (uid 1000) for exactly
# this purpose; the relay never runs as root.
USER bun

ENV PORT=8787
EXPOSE 8787

# Liveness only; readiness is the same thing here, since the relay has no
# startup dependency (database, queue, external service) to warm up before
# GET /health means "ready to serve".
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["bun", "run", "bun/healthcheck.ts"]

CMD ["bun", "run", "bun/server.ts"]
