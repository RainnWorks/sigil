# Sigil native relay: a static musl binary in a scratch image.
#
# Build from the REPO ROOT so the whole workspace and relay/landing.html are in
# context (the crate include_str!'s the landing page from ../../relay):
#
#   docker build -f crates/sigil-relay/Dockerfile -t sigil-relay .
#   docker run --rm -p 8787:8787 sigil-relay
#
# The result is a single static binary in `scratch`: no shell, no libc, no
# package manager, nothing else. Docker still bind-mounts /etc/resolv.conf at
# runtime so DNS works, and the TLS roots are bundled via webpki-roots, so the
# APNs/knock HTTPS path needs no system CA bundle.

# ---- build stage: static musl binary ----
# rust:1-alpine is musl-native, so the default host target already links
# crt-static. build-base/musl-dev provide the C toolchain `ring` (rustls) needs.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src

# Copy the whole workspace. .dockerignore (at the repo root) keeps target/,
# .git/, and node_modules out of the build context.
COPY . .

# --locked builds against the committed Cargo.lock for a reproducible resolve.
RUN cargo build --release --locked -p sigil-relay \
    && cp target/release/sigil-relay /sigil-relay \
    && strip /sigil-relay || true

# ---- runtime stage: nothing but the binary ----
FROM scratch
COPY --from=build /sigil-relay /sigil-relay
ENV PORT=8787
EXPOSE 8787
ENTRYPOINT ["/sigil-relay"]
