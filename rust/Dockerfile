# syntax=docker/dockerfile:1
#
# Multi-stage build for the Rust parapet-ingress-controller.
#
# Requires BuildKit — the `--mount=type=cache` steps below are rejected by the
# legacy builder. Build with BuildKit enabled (the default on modern Docker;
# set the env var or use buildx if your daemon defaults to the legacy builder):
#
#     DOCKER_BUILDKIT=1 docker build -t parapet-ingress-controller:rust rust/
#     # or: docker buildx build -t parapet-ingress-controller:rust rust/
#
# Build context is this `rust/` directory.
#
# The builder is Debian trixie (rust:1.95-trixie); the runtime is the matching
# distroless trixie image so the dynamically-linked OpenSSL (libssl3) and glibc
# ABIs line up between stages. `cc-debian13` ships glibc + libssl3 +
# ca-certificates + libgcc (the last is needed for Rust's panic=unwind) with no
# package manager or shell — much smaller than debian:trixie-slim and a smaller
# attack surface. Override with --build-arg RUNTIME_IMAGE=debian:trixie-slim if
# a shell is needed for debugging.

ARG RUST_VERSION=1.95
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:latest

# ---- builder ----
FROM rust:${RUST_VERSION}-trixie AS builder

# Native build dependencies:
#   pkg-config + libssl-dev : pingora's `openssl` TLS backend (dynamically linked)
#   cmake                   : libz-ng-sys (compression) and aws-lc-rs (rustls crypto)
#   clang, perl             : aws-lc-rs / aws-lc-sys build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake clang perl pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# The whole `rust/` workspace (all members must be present for cargo to resolve
# the workspace, even though only the controller binary is built). `target/` and
# the macOS-specific `.cargo/config.toml` are excluded via .dockerignore.
COPY . .

# Optional CPU baseline, mirroring the Go image's GOAMD64 v3/v1 split. CI passes
# e.g. `--build-arg TARGET_CPU=x86-64-v3` (or `x86-64` — the baseline level, Go's
# GOAMD64=v1 equivalent — for the compat image; LLVM has no "x86-64-v1").
# Left empty by default for a portable, generic-baseline build.
ARG TARGET_CPU=
ENV CARGO_TERM_COLOR=never
# BuildKit cache mounts for the cargo registry/git and the target dir, so
# rebuilds reuse fetched crates and compiled artifacts. Cache mounts are not
# part of the image layer, so the binary is copied out of the (cached) target
# dir to a real path for the runtime stage to pick up.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    if [ -n "$TARGET_CPU" ]; then export RUSTFLAGS="-C target-cpu=$TARGET_CPU"; fi; \
    cargo build --release --locked \
      -p parapet-ingress-controller \
      --features proxy,cluster \
      --bin parapet-ingress-controller \
    && cp target/release/parapet-ingress-controller /usr/local/bin/parapet-ingress-controller

# ---- optional GeoIP database ----
# Off by default. Set the edition flag and pass the MaxMind license key as a
# BuildKit secret to bake the .mmdb into the image:
#
#     docker build --build-arg GEOIP_EDITION=GeoLite2-Country \
#       --secret id=maxmind_license,env=MAXMIND_LICENSE_KEY -t img rust/
#
# then run with WAF_GEOIP_DB=/geoip/GeoLite2-Country.mmdb. The key is read from a
# secret mount, so it never lands in an image layer. Empty edition (default) bakes
# no DB but still creates /geoip so the COPY below always succeeds.
FROM debian:trixie-slim AS geoip
ARG GEOIP_EDITION=
RUN --mount=type=secret,id=maxmind_license \
    mkdir -p /geoip && \
    if [ -n "$GEOIP_EDITION" ]; then \
        apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
        curl -fsSL "https://download.maxmind.com/app/geoip_download?edition_id=${GEOIP_EDITION}&license_key=$(cat /run/secrets/maxmind_license)&suffix=tar.gz" -o /tmp/geoip.tar.gz && \
        tar -xzf /tmp/geoip.tar.gz -C /tmp && \
        find /tmp -name '*.mmdb' -exec mv {} /geoip/ \; && \
        ls -l /geoip; \
    fi

# ---- runtime ----
# distroless/cc already provides libssl3, ca-certificates, glibc and libgcc, so
# there is no apt step here (the image has no package manager). Runs as root
# (uid 0) to keep binding the privileged :80/:443 ports, matching the Go image.
FROM ${RUNTIME_IMAGE}

COPY --from=builder \
     /usr/local/bin/parapet-ingress-controller \
     /usr/local/bin/parapet-ingress-controller
COPY --from=geoip /geoip/ /geoip/

# HTTP, HTTPS, Prometheus
EXPOSE 80 443 9187

ENTRYPOINT ["/usr/local/bin/parapet-ingress-controller"]
