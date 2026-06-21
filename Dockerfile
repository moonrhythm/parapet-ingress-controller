# syntax=docker/dockerfile:1
#
# Ingress controller (Go). Pure Go (no CGO) — builds static and runs on
# distroless/static. Build context is the repo root.
#
# Multi-arch (linux/amd64 + linux/arm64): the build stage is pinned to
# $BUILDPLATFORM and Go cross-compiles to $TARGETARCH, so the arm64 image is
# produced WITHOUT QEMU emulation (pure-Go, CGO_ENABLED=0, cross-compiles
# natively on the runner). GOAMD64 is honored only for amd64 (Go ignores it when
# GOARCH=arm64). Build a multi-arch image with:
#
#     docker buildx build --platform linux/amd64,linux/arm64 -t parapet-ingress-controller .
FROM --platform=$BUILDPLATFORM golang:1.26.4-trixie AS build

ARG VERSION
ARG GOAMD64
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0
ENV GOAMD64=$GOAMD64

WORKDIR /workspace
ADD go.mod go.sum ./
RUN go mod download

ADD . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
		-o parapet-ingress-controller \
		-ldflags "-w -s -X main.version=$VERSION" \
		./cmd/parapet-ingress-controller

# GeoIP databases for the WAF, both baked by default from IPLocate's free MMDBs
# (CC BY-SA 4.0 — no account or license key, just keep the attribution to
# iplocate.io): ip-to-country (request.country, run with
# WAF_GEOIP_DB=/geoip/ip-to-country.mmdb) and ip-to-asn (request.asn, run with
# WAF_ASN_DB=/geoip/ip-to-asn.mmdb). The ip-to-asn DB is large (~74 MB) — pass
# --build-arg ASN_DB_URL= (empty) to skip it if you don't need request.asn.
# Override either URL to bake a different .mmdb; an empty value bakes none (the
# /geoip dir is still created so the COPY below always succeeds). Pinned to
# $BUILDPLATFORM: the MMDBs are arch-neutral data, so this stage runs on the
# native runner arch (no QEMU needed to curl them for an arm64 target build).
FROM --platform=$BUILDPLATFORM debian:trixie-slim AS geoip
ARG GEOIP_DB_URL=https://github.com/iplocate/ip-address-databases/raw/main/ip-to-country/ip-to-country.mmdb
ARG ASN_DB_URL=https://github.com/iplocate/ip-address-databases/raw/main/ip-to-asn/ip-to-asn.mmdb
RUN mkdir -p /geoip && \
	if [ -n "$GEOIP_DB_URL" ] || [ -n "$ASN_DB_URL" ]; then \
		apt-get update && apt-get -y install --no-install-recommends curl ca-certificates; \
	fi && \
	if [ -n "$GEOIP_DB_URL" ]; then curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 30 "$GEOIP_DB_URL" -o /geoip/ip-to-country.mmdb; fi && \
	if [ -n "$ASN_DB_URL" ]; then curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 30 "$ASN_DB_URL" -o /geoip/ip-to-asn.mmdb; fi && \
	ls -l /geoip

# ---- runtime ----
# distroless/static provides CA roots + tzdata; the default (root) variant — not
# :nonroot — so the controller can bind the privileged :443 / :80 ports.
FROM gcr.io/distroless/static-debian12

COPY --from=build /workspace/parapet-ingress-controller /app/parapet-ingress-controller
COPY --from=geoip /geoip/ /geoip/

ENTRYPOINT ["/app/parapet-ingress-controller"]
