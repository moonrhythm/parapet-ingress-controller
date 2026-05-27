# syntax=docker/dockerfile:1
FROM golang:1.26.3-trixie AS build

ARG VERSION
ARG GOAMD64

RUN apt-get update && \
	apt-get -y install libbrotli-dev

ENV CGO_ENABLED=1
ENV GOAMD64=$GOAMD64

WORKDIR /workspace
ADD go.mod go.sum ./
RUN go mod download

ADD . .
RUN go build \
		-o parapet-ingress-controller \
		-ldflags "-w -s -X main.version=$VERSION" \
		-tags=cbrotli \
		./cmd/parapet-ingress-controller

# GeoIP databases for the WAF. The ip-to-country DB (request.country) is baked by
# default from IPLocate's free MMDB (CC BY-SA 4.0 — no account or license key, just
# keep the attribution to iplocate.io); run with WAF_GEOIP_DB=/geoip/ip-to-country.mmdb.
# The ip-to-asn DB (request.asn) is opt-in — it is ~74 MB, so it is NOT baked unless
# you pass ASN_DB_URL; then run with WAF_ASN_DB=/geoip/ip-to-asn.mmdb. Override either
# URL to bake a different .mmdb, or pass an empty value to bake none (the /geoip dir
# is still created so the COPY below always succeeds).
#   docker build --build-arg ASN_DB_URL=https://github.com/iplocate/ip-address-databases/raw/main/ip-to-asn/ip-to-asn.mmdb -t img go/
FROM debian:trixie-slim AS geoip
ARG GEOIP_DB_URL=https://github.com/iplocate/ip-address-databases/raw/main/ip-to-country/ip-to-country.mmdb
ARG ASN_DB_URL=
RUN mkdir -p /geoip && \
	if [ -n "$GEOIP_DB_URL" ] || [ -n "$ASN_DB_URL" ]; then \
		apt-get update && apt-get -y install --no-install-recommends curl ca-certificates; \
	fi && \
	if [ -n "$GEOIP_DB_URL" ]; then curl -fsSL "$GEOIP_DB_URL" -o /geoip/ip-to-country.mmdb; fi && \
	if [ -n "$ASN_DB_URL" ]; then curl -fsSL "$ASN_DB_URL" -o /geoip/ip-to-asn.mmdb; fi && \
	ls -l /geoip

FROM debian:trixie-slim

RUN apt-get update && \
	apt-get -y install libbrotli1 ca-certificates && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /workspace/parapet-ingress-controller ./
COPY --from=geoip /geoip/ /geoip/
ENTRYPOINT ["/app/parapet-ingress-controller"]
