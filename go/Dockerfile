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

# Optional GeoIP database for the WAF's request.country. Off by default — set the
# edition flag and pass the MaxMind license key as a BuildKit secret to bake the
# .mmdb into the image:
#
#   docker build --build-arg GEOIP_EDITION=GeoLite2-Country \
#     --secret id=maxmind_license,env=MAXMIND_LICENSE_KEY -t img go/
#
# then run with WAF_GEOIP_DB=/geoip/GeoLite2-Country.mmdb. The key is read from a
# secret mount, so it never lands in an image layer. Empty edition (default) bakes
# no DB but still creates /geoip so the COPY below always succeeds.
FROM debian:trixie-slim AS geoip
ARG GEOIP_EDITION=
RUN --mount=type=secret,id=maxmind_license \
	mkdir -p /geoip && \
	if [ -n "$GEOIP_EDITION" ]; then \
		apt-get update && apt-get -y install --no-install-recommends curl ca-certificates && \
		curl -fsSL "https://download.maxmind.com/app/geoip_download?edition_id=${GEOIP_EDITION}&license_key=$(cat /run/secrets/maxmind_license)&suffix=tar.gz" -o /tmp/geoip.tar.gz && \
		tar -xzf /tmp/geoip.tar.gz -C /tmp && \
		find /tmp -name '*.mmdb' -exec mv {} /geoip/ \; && \
		ls -l /geoip; \
	fi

FROM debian:trixie-slim

RUN apt-get update && \
	apt-get -y install libbrotli1 ca-certificates && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /workspace/parapet-ingress-controller ./
COPY --from=geoip /geoip/ /geoip/
ENTRYPOINT ["/app/parapet-ingress-controller"]
