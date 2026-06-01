#!/usr/bin/env bash
# Run the edge proxy as a container with `docker run` — the docker equivalent of
# deploy/edge/edge.yaml, for hosts that run the edge outside Kubernetes (a VM, a
# bare-metal box near clients, etc.). It mirrors the manifest's env contract.
#
# This is a production-style launcher, NOT a test. It does not build anything and
# does not stand up a control plane or upstream — point it at a real, reachable
# control plane and parapet. The edge is a Go binary (cmd/edge-proxy).
#
# Required:
#   EDGE_CP_TOKEN     the edge's bearer token (authorizes its domains)
# Common (defaults match edge.yaml; override as needed):
#   EDGE_IMAGE        gcr.io/moonrhythm-containers/parapet-ingress-controller:edge-latest
#   EDGE_HTTPS_LISTEN 0.0.0.0:443      (container-internal; also the published port)
#   EDGE_HTTP_LISTEN  ""               plaintext listener; "" disables it (this
#                                      single-port launcher publishes only HTTPS)
#   EDGE_DOMAINS      ""               comma-separated SNIs this edge serves;
#                                      EMPTY = serve ALL domains (on-demand cert fetch)
#   EDGE_CP_ENDPOINT  https://controlplane:8443
#   EDGE_CP_CA        path to the CA cert that signs the control plane's server
#                     cert (mounted read-only); unset if the CP cert is publicly
#                     trusted or the CP runs plaintext http://
#   EDGE_UPSTREAM_ADDR parapet:80
#   EDGE_UPSTREAM_TLS  false
#   EDGE_UPSTREAM_SNI  ""              SNI to present to the upstream when re-encrypting
#   EDGE_REFRESH_INTERVAL  300
#   EDGE_WAF_ENABLED  true
#   WAF_GEOIP_DB      /geoip/ip-to-country.mmdb   (baked into the image; "" disables)
#   WAF_ASN_DB        /geoip/ip-to-asn.mmdb       (baked into the image; "" disables)
#   EDGE_METRICS_LISTEN  :9187        (Prometheus metrics; "" disables)
#   EDGE_NAME         parapet-edge     docker container name
#   DOCKER_RUN_ARGS   extra args inserted into `docker run` (e.g. "--network host")
#
# Usage:
#   EDGE_CP_TOKEN=… EDGE_DOMAINS=acme.com,www.acme.com EDGE_CP_CA=./ca.crt \
#     deploy/edge/run-edge-docker.sh
set -euo pipefail

EDGE_IMAGE="${EDGE_IMAGE:-gcr.io/moonrhythm-containers/parapet-ingress-controller:edge-latest}"
EDGE_NAME="${EDGE_NAME:-parapet-edge}"
EDGE_HTTPS_LISTEN="${EDGE_HTTPS_LISTEN:-0.0.0.0:443}"
EDGE_HTTP_LISTEN="${EDGE_HTTP_LISTEN:-}"
EDGE_DOMAINS="${EDGE_DOMAINS:-}"
EDGE_CP_ENDPOINT="${EDGE_CP_ENDPOINT:-https://controlplane:8443}"
EDGE_UPSTREAM_ADDR="${EDGE_UPSTREAM_ADDR:-parapet:80}"
EDGE_UPSTREAM_TLS="${EDGE_UPSTREAM_TLS:-false}"
EDGE_UPSTREAM_SNI="${EDGE_UPSTREAM_SNI:-}"
EDGE_REFRESH_INTERVAL="${EDGE_REFRESH_INTERVAL:-300}"
EDGE_WAF_ENABLED="${EDGE_WAF_ENABLED:-true}"
WAF_GEOIP_DB="${WAF_GEOIP_DB:-/geoip/ip-to-country.mmdb}"
WAF_ASN_DB="${WAF_ASN_DB:-/geoip/ip-to-asn.mmdb}"
EDGE_METRICS_LISTEN="${EDGE_METRICS_LISTEN-:9187}"

if [ -z "${EDGE_CP_TOKEN:-}" ]; then
  echo "EDGE_CP_TOKEN is required (the edge's bearer token)" >&2
  exit 1
fi

# Publish the host port matching the container's HTTPS listen port (host:container).
listen_port="${EDGE_HTTPS_LISTEN##*:}"

args=(
  run --rm --name "$EDGE_NAME"
  -p "${listen_port}:${listen_port}"
  -e EDGE_HTTPS_LISTEN="$EDGE_HTTPS_LISTEN"
  -e EDGE_HTTP_LISTEN="$EDGE_HTTP_LISTEN"
  -e EDGE_DOMAINS="$EDGE_DOMAINS"
  -e EDGE_CP_ENDPOINT="$EDGE_CP_ENDPOINT"
  -e EDGE_CP_TOKEN="$EDGE_CP_TOKEN"
  -e EDGE_UPSTREAM_ADDR="$EDGE_UPSTREAM_ADDR"
  -e EDGE_UPSTREAM_TLS="$EDGE_UPSTREAM_TLS"
  -e EDGE_UPSTREAM_SNI="$EDGE_UPSTREAM_SNI"
  -e EDGE_REFRESH_INTERVAL="$EDGE_REFRESH_INTERVAL"
  -e EDGE_WAF_ENABLED="$EDGE_WAF_ENABLED"
  -e WAF_GEOIP_DB="$WAF_GEOIP_DB"
  -e WAF_ASN_DB="$WAF_ASN_DB"
  -e EDGE_METRICS_LISTEN="$EDGE_METRICS_LISTEN"
)

# Mount the control-plane CA read-only and tell the edge where it is, if given.
if [ -n "${EDGE_CP_CA:-}" ]; then
  args+=( -v "$(cd "$(dirname "$EDGE_CP_CA")" && pwd)/$(basename "$EDGE_CP_CA"):/cp-ca/ca.crt:ro" )
  args+=( -e EDGE_CP_CA=/cp-ca/ca.crt )
fi

# Allow caller-supplied extra docker args (e.g. --network, --restart).
if [ -n "${DOCKER_RUN_ARGS:-}" ]; then
  # shellcheck disable=SC2206  # intentional word-split of caller-provided args
  args+=( ${DOCKER_RUN_ARGS} )
fi

exec docker "${args[@]}" "$EDGE_IMAGE"
