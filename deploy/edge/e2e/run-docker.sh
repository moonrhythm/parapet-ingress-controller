#!/usr/bin/env bash
# Cross-language end-to-end smoke test for the edge + control plane, run entirely
# as CONTAINERS via `docker run` — exercising the actual shipped images
# (go/Dockerfile.edge-controlplane + rust/Dockerfile.edge), not local binaries.
# It is the docker-native sibling of run.sh and asserts the exact same behavior:
#
#   client --TLS--> edge container --(fetch cert+key + WAF)--> controlplane container
#                       │                                            (fs backend)
#                       └--(forward, if not WAF-blocked)--> upstream container ("parapet")
#
# Phases proved (identical to run.sh):
#   1 cert+key distribution + local TLS termination + forwarding
#   2 global WAF early-drop (+ GeoIP request.country at the edge)
#   3 tenant zone bound by host
#
# All three services share a user-defined Docker network and reach each other by
# container name (controlplane / upstream). Host-published ports are only for the
# readiness polls and the test client's curls.
#
# Usage:  deploy/edge/e2e/run-docker.sh
# Env:
#   EDGE_E2E_BUILD=0          reuse existing images instead of building (default: build)
#   CP_IMAGE / EDGE_IMAGE     override image tags (default: parapet-edge-controlplane:e2e / parapet-edge:e2e)
# Requires: docker (with BuildKit), openssl, curl, nc. Exit 0 = pass.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$(mktemp -d)"
NET="parapet-edge-e2e-$$"
CP_NAME="cp-e2e-$$"
EDGE_NAME="edge-e2e-$$"
UP_NAME="up-e2e-$$"
CP_IMAGE="${CP_IMAGE:-parapet-edge-controlplane:e2e}"
EDGE_IMAGE="${EDGE_IMAGE:-parapet-edge:e2e}"
BUILD="${EDGE_E2E_BUILD:-1}"
# Host-published ports (readiness polls + client curls). Container-internal ports
# are fixed: controlplane 8443, edge 443, upstream 80.
CP_HOSTPORT=18444
EDGE_HOSTPORT=18081
TOKEN="e2e-secret-token"
DOMAIN="test.local"

cleanup() {
  docker rm -f "$EDGE_NAME" "$CP_NAME" "$UP_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }
fail() {
  printf '\nFAIL: %s\n' "$*" >&2
  echo "--- controlplane logs ---" >&2; docker logs "$CP_NAME" 2>&1 | tail -30 >&2 || true
  echo "--- edge logs ---" >&2; docker logs "$EDGE_NAME" 2>&1 | tail -30 >&2 || true
  exit 1
}

wait_for_port() {
  local port="$1" name="$2" i
  for i in $(seq 1 100); do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then return 0; fi
    sleep 0.3
  done
  fail "$name did not come up on 127.0.0.1:$port"
}

command -v docker >/dev/null 2>&1 || fail "docker not found"

# ---------------------------------------------------------------------------
say "1. generate test PKI (CA, controlplane server cert [SAN=controlplane], $DOMAIN leaf)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 1 -subj "/CN=e2e-ca" 2>/dev/null

gen_cert() { # name CN  -> name.key/name.crt signed by the CA, SAN=CN
  local name="$1" cn="$2"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/$name.key" -out "$WORK/$name.csr" -subj "/CN=$cn" 2>/dev/null
  openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=DNS:%s' "$cn") \
    -out "$WORK/$name.crt" 2>/dev/null
}
# The edge dials the control plane by its container name, so the CP server cert
# must be valid for `controlplane` (not localhost as in the binary script).
gen_cert cp controlplane
gen_cert leaf "$DOMAIN"

# ---------------------------------------------------------------------------
say "2. write static manifests (TLS Secret + global + zone ConfigMaps + Ingress) + tokens.json"
mkdir -p "$WORK/manifests" "$WORK/tls" "$WORK/tokens" "$WORK/ca"
cp "$WORK/cp.crt" "$WORK/tls/cp.crt"; cp "$WORK/cp.key" "$WORK/tls/cp.key"
cp "$WORK/ca.crt" "$WORK/ca/ca.crt"
b64() { base64 < "$1" | tr -d '\n'; }
cat > "$WORK/manifests/leaf-secret.yaml" <<EOF
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: leaf-tls
  namespace: default
data:
  tls.crt: $(b64 "$WORK/leaf.crt")
  tls.key: $(b64 "$WORK/leaf.key")
EOF
cat > "$WORK/manifests/waf-global.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-global
  namespace: default
  labels:
    parapet.moonrhythm.io/waf: global
data:
  rules.yaml: |
    rules:
      - id: block-test-path
        expression: request.path == "/blocked"
        action: block
        status: 403
        message: blocked-by-edge-waf
      - id: block-geo-on-path
        expression: request.path == "/geo" && request.country == "XX"
        action: block
        status: 403
        message: blocked-by-geo
EOF
cat > "$WORK/manifests/waf-zone.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: myzone
  namespace: default
  labels:
    parapet.moonrhythm.io/waf: zone
data:
  rules.yaml: |
    rules:
      - id: zone-block-path
        expression: request.path == "/zoneblocked"
        action: block
        status: 403
        message: blocked-by-zone
EOF
cat > "$WORK/manifests/ingress.yaml" <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: default
  annotations:
    parapet.moonrhythm.io/waf-zone: myzone
spec:
  rules:
    - host: $DOMAIN
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
EOF
printf '{"%s":["%s"]}' "$TOKEN" "$DOMAIN" > "$WORK/tokens/tokens.json"
# The control-plane image runs as the distroless `nonroot` uid, which can't read
# the 0700 mktemp dir or host-owned files. Make the mounted material world-readable
# (acceptable: ephemeral test keys in a temp dir we delete on exit).
chmod -R a+rX "$WORK"

# ---------------------------------------------------------------------------
if [ "$BUILD" = "1" ]; then
  say "3. build images (DOCKER_BUILDKIT=1)"
  DOCKER_BUILDKIT=1 docker build -f "$REPO/go/Dockerfile.edge-controlplane" \
    -t "$CP_IMAGE" "$REPO/go" || fail "build control-plane image"
  # The Rust edge build compiles the workspace from source — this is the slow step.
  DOCKER_BUILDKIT=1 docker build -f "$REPO/rust/Dockerfile.edge" \
    -t "$EDGE_IMAGE" "$REPO/rust" || fail "build edge image"
else
  say "3. reuse existing images ($CP_IMAGE, $EDGE_IMAGE)"
fi

# ---------------------------------------------------------------------------
say "4. create network + start upstream (stands in for parapet)"
docker network create "$NET" >/dev/null
docker run -d --name "$UP_NAME" --network "$NET" --network-alias upstream \
  python:3-alpine python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'hello-from-upstream'
        self.send_response(200); self.send_header('content-length',str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self,*a): pass
socketserver.TCPServer(('0.0.0.0',80),H).serve_forever()
" >/dev/null || fail "start upstream"

say "5. start the control-plane container (fs backend, WAF enabled)"
docker run -d --name "$CP_NAME" --network "$NET" --network-alias controlplane \
  -p "127.0.0.1:$CP_HOSTPORT:8443" \
  -v "$WORK/manifests:/manifests:ro" -v "$WORK/tls:/tls:ro" -v "$WORK/tokens:/tokens:ro" \
  -e KUBERNETES_BACKEND=fs -e KUBERNETES_FS=/manifests \
  -e CP_LISTEN=:8443 -e CP_TLS_CERT=/tls/cp.crt -e CP_TLS_KEY=/tls/cp.key \
  -e CP_TOKENS_FILE=/tokens/tokens.json -e WATCH_NAMESPACE="" \
  -e POD_NAMESPACE=default -e CP_WAF_ENABLED=true \
  "$CP_IMAGE" >/dev/null || fail "start control plane"
wait_for_port "$CP_HOSTPORT" "control plane"

say "6. start the edge container (fetches cert + WAF; GeoIP from fixture DB)"
# Mount the conformance GeoIP fixtures and point the edge at them so request.country
# is deterministic. The client IP the edge sees is a private/unmapped address → "XX".
docker run -d --name "$EDGE_NAME" --network "$NET" --network-alias edge \
  -p "127.0.0.1:$EDGE_HOSTPORT:443" \
  -v "$WORK/ca:/ca:ro" -v "$REPO/conformance/geoip:/geoip-fixtures:ro" \
  -e EDGE_LISTEN=0.0.0.0:443 \
  -e EDGE_CP_ENDPOINT="https://controlplane:8443" -e EDGE_CP_TOKEN="$TOKEN" \
  -e EDGE_CP_CA=/ca/ca.crt -e EDGE_DOMAINS="$DOMAIN" \
  -e EDGE_PARAPET_ADDR="upstream:80" -e EDGE_PARAPET_TLS=false \
  -e EDGE_WAF_ENABLED=true \
  -e WAF_GEOIP_DB=/geoip-fixtures/iplocate-country.mmdb \
  -e WAF_ASN_DB=/geoip-fixtures/iplocate-asn.mmdb \
  -e RUST_LOG=info \
  "$EDGE_IMAGE" >/dev/null || fail "start edge"
wait_for_port "$EDGE_HOSTPORT" edge

# ---------------------------------------------------------------------------
say "7. assertions"
EP="$DOMAIN:$EDGE_HOSTPORT"
RESOLVE="--resolve $EP:127.0.0.1"

# Phase 1: a normal request terminates TLS with the fetched cert and reaches upstream.
OUT="$(curl -sS --cacert "$WORK/ca.crt" $RESOLVE "https://$EP/" 2>"$WORK/curl.err")" \
  || { cat "$WORK/curl.err" >&2; fail "curl through edge failed"; }
[ "$OUT" = "hello-from-upstream" ] || fail "unexpected body for /: $OUT"
echo "  ✓ TLS terminated with control-plane-fetched cert; / forwarded to upstream"

# Phase 2: the global WAF rule blocks /blocked AT THE EDGE with 403 (never upstream).
CODE="$(curl -s -o "$WORK/blocked.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  $RESOLVE "https://$EP/blocked")" || fail "curl /blocked failed"
[ "$CODE" = "403" ] || fail "/blocked: want 403, got $CODE"
grep -q "blocked-by-edge-waf" "$WORK/blocked.body" || fail "/blocked: missing WAF message body"
echo "  ✓ global WAF blocked /blocked at the edge (403, custom message)"

# A non-matching path is still allowed through.
OUT2="$(curl -sS --cacert "$WORK/ca.crt" $RESOLVE "https://$EP/allowed")"
[ "$OUT2" = "hello-from-upstream" ] || fail "non-matching path unexpectedly blocked: $OUT2"
echo "  ✓ non-matching path still forwarded (WAF is selective)"

# Phase 2 GeoIP: the edge resolves request.country from its own DB (private IP → XX).
GEO="$(curl -s -o "$WORK/geo.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  $RESOLVE "https://$EP/geo")" || fail "curl /geo failed"
[ "$GEO" = "403" ] || fail "/geo (country XX): want 403, got $GEO"
grep -q "blocked-by-geo" "$WORK/geo.body" || fail "/geo: missing geo WAF message"
echo "  ✓ edge GeoIP resolved request.country (XX) → country rule blocked /geo"

# Phase 3: the zone bound to $DOMAIN (via the Ingress annotation) blocks /zoneblocked.
ZONE="$(curl -s -o "$WORK/zone.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  $RESOLVE "https://$EP/zoneblocked")" || fail "curl /zoneblocked failed"
[ "$ZONE" = "403" ] || fail "/zoneblocked: want 403, got $ZONE"
grep -q "blocked-by-zone" "$WORK/zone.body" || fail "/zoneblocked: missing zone WAF message"
echo "  ✓ tenant zone (host→zone bound) blocked /zoneblocked at the edge"

# Negative: unknown SNI serves the self-signed fallback (CA validation must fail).
if curl -sf --cacert "$WORK/ca.crt" --resolve "other.local:$EDGE_HOSTPORT:127.0.0.1" \
     "https://other.local:$EDGE_HOSTPORT/" >/dev/null 2>&1; then
  fail "unknown SNI unexpectedly validated against our CA"
fi
echo "  ✓ unknown SNI falls back to self-signed (not served the real cert)"

say "E2E PASSED (docker)"
