#!/usr/bin/env bash
# Cross-component end-to-end smoke test for the edge + control plane, with NO
# Kubernetes cluster. It wires the REAL binaries together:
#
#   client --TLS--> go edge --(fetches cert+key + WAF rules)--> go control plane
#                      │                                              (fs backend)
#                      └--(forwards, if not WAF-blocked)--> dummy upstream ("parapet")
#
# It proves:
#   Phase 1 — the edge fetches a cert+key it does NOT have locally from the
#     control plane (bearer-authorized), terminates TLS with it, forwards upstream.
#   Phase 2 — the edge fetches the GLOBAL WAF ruleset and blocks a matching
#     request at the edge (early drop) before it reaches the upstream.
#   Phase 3 — a tenant ZONE bound to the host (via an Ingress annotation) blocks
#     at the edge (host->zone resolution + zone distribution).
#   Phase 4 — the optional disk-backed response cache serves a cacheable object
#     locally on the second request (X-Cache: MISS then HIT).
#
# Both the edge and the control plane are Go binaries (cmd/edge-proxy and
# cmd/edge-controlplane). The control plane reads cert + WAF ConfigMap from
# static manifests via KUBERNETES_BACKEND=fs, so no cluster is needed.
#
# Usage:  deploy/edge/e2e/run.sh
# Requires: openssl, curl, python3, nc, and a Go toolchain. Exit 0 = pass.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$(mktemp -d)"
CP_PORT=18443
CP_METRICS_PORT=18187
EDGE_PORT=18080
EDGE_HTTP_PORT=18081
UP_PORT=18090
TOKEN="e2e-secret-token"
DOMAIN="test.local"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

wait_for_port() {
  local port="$1" name="$2" i
  for i in $(seq 1 50); do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  # Surface the process logs so a startup crash is diagnosable in CI (not just a
  # bare "did not come up").
  for log in "$WORK/cp.log" "$WORK/edge.log" "$WORK/upstream.log"; do
    [ -s "$log" ] && { echo "----- $(basename "$log") -----" >&2; cat "$log" >&2; }
  done
  fail "$name did not come up on :$port"
}

# ---------------------------------------------------------------------------
say "1. generate test PKI (CA, control-plane server cert, $DOMAIN leaf)"
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
gen_cert cp localhost      # control-plane HTTPS server cert
gen_cert leaf "$DOMAIN"    # the cert the edge will fetch + serve for $DOMAIN

# A dedicated edge CA (provided mode) so the CP loads a signer and exposes the
# convergence metrics (parapet_edge_ca_signer_fingerprint) on its /metrics listener.
# Use an explicit -config (NOT -addext): -addext APPENDS to the system openssl.cnf's
# default x509 extensions, so on distros whose default already adds basicConstraints
# the cert ends up with a DUPLICATE basicConstraints, which Go 1.26's x509 parser
# rejects. A self-contained config sets each extension exactly once.
cat > "$WORK/edge-ca.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = parapet-edge-ca
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = clientAuth
CNF
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/edge-ca.key" -out "$WORK/edge-ca.crt" -days 1 \
  -config "$WORK/edge-ca.cnf" 2>/dev/null

# ---------------------------------------------------------------------------
say "2. write static manifests (TLS Secret + global WAF ConfigMap) + tokens.json"
mkdir -p "$WORK/manifests"
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
# Global WAF baseline: block /blocked. Namespace "default" matches POD_NAMESPACE
# below (the global-ruleset boundary); label marks it as the global role.
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
# A tenant ZONE (label=zone) in namespace "default" → zone key "default/myzone".
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
# An Ingress binds $DOMAIN to that zone via the waf-zone annotation (bare id →
# same-namespace zone "default/myzone"). The control plane derives host→zoneKey.
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
printf '{"%s":["%s"]}' "$TOKEN" "$DOMAIN" > "$WORK/tokens.json"

# ---------------------------------------------------------------------------
say "3. build binaries (Go edge + Go control plane)"
( cd "$REPO" && go build -o "$WORK/edge-controlplane" ./cmd/edge-controlplane ) \
  || fail "go build control plane"
( cd "$REPO" && go build -o "$WORK/parapet-edge" ./cmd/edge-proxy ) \
  || fail "go build edge"
# Dummy upstream is a Go h2c-capable origin (stands in for parapet's H2C=true :80),
# so the edge's default h2c upstream hop is actually exercised end-to-end.
( cd "$REPO" && go build -o "$WORK/upstream" ./deploy/edge/e2e/upstream ) \
  || fail "go build upstream"

# ---------------------------------------------------------------------------
say "4. start dummy upstream (Go h2c origin, stands in for parapet)"
UPSTREAM_ADDR="127.0.0.1:$UP_PORT" "$WORK/upstream" > "$WORK/upstream.log" 2>&1 & PIDS+=($!)
wait_for_port "$UP_PORT" upstream

say "5. start the Go control plane (fs backend, WAF enabled)"
KUBERNETES_BACKEND=fs KUBERNETES_FS="$WORK/manifests" \
  CP_LISTEN=":$CP_PORT" CP_METRICS_LISTEN="127.0.0.1:$CP_METRICS_PORT" \
  CP_TLS_CERT="$WORK/cp.crt" CP_TLS_KEY="$WORK/cp.key" \
  CP_TOKENS_FILE="$WORK/tokens.json" WATCH_NAMESPACE="" \
  POD_NAMESPACE=default CP_WAF_ENABLED=true \
  EDGE_CA_CERT="$WORK/edge-ca.crt" EDGE_CA_KEY="$WORK/edge-ca.key" \
  "$WORK/edge-controlplane" > "$WORK/cp.log" 2>&1 & PIDS+=($!)
wait_for_port "$CP_PORT" "control plane"

say "6. start the Go edge (fetches cert + WAF rules; GeoIP from fixture DB; cache on)"
# Point the edge at the conformance GeoIP fixtures so request.country resolves at
# the edge. Loopback (127.0.0.1) is unmapped in the country fixture → "XX".
EDGE_HTTPS_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_HTTP_LISTEN="127.0.0.1:$EDGE_HTTP_PORT" \
  EDGE_METRICS_LISTEN="" \
  EDGE_CP_ENDPOINT="https://localhost:$CP_PORT" EDGE_CP_TOKEN="$TOKEN" \
  EDGE_CP_CA="$WORK/ca.crt" EDGE_DOMAINS="$DOMAIN" \
  EDGE_UPSTREAM_ADDR="127.0.0.1:$UP_PORT" EDGE_UPSTREAM_TLS=false \
  EDGE_WAF_ENABLED=true \
  EDGE_CACHE_ENABLED=true EDGE_CACHE_DIR="$WORK/cache" \
  WAF_GEOIP_DB="$REPO/conformance/geoip/iplocate-country.mmdb" \
  WAF_ASN_DB="$REPO/conformance/geoip/iplocate-asn.mmdb" \
  "$WORK/parapet-edge" > "$WORK/edge.log" 2>&1 & PIDS+=($!)
wait_for_port "$EDGE_PORT" edge
wait_for_port "$EDGE_HTTP_PORT" "edge http"

# ---------------------------------------------------------------------------
say "7. assertions"
# Phase 1: a normal request terminates TLS with the fetched cert and reaches upstream.
OUT="$(curl -sS -D "$WORK/https.hdr" --cacert "$WORK/ca.crt" --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" \
  "https://$DOMAIN:$EDGE_PORT/" 2>"$WORK/curl.err")" \
  || { cat "$WORK/curl.err" "$WORK/edge.log" "$WORK/cp.log" >&2; fail "curl through edge failed"; }
[ "$OUT" = "hello-from-upstream" ] || fail "unexpected body for /: $OUT"
# The TLS listener must forward X-Forwarded-Proto: https (echoed back by upstream).
grep -qiE "^x-seen-forwarded-proto: https[[:space:]]*$" "$WORK/https.hdr" \
  || { cat "$WORK/https.hdr" >&2; fail "TLS listener did not forward X-Forwarded-Proto: https"; }
# The edge→upstream hop defaults to h2c (EDGE_UPSTREAM_HTTP2 unset ⇒ on); the upstream
# echoes the HTTP major version it saw, so 2 proves h2c was negotiated by default.
grep -qiE "^x-seen-proto-major: 2[[:space:]]*$" "$WORK/https.hdr" \
  || { cat "$WORK/https.hdr" >&2; fail "edge did not forward to upstream over h2c (want proto-major 2)"; }
echo "  ✓ TLS terminated with control-plane-fetched cert; / forwarded to upstream over h2c (proto=https)"

# Phase 1b: the plaintext HTTP listener forwards to upstream WITHOUT redirecting,
# tagging the hop X-Forwarded-Proto: http so the in-cluster core (not the edge)
# owns the http→https redirect decision.
HTTP_OUT="$(curl -sS -D "$WORK/http.hdr" -H "Host: $DOMAIN" \
  "http://127.0.0.1:$EDGE_HTTP_PORT/" 2>"$WORK/curlhttp.err")" \
  || { cat "$WORK/curlhttp.err" "$WORK/edge.log" >&2; fail "curl through edge HTTP listener failed"; }
[ "$HTTP_OUT" = "hello-from-upstream" ] || fail "unexpected body over http: $HTTP_OUT"
grep -qiE "^x-seen-forwarded-proto: http[[:space:]]*$" "$WORK/http.hdr" \
  || { cat "$WORK/http.hdr" >&2; fail "HTTP listener did not forward X-Forwarded-Proto: http"; }
grep -qiE "^x-seen-proto-major: 2[[:space:]]*$" "$WORK/http.hdr" \
  || { cat "$WORK/http.hdr" >&2; fail "edge did not forward to upstream over h2c (want proto-major 2)"; }
echo "  ✓ plaintext HTTP listener forwarded to upstream over h2c (proto=http, no edge redirect)"

# Phase 2: the global WAF rule blocks /blocked AT THE EDGE with 403 (never upstream).
CODE="$(curl -s -o "$WORK/blocked.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" "https://$DOMAIN:$EDGE_PORT/blocked")" \
  || fail "curl /blocked failed"
[ "$CODE" = "403" ] || { cat "$WORK/edge.log" >&2; fail "/blocked: want 403, got $CODE"; }
grep -q "blocked-by-edge-waf" "$WORK/blocked.body" || fail "/blocked: missing WAF message body"
echo "  ✓ global WAF blocked /blocked at the edge (403, custom message)"

# And a non-matching path is still allowed through.
OUT2="$(curl -sS --cacert "$WORK/ca.crt" --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" \
  "https://$DOMAIN:$EDGE_PORT/allowed")"
[ "$OUT2" = "hello-from-upstream" ] || fail "non-matching path unexpectedly blocked: $OUT2"
echo "  ✓ non-matching path still forwarded (WAF is selective)"

# Phase 2 GeoIP: the edge resolves request.country from its own DB (loopback → XX),
# so the country rule fires AT THE EDGE — proving GeoIP works edge-side.
GEO="$(curl -s -o "$WORK/geo.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" "https://$DOMAIN:$EDGE_PORT/geo")" \
  || fail "curl /geo failed"
[ "$GEO" = "403" ] || { cat "$WORK/edge.log" >&2; fail "/geo (country XX): want 403, got $GEO"; }
grep -q "blocked-by-geo" "$WORK/geo.body" || fail "/geo: missing geo WAF message"
echo "  ✓ edge GeoIP resolved request.country (XX) → country rule blocked /geo"

# Phase 3: the zone bound to $DOMAIN (via the Ingress annotation) blocks
# /zoneblocked AT THE EDGE — proving zone distribution + host→zone resolution.
ZONE="$(curl -s -o "$WORK/zone.body" -w '%{http_code}' --cacert "$WORK/ca.crt" \
  --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" "https://$DOMAIN:$EDGE_PORT/zoneblocked")" \
  || fail "curl /zoneblocked failed"
[ "$ZONE" = "403" ] || { cat "$WORK/edge.log" >&2; fail "/zoneblocked: want 403, got $ZONE"; }
grep -q "blocked-by-zone" "$WORK/zone.body" || fail "/zoneblocked: missing zone WAF message"
echo "  ✓ tenant zone (host→zone bound) blocked /zoneblocked at the edge"

# Phase 4: the disk cache serves a cacheable object locally on the 2nd request.
curl -s -D "$WORK/c1.hdr" --cacert "$WORK/ca.crt" --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" \
  "https://$DOMAIN:$EDGE_PORT/cacheme" >/dev/null || fail "curl /cacheme (1) failed"
grep -qiE "^x-cache: MISS[[:space:]]*$" "$WORK/c1.hdr" \
  || { cat "$WORK/c1.hdr" >&2; fail "first /cacheme should be X-Cache: MISS"; }
curl -s -D "$WORK/c2.hdr" --cacert "$WORK/ca.crt" --resolve "$DOMAIN:$EDGE_PORT:127.0.0.1" \
  "https://$DOMAIN:$EDGE_PORT/cacheme" >/dev/null || fail "curl /cacheme (2) failed"
grep -qiE "^x-cache: HIT[[:space:]]*$" "$WORK/c2.hdr" \
  || { cat "$WORK/c2.hdr" >&2; fail "second /cacheme should be X-Cache: HIT"; }
echo "  ✓ disk cache served /cacheme from the edge on the 2nd request (MISS→HIT)"

# Negative: unknown SNI serves the self-signed fallback (CA validation must fail).
if curl -sf --cacert "$WORK/ca.crt" --resolve "other.local:$EDGE_PORT:127.0.0.1" \
     "https://other.local:$EDGE_PORT/" >/dev/null 2>&1; then
  fail "unknown SNI unexpectedly validated against our CA"
fi
echo "  ✓ unknown SNI falls back to self-signed (not served the real cert)"

# Convergence metrics: the CP exposes /metrics on a SEPARATE, unauthenticated
# listener (no bearer token), and with a signer loaded it publishes the
# signer-fingerprint series — so a scraper can detect which CA the CP signs under.
# This guards against an unwired/zero-target CP showing a false-green convergence board.
say "8. CP convergence /metrics (separate listener, signer fingerprint present)"
wait_for_port "$CP_METRICS_PORT" "cp metrics"
MET="$(curl -sS "http://127.0.0.1:$CP_METRICS_PORT/metrics")" \
  || { cat "$WORK/cp.log" >&2; fail "curl CP /metrics failed"; }
grep -q "parapet_edge_ca_signer_fingerprint{" <<<"$MET" \
  || { grep parapet_edge <<<"$MET" >&2; fail "CP /metrics missing signer_fingerprint series"; }
grep -qE "^parapet_edge_ca_signer_loaded 1$" <<<"$MET" \
  || { grep signer_loaded <<<"$MET" >&2; fail "CP signer_loaded != 1"; }
echo "  ✓ CP /metrics (tokenless) serves signer_fingerprint + signer_loaded=1"

# Force-re-mint signal: GET /v1/certs carries the X-Parapet-CA-Id header (the universal
# proactive carrier that rides the edge's existing cert poll on EVERY arm, incl. 304/404).
# Assert it is present and equals the signer fingerprint from /metrics — so a CA rotation
# would be observable by every edge regardless of WAF/serve-all mode.
say "9. force-re-mint signal: /v1/certs advertises X-Parapet-CA-Id"
SIG_CAID="$(grep -oE 'parapet_edge_ca_signer_fingerprint\{ca_id="[^"]+"' <<<"$MET" | grep -oE 'ca_id="[^"]+"' | cut -d'"' -f2)"
[ -n "$SIG_CAID" ] || fail "could not read signer ca_id from /metrics"
CERT_CAID="$(curl -sS -D - -o /dev/null --cacert "$WORK/ca.crt" -H "Authorization: Bearer $TOKEN" \
  --resolve "localhost:$CP_PORT:127.0.0.1" "https://localhost:$CP_PORT/v1/certs?sni=$DOMAIN" \
  | grep -i '^x-parapet-ca-id:' | tr -d '\r' | awk '{print $2}')"
[ "$CERT_CAID" = "$SIG_CAID" ] \
  || { echo "cert-arm ca_id='$CERT_CAID' signer ca_id='$SIG_CAID'" >&2; fail "/v1/certs X-Parapet-CA-Id missing or != signer ca_id"; }
echo "  ✓ /v1/certs advertises X-Parapet-CA-Id ($CERT_CAID) matching the signer"

# Active-signer fingerprint signal (the revoke interlock's load-bearing axis): the ca_id is
# identical for active=OLD/NEW during an overlap, so the edge re-mints + the OLD-drop gates
# on the SIGNER fp, not the ca_id. Assert the live binary advertises it on /v1/certs (header)
# AND the tokenless trust bundle (body), both equal to parapet_edge_ca_active_signer_fp.
say "10. active-signer fp signal: /v1/certs + /v1/trust-bundle advertise signing_cert_fp"
SIG_FP="$(grep -oE 'parapet_edge_ca_active_signer_fp\{[^}]*sigfp="[^"]+"' <<<"$MET" | grep -oE 'sigfp="[^"]+"' | cut -d'"' -f2)"
[ -n "$SIG_FP" ] || { grep parapet_edge_ca_active <<<"$MET" >&2; fail "could not read active signer fp from /metrics"; }
CERT_FP="$(curl -sS -D - -o /dev/null --cacert "$WORK/ca.crt" -H "Authorization: Bearer $TOKEN" \
  --resolve "localhost:$CP_PORT:127.0.0.1" "https://localhost:$CP_PORT/v1/certs?sni=$DOMAIN" \
  | grep -i '^x-parapet-signing-cert-fp:' | tr -d '\r' | awk '{print $2}')"
[ "$CERT_FP" = "$SIG_FP" ] \
  || { echo "cert-arm fp='$CERT_FP' signer fp='$SIG_FP'" >&2; fail "/v1/certs X-Parapet-Signing-Cert-Fp missing or != active signer fp"; }
TB_FP="$(curl -sS --cacert "$WORK/ca.crt" --resolve "localhost:$CP_PORT:127.0.0.1" \
  "https://localhost:$CP_PORT/v1/trust-bundle" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("signing_cert_fp",""))')"
[ "$TB_FP" = "$SIG_FP" ] \
  || { echo "trust-bundle fp='$TB_FP' signer fp='$SIG_FP'" >&2; fail "/v1/trust-bundle signing_cert_fp missing or != active signer fp"; }
echo "  ✓ /v1/certs + /v1/trust-bundle advertise signing_cert_fp ($SIG_FP) matching the active signer"

say "E2E PASSED"
