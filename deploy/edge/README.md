# Edge deployment

Manifests for the out-of-cluster **edge proxy** + in-cluster **edge control
plane**. Design and contract: [`../../EDGE.md`](../../EDGE.md).

- `controlplane.yaml` — the Go control plane (`Deployment` + `ClusterIP Service`
  + `NetworkPolicy`). Runs in the controller's namespace, reuses its
  ServiceAccount (needs `get/list/watch secrets`). **Distributes private keys** —
  ClusterIP only, locked to edge source IPs; never on the public LB.
- `edge.yaml` — the Go edge proxy (`Deployment` + `LoadBalancer Service`).
  Terminates public TLS; the public-facing tier. (Migrated off Rust/Pingora; the
  image is now built from `Dockerfile.edge`.)

## Required secrets

Create these before applying (names referenced by the manifests):

```bash
# 1. Control-plane server TLS (edges must trust this cert). Use a cert for the
#    control-plane Service hostname, signed by an internal CA the edges carry.
#    OPTIONAL: skip this (and unset CP_TLS_CERT/CP_TLS_KEY) to serve plaintext
#    HTTP when the edge↔control-plane hop is a trusted encrypted private network
#    (tunnel / mesh / VPC peering). Point the edge at http:// and drop its CA
#    secret. Do NOT do this over the open internet — the API ships private keys.
kubectl -n parapet-ingress-controller create secret tls edge-controlplane-tls \
  --cert=cp.crt --key=cp.key

# 2. Per-edge bearer tokens → allowed domains (the authz table).
#    Format: {"<token>": ["acme.com", "*.acme.com"], ...}
kubectl -n parapet-ingress-controller create secret generic edge-controlplane-tokens \
  --from-file=tokens.json=tokens.json

# 3. The edge's own copy of its token (one per edge / shard).
kubectl -n parapet-edge create secret generic parapet-edge-cp \
  --from-literal=token=<that-edge's-token>

# 4. The CA the edge uses to verify the control plane's server cert.
kubectl -n parapet-edge create secret generic parapet-edge-cp-ca \
  --from-file=ca.crt=internal-ca.crt
```

## Sharding is the security boundary

Each edge's `EDGE_DOMAINS` and its token's allow-set should match its shard. The
isolation (an edge only holds *its* domains' keys) only holds if edges are
sharded by domain — see [`../../EDGE.md`](../../EDGE.md) "The tradeoff".

## Edge auto-trust (CA-only mTLS)

Lets the in-cluster core trust a newly-deployed edge automatically — no
`TRUST_PROXY` edit, no core restart. Full design: [`../../EDGE-AUTOTRUST.md`](../../EDGE-AUTOTRUST.md).

1. Supply the **edge CA** to the control plane, one of two ways:
   - **Managed (recommended):** `kubectl apply -f ca-bootstrap.yaml` — a run-once
     Job self-generates a dedicated, single-purpose, NameConstrained edge CA into
     the `parapet-edge-ca` Secret (adopt-if-present, never regenerate), and set
     `EDGE_CA_SECRET=parapet-edge-ca` on the CP (see `controlplane.yaml`). **No
     cert-manager, no hand-mounted CA — a Docker edge needs only its token.**
   - **Provided (existing PKI):** create the dedicated CA yourself (clientAuth-issuing;
     ideally `NameConstraints` to `spiffe://parapet.moonrhythm.io/edge/*`) as the
     `parapet-edge-ca` Secret and mount it on the CP (`EDGE_CA_CERT`/`EDGE_CA_KEY`).

   Either way the CP signs short-lived edge client certs (`POST /v1/edge-cert`) and
   serves the public CA in the tokenless `GET /v1/trust-bundle`.
2. Give each edge a **data-plane identity** by adding an `id` to its registry
   entry: `{"<token>": {"id": "acme-edge-1", "domains": ["acme.com"]}}` (a bare
   array still works for cert/WAF fetch, but grants no identity, so no `/v1/edge-cert`).
3. On the **edge**, set `EDGE_DATAPLANE_MTLS=true`, `EDGE_UPSTREAM_TLS=true`, and
   point `EDGE_UPSTREAM_ADDR` at the core's `:443` (see `edge.yaml` / the
   `run-edge-docker.sh` env). The edge generates its key in memory, fetches a leaf,
   and presents it on the re-encrypt hop.
4. On the **core**, set `EDGE_TRUST_CP_ENDPOINT` (the CP, `https://` only) and
   `EDGE_TRUST_CP_CA` (the CP **server** CA — mandatory, verified) and mount that CA
   (see `../deployment.yaml`). The core pulls the edge CA and trusts any client cert
   chaining to it; a no-cert client (Cloudflare/browser) still works (CIDR-only).

Revocation in this mode is by leaf expiry (`EDGE_CLIENTCERT_TTL`, default 7d) or CA
rotation; the `disabled` registry tombstone stops re-issuance. The convergence-gated
rotation + `revoke --edge` tool are follow-ons.

## WAF (global + zones)

Set `EDGE_WAF_ENABLED=true` on the edge and `CP_WAF_ENABLED=true` +
`POD_NAMESPACE` on the control plane to distribute the **global** baseline and the
tenant **zones** (`GET /v1/waf`) and run them at the edge as an early-drop layer.
parapet still re-runs the full WAF authoritatively — the edge is the lower trust
tier, so a stale/disabled edge never means an unprotected origin. The edge reuses
the same CEL engine as parapet (`parapet/pkg/waf`, conformance-guarded), so rules
block identically. Zone resolution at the edge is host-level (the control plane
derives `host → zoneKey` from Ingress objects, scoped to the edge's domains);
path-precise zone resolution stays parapet's authoritative job.

GeoIP/ASN (`request.country` / `request.asn`) resolve at the edge from the true
client IP via `WAF_GEOIP_DB` / `WAF_ASN_DB` (the edge image bakes both at the
default paths). The edge also forwards `X-Forwarded-Country` / `X-Forwarded-ASN`
to parapet.

## Response cache (optional)

Set `EDGE_CACHE_ENABLED=true` (and mount a writable `EDGE_CACHE_DIR`) to enable
the disk-backed honor-origin response cache — see [`../../EDGE.md`](../../EDGE.md)
"Response cache at the edge". Off by default; `X-Cache: HIT|MISS`.

## End-to-end smoke test

`e2e/run.sh` is a cluster-free harness that builds the local Go binaries
(`go build ./cmd/edge-controlplane` + `go build ./cmd/edge-proxy`) and wires the
real control plane (`KUBERNETES_BACKEND=fs`) + real edge + a dummy upstream,
asserting TLS termination, the http listener, global/zone/GeoIP WAF blocks, the
disk cache (MISS→HIT), and SNI fallback. Fast; needs only a Go toolchain plus
`openssl`, `curl`, `python3`, and `nc`.

## Rotation

The edge serves a cached cert and refreshes every `EDGE_REFRESH_INTERVAL`
seconds with ETag revalidation; a fetch failure is fail-static (keeps the cached
cert). The WAF ruleset refreshes on the same interval with the same fail-static
behavior (keeps last-good). Ensure renewed certs land in the source Secret
before the old ones are distrusted so there's no gap.
