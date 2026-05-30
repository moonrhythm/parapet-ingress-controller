# Edge deployment

Manifests for the out-of-cluster **edge proxy** + in-cluster **edge control
plane**. Design and contract: [`../../EDGE.md`](../../EDGE.md).

- `controlplane.yaml` — the Go control plane (`Deployment` + `ClusterIP Service`
  + `NetworkPolicy`). Runs in the controller's namespace, reuses its
  ServiceAccount (needs `get/list/watch secrets`). **Distributes private keys** —
  ClusterIP only, locked to edge source IPs; never on the public LB.
- `edge.yaml` — the Rust/Pingora edge (`Deployment` + `LoadBalancer Service`).
  Terminates public TLS; the public-facing tier.

## Required secrets

Create these before applying (names referenced by the manifests):

```bash
# 1. Control-plane server TLS (edges must trust this cert). Use a cert for the
#    control-plane Service hostname, signed by an internal CA the edges carry.
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

## WAF (Phase 2)

Set `EDGE_WAF_ENABLED=true` on the edge and `CP_WAF_ENABLED=true` +
`POD_NAMESPACE` on the control plane to distribute the **global** WAF baseline
(`GET /v1/waf`) and run it at the edge as an early-drop layer. parapet still
re-runs the full WAF authoritatively — the edge is the lower trust tier, so a
stale/disabled edge never means an unprotected origin. The edge reuses the same
CEL engine as parapet (conformance-guarded), so rules block identically.

GeoIP/ASN (`request.country` / `request.asn`) resolve at the edge from the true
client IP via `WAF_GEOIP_DB` / `WAF_ASN_DB` (the edge image bakes both at the
default paths). The edge also forwards `X-Forwarded-Country` / `X-Forwarded-ASN`
to parapet. Tenant **zones** are not distributed yet (Phase 3).

## End-to-end smoke tests

Two cluster-free harnesses wire the real control plane (`KUBERNETES_BACKEND=fs`)
+ real edge + a dummy upstream and assert TLS termination, global/zone/GeoIP WAF
blocks, and SNI fallback (identical assertions):

- `e2e/run.sh` — builds local binaries (`go build` / `cargo build`) and runs them
  as processes. Fast; needs a Go + Rust toolchain.
- `e2e/run-docker.sh` — builds the actual shipped images
  (`go/Dockerfile.edge-controlplane`, `rust/Dockerfile.edge`) and runs them as
  containers on a shared Docker network. Slower (compiles in-image) but exercises
  the real images. Needs Docker (BuildKit). `EDGE_E2E_BUILD=0` reuses existing
  images; `CP_IMAGE` / `EDGE_IMAGE` override the tags.

## Rotation

The edge serves a cached cert and refreshes every `EDGE_REFRESH_INTERVAL`
seconds with ETag revalidation; a fetch failure is fail-static (keeps the cached
cert). The WAF ruleset refreshes on the same interval with the same fail-static
behavior (keeps last-good). Ensure renewed certs land in the source Secret
before the old ones are distrusted so there's no gap.
