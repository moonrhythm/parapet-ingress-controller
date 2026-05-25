# Phase 3 — Validate against a real Kubernetes cluster

> **This phase needs you.** Everything so far was developed and verified with the
> `fs` backend (static YAML manifests, no cluster) and local smoke tests. The
> *live* path — the kube-rs watch, in-cluster auth + TLS to the API server, real
> Endpoints/Secrets, h2c to real pods, SIGTERM draining, and RBAC — can only be
> exercised on an actual cluster, which the dev environment does not have. So
> Phase 3 is a **handoff**: the code-side prep that can be done offline is done;
> the cluster validation is yours to run and report back.

## Division of labor

| Done / available offline (me) | Needs a real cluster (you) |
|---|---|
| Controller code + 53 unit tests + fs-mode smoke | Build & push a container image |
| `cluster` watch (kube-rs reflectors + 300 ms debounce), compiles clean | Deploy + connect to the API server (RBAC, in-cluster TLS) |
| rustls `CryptoProvider` install in `main()` (see below) | Watch real Ingress/Service/Secret/Endpoints |
| RBAC + run instructions (this doc) | Real traffic, real TLS secrets, h2c to real pods |
| Dockerfile / CI / deploy manifests (Phase 4, on request) | SIGTERM graceful drain, side-by-side vs the Go controller |

## What I changed to make the first cluster run viable

`main()` now installs the process-default rustls crypto provider before starting
the watch — kube 3.x's `rustls-tls` client requires it, or the API connection
fails at runtime:

```rust
let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
```

(Could not be runtime-tested here without a cluster — first thing to confirm.)

## Known gaps to resolve before a *realistic* test

1. ✅ **Resolved — `TRUST_PROXY` shorthands.** `cloudflare` / `google` / `bunny`
   now expand to their CIDR lists (599 ranges, ported verbatim from
   `cmd/.../config.go` into `proxy/predefined.rs`), so the production
   `TRUST_PROXY: cloudflare` works as-is. Comma-mixed CIDRs + shorthands are
   supported, e.g. `cloudflare,10.0.0.0/8`.
2. ✅ **Resolved — upstream 502/503 retry.** A pod that connects then returns
   502/503 is now retried onto the next pod (round-robin), up to 5 total attempts
   (matching Go's `maxRetry`), only when the request body is replayable; the real
   upstream response passes through once the budget is spent.
3. **Graceful shutdown / `WAIT_BEFORE_SHUTDOWN`:** Pingora drains on SIGTERM, but
   the Go controller's pre-drain delay (default 30 s, to let the LB deregister)
   is not wired. Verify drain behavior; we may need to add the delay.
4. **Endpoints API:** uses core/v1 `Endpoints` (matches Go), *not* `EndpointSlice`.
   RBAC therefore needs `endpoints`, not `endpointslices`.
5. **Per-addr backend metrics** (`parapet_backend_*`) and downstream
   `parapet_connections` / `network_*` are not wired (Pingora pools upstreams).

## RBAC (list + watch only)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: parapet-ingress-controller-rs }
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["list", "watch"]
- apiGroups: [""]
  resources: ["services", "secrets", "endpoints"]
  verbs: ["list", "watch"]
```

Bind it to the controller's ServiceAccount (reuse the existing
`deploy/01-serviceaccount.yaml` pattern). `WATCH_NAMESPACE` set ⇒ a namespaced
Role suffices.

## How to run the cluster test

### Option A — fastest iteration: out-of-cluster against a real cluster

`kube::Client::try_default()` reads your `~/.kube/config`, so you can run the
binary locally pointed at a (test) cluster, no image build needed:

```bash
cd rust
cargo build --release -p parapet-ingress-controller --features proxy,cluster
KUBERNETES_BACKEND=cluster \
  INGRESS_CLASS=parapet \
  HTTP_PORT=8080 HTTPS_PORT=8443 \    # non-privileged ports for local runs
  WATCH_NAMESPACE=default \           # optional; omit to watch all namespaces
  ./target/release/parapet-ingress-controller
```

It will list+watch the cluster's resources and proxy to real pod IPs (reachable
only if your machine has pod-network access, e.g. kind, or via a VPN/port-forward).

### Option B — in-cluster (closest to production)

1. Build & push an image (Phase 4 provides the Dockerfile; until then a release
   binary in a `debian:trixie-slim` base works).
2. Apply: ServiceAccount + the RBAC above + a Deployment/DaemonSet (adapt
   `deploy/deployment.yaml`, swap the image, keep the env). Env vars are
   identical to the Go controller:

   | Env | Notes |
   |---|---|
   | `INGRESS_CLASS` | default `parapet` |
   | `WATCH_NAMESPACE` | empty = all namespaces |
   | `LOAD_ALL_CERTS` | `true` to index every TLS secret |
   | `TRUST_PROXY` | `true`/`false`/CIDRs/shorthands (`cloudflare`,`google`,`bunny`) |
   | `DISABLE_LOG` | `true` to silence the access log |
   | `HOST_CONCURRENT_CAPACITY` / `_SIZE` | per-host concurrency |
   | `HOST_COUNTRY_CONCURRENT_CAPACITY` / `_SIZE` / `HOST_COUNTRY_HEADER` | per-host+country |
   | `HTTP_PORT` / `HTTPS_PORT` | 80 / 443 |

   `PROFILER`/`PROFILER_NAME` and the `operations-trace*` annotations are dropped
   by design (no Rust GCP Profiler/Trace).

## Verification checklist

- [ ] Starts, connects to the API server (no rustls/provider error), logs
      "reload"; `GET /healthz` → 200, `GET /healthz?ready=1` → 200 after first sync.
- [ ] Create Ingress (class `parapet`) + Service + backing pods → request to the
      host routes to a pod (`Prefix`/`Exact`/`ImplementationSpecific` all behave
      like the Go controller).
- [ ] Edit/delete the Ingress → routes update within ~300 ms; no dropped requests
      during reload (hot swap).
- [ ] Scale the backend → round-robins across new pod IPs; kill a pod →
      bad-addr skip + retry onto a live pod.
- [ ] TLS: create a `kubernetes.io/tls` Secret referenced by `spec.tls` → correct
      cert served per SNI (exact + wildcard); also test `LOAD_ALL_CERTS=true`.
- [ ] h2c: a backend Service with `appProtocol: h2c` (e.g. gRPC) is reachable.
- [ ] Annotations on real ingresses: redirect-https, hsts, allow-remote,
      body-limitrequest, basic-auth, ratelimit-s/m/h, forward-auth,
      strip-prefix, upstream-host/path/protocol, redirect.
- [ ] Metrics: scrape `:9187/metrics`; diff the `parapet_*` series + label sets
      against the Go controller's `/metrics`.
- [ ] Access log: JSON lines match the Go format on real traffic.
- [ ] `kubectl rollout restart` / SIGTERM → connections drain cleanly (see gap #3).
- [ ] **Side-by-side:** run the Rust controller next to the Go one on the same
      ingresses (different ports / a canary) and diff routing, headers, status
      codes, metric labels, and log fields.

## Report back

Send me: any startup/auth/TLS errors (especially the crypto provider), and any
behavior differences vs the Go controller. I'll close the gaps above, then we
proceed to **Phase 4** (Dockerfile + CI + deploy manifests) and **Phase 5** (the
load-test performance-parity gate, which is the cutover criterion).
