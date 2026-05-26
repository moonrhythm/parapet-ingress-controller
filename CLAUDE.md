# parapet-ingress-controller

A Kubernetes ingress controller built on the [parapet](https://github.com/moonrhythm/parapet) middleware framework. It watches Kubernetes Ingress, Service, Secret, and Endpoints resources and hot-reloads an `http.ServeMux` router without restarting the process.

## Rust port (`rust/`, in progress)

A from-scratch rewrite on the [Pingora](https://github.com/cloudflare/pingora) framework lives in `rust/`, intended to replace the Go controller once it clears a load-test perf-parity gate. **The Go controller remains the production binary until that cutover.** GCP Cloud Profiler and Cloud Trace are dropped from the port by design (no Rust SDK).

The operational reference for the port — build/run, the full **environment-variable** table (including the Rust-only `UPSTREAM_CONNECT_TIMEOUT` / `UPSTREAM_TOTAL_CONNECT_TIMEOUT` connect-phase timeouts), metrics, and DDoS-resilience notes — is [`rust/README.md`](rust/README.md). The env table below is the Go controller's.

```
rust/
  controller/         # the real crate (lib `controller`, bin `parapet-ingress-controller`)
    src/proxy/        # Pingora ProxyHttp impl: routing, upstream (http/https/h2c),
                      #   retry + bad-addr, middleware, metrics, SNI, server wiring
    src/{router,route,cert,config,reconcile,shared,k8s}.rs  # routing/reconcile core
                      #   (no pingora/kube deps → builds + tests in ~1s)
  spike/              # throwaway Phase-0 de-risk proof (see PHASE0_FINDINGS.md)
  bench/              # Phase-5 perf harness: k6 load.js + run.sh (see PHASE5.md)
  Dockerfile          # multi-stage; distroless/cc-debian13 runtime (~41 MB)
  PHASE{0,3,5}.md     # de-risk findings / cluster-validation handoff / perf-parity gate
```

Build, test, run:

```bash
cd rust
cargo test -p parapet-ingress-controller                       # fast core (default features)
cargo test -p parapet-ingress-controller --features proxy,cluster
# run locally against static manifests (no cluster):
KUBERNETES_BACKEND=fs KUBERNETES_FS=<dir> HTTP_PORT=8080 HTTPS_PORT=8443 \
  cargo run -p parapet-ingress-controller --features proxy,cluster
```

Cargo features: `cluster` (kube-rs watch) and `proxy` (Pingora server); the binary needs both. The macOS-only `rust/.cargo/config.toml` (Homebrew OpenSSL) is gitignored — CI/Docker resolve TLS via `pkg-config`/`libssl-dev`.

CI: `.github/workflows/rust-test.yaml` (fmt + clippy + test on push/PR) and `rust-build.yaml` (build + push `rust-`-prefixed images on master), both path-filtered to `rust/**` so they never fire on Go-only changes.

**Parity status:** the full request data path is ported — routing (all PathTypes), TLS/SNI, h2c, all 12 annotations, host/country concurrency, rate limits, forward/basic auth, trust-proxy (+ cloudflare/google/bunny shorthands), `WAIT_BEFORE_SHUTDOWN` drain, JSON access log, and compression (SSE responses are exempted from compression so they stream). Setting `HTTPS_PORT=` (empty) runs HTTP-only (e.g. the internal-ingress controller); unset defaults to 443. **Retry differs intentionally from Go:** the Rust proxy retries only on *connection* failures — `fail_to_connect` (cannot connect, marks the pod bad + round-robins) and a reused keepalive connection breaking before a response — and **never** on an upstream HTTP status (Go retried 502/503 via `IsRetryable`); an upstream that responds has processed the request, so retrying would duplicate side effects and amplify load. Metrics match the Go names, including `process_*` (Linux; a custom `/proc` collector — the `prometheus` crate's `ProcessCollector` truncates `process_cpu_seconds_total` to whole seconds via integer division), `parapet_network_request/response_bytes`, and `parapet_backend_connections` (an in-flight-per-addr approximation; Pingora pools connections). `TR_MAX_IDLE_CONNS_PER_HOST` maps to Pingora's (process-global) `upstream_keepalive_pool_size`. **Known gaps:** `parapet_connections` (downstream connection gauge by state — no Pingora `ConnState` equivalent) and `go_*` runtime metrics (no Rust equivalent); `TR_MAX_CONNS_PER_HOST` and `HTTP_SERVER_MAX_HEADER_BYTES` (no Pingora 0.8 equivalent).

## Repository layout

```
cmd/parapet-ingress-controller/   # binary entry-point (main.go, config.go)
controller.go                     # Controller struct — watch/reload logic (generic watchResource)
retry.go                          # retryMiddleware — retries idempotent requests on upstream failure
plugin/                           # annotation-driven middleware plugins
  plugin.go                       # core plugin type + built-in plugins
  auth.go                         # BasicAuth, ForwardAuth
  trace.go                        # OpenTelemetry tracing
proxy/                            # reverse-proxy implementation
  proxy.go, transport.go          # http.ReverseProxy wrapper
  gateway.go, dialer.go           # TCP dialing / gateway support
  buffer.go                       # buffer pool
route/                            # routing tables
  table.go                        # route Table — host→IP / addr→port lookup
  rrlb.go                         # RRLB (round-robin load balancer)
  badaddr.go                      # bad-address tracking (skip failing pods)
cert/                             # TLS certificate table (SNI lookup)
k8s/                              # Kubernetes client helpers
  k8s.go, cluster.go, fs.go      # in-cluster / local kubeconfig init + list/watch helpers
metric/                           # Prometheus metrics
  requests.go, backendconns.go, host.go, reload.go
  cache.go                        # generic lock+map cache for per-label-set metric handles
state/                            # per-request state map (passed via context)
debounce/                         # debounce helper used for reload coalescing
deploy/                           # raw Kubernetes YAML manifests
.github/workflows/                # test.yaml (CI), build.yaml (push), release.yaml (tag)
```

## Key concepts

### Controller lifecycle
`Controller.Watch()` starts four goroutines that continuously watch Ingress, Service, Secret, and Endpoints resources. Changes are coalesced through a 300 ms `debounce.Debounce` before triggering a reload. On reload, a new `http.ServeMux` is built and swapped in under a `sync.RWMutex` — zero downtime.

### Plugins
A `Plugin` is `func(ctx plugin.Context)` where `Context` carries:
- `*parapet.Middlewares` — append middleware with `ctx.Use(...)`
- `Routes map[string]http.Handler` — inject routes directly (used by RedirectRules)
- `Ingress *networking.Ingress` — the raw ingress object

Plugins are called once per Ingress object on every reload. All annotation keys use the prefix `parapet.moonrhythm.io/`.

### Routing
Routes are keyed as `host + path` strings (e.g. `"www.example.com/api/"`). PathType semantics:
- `Prefix` → registers both `host/path` and `host/path/`
- `Exact` → registers `host/path` only (strips trailing slash)
- `ImplementationSpecific` → registers as-is

Endpoint lookup is round-robin (`route.RRLB`). Bad addresses (dial errors) are marked and skipped temporarily.

### TLS
TLS secrets are loaded from `Secret.Data["tls.crt"]` / `["tls.key"]`. The `cert.Table` provides `GetCertificate` for SNI-based lookup (exact match, then a single-label wildcard climb), plugged directly into `tls.Config`. By default only secrets referenced by an Ingress's `spec.tls.secretName` are loaded; set `LOAD_ALL_CERTS=true` to index every TLS-typed secret in the watch namespace (lets a wildcard cert serve SNI without per-ingress wiring).

### Proxy
`proxy.Proxy` wraps `httputil.ReverseProxy`. The upstream URL is resolved at request time via `route.Table.Lookup`. Protocol is controlled by the `parapet.moonrhythm.io/upstream-protocol` annotation (default: `http`).

On an upstream failure (dial error, upstream 502/503), the proxy's `ErrorHandler` panics; `retryMiddleware` (`retry.go`) recovers it and retries the request (up to 5 times with backoff) — but only when the body hasn't been read, so non-idempotent requests aren't replayed. `proxy.IsRetryable` decides which errors qualify.

## Annotation reference

| Annotation | Values | Effect |
|---|---|---|
| `parapet.moonrhythm.io/redirect-https` | `"true"` | 301 redirect HTTP→HTTPS (skips ACME challenge) |
| `parapet.moonrhythm.io/hsts` | `"preload"` / any | Strict-Transport-Security header |
| `parapet.moonrhythm.io/redirect` | YAML map `host: url` | Host-level redirect rules |
| `parapet.moonrhythm.io/ratelimit-s` | integer | Requests per second (fixed window) |
| `parapet.moonrhythm.io/ratelimit-m` | integer | Requests per minute |
| `parapet.moonrhythm.io/ratelimit-h` | integer | Requests per hour |
| `parapet.moonrhythm.io/body-limitrequest` | bytes (int64) | Max request body size |
| `parapet.moonrhythm.io/upstream-protocol` | `http` / `https` | Force upstream scheme |
| `parapet.moonrhythm.io/upstream-host` | hostname | Override `Host` header sent upstream |
| `parapet.moonrhythm.io/upstream-path` | path prefix | Prepend path (and optional query) upstream |
| `parapet.moonrhythm.io/allow-remote` | comma-sep CIDRs | IP allowlist (blocks everything else) |
| `parapet.moonrhythm.io/strip-prefix` | path prefix | Strip prefix from request path |
| `parapet.moonrhythm.io/basic-auth` | see auth.go | HTTP Basic Auth |
| `parapet.moonrhythm.io/forward-auth` | URL | Delegate auth to external service |

## Configuration (environment variables)

| Env var | Default | Description |
|---|---|---|
| `HTTP_PORT` | `80` | HTTP listener port |
| `HTTPS_PORT` | `443` | HTTPS listener port |
| `INGRESS_CLASS` | `parapet` | IngressClassName to handle |
| `LOAD_ALL_CERTS` | `false` | Load every TLS-typed secret in the namespace, not just those referenced by an Ingress's `spec.tls` |
| `WATCH_NAMESPACE` | `""` (all) | Restrict namespace watch |
| `POD_NAMESPACE` | | Current pod's namespace |
| `TRUST_PROXY` | | `true`, `false`, or comma-sep CIDRs (supports `cloudflare` shorthand) |
| `WAIT_BEFORE_SHUTDOWN` | `30s` | Graceful shutdown delay |
| `HTTP_SERVER_MAX_HEADER_BYTES` | `16384` | Max header size |
| `HOST_CONCURRENT_CAPACITY` | | Per-host concurrent request cap |
| `HOST_CONCURRENT_SIZE` | | Per-host queue size (enables queueing) |
| `HOST_COUNTRY_CONCURRENT_CAPACITY` | | Per-host+country cap |
| `HOST_COUNTRY_CONCURRENT_SIZE` | | Per-host+country queue size |
| `HOST_COUNTRY_HEADER` | | Header carrying country code |
| `TR_MAX_CONNS_PER_HOST` | stdlib default | Transport max conns per host |
| `TR_MAX_IDLE_CONNS_PER_HOST` | stdlib default | Transport max idle conns per host |
| `PROFILER` | `false` | Enable Cloud Profiler |
| `PROFILER_NAME` | | Cloud Profiler service name |
| `DISABLE_LOG` | `false` | Suppress access log |

## Build & run

```bash
# Run locally against current kubeconfig
KUBERNETES_LOCAL=true HTTP_PORT=8080 HTTPS_PORT=8443 go run ./cmd/parapet-ingress-controller

# Run tests
go test ./...

# Build Docker image via buildctl
make build-dev

# Build binary directly
go build -o parapet-ingress-controller \
  -ldflags "-w -s -X main.version=$(git describe --tags)" \
  -tags=cbrotli \
  ./cmd/parapet-ingress-controller
```

### Docker image
- Builder: `golang:1.26.3-trixie` with `libbrotli-dev` (CGO enabled, `-tags=cbrotli`)
- Runtime: `debian:trixie-slim` with `libbrotli1` and `ca-certificates`
- Build args: `VERSION` (injected as `main.version`), `GOAMD64` (v3 default, v1 for compatibility image)

## CI / Release

- **Every push & PR** → `test.yaml`: runs `go vet` and `go test -race` with coverage, uploads to Codecov
- **Push to `master`** → `build.yaml`: builds and pushes two images tagged with `$GITHUB_SHA`
  - `...:$sha` (GOAMD64=v3)
  - `...:$sha-amd64v1` (GOAMD64=v1)
- **Push a tag** → `release.yaml`: same but also pushes `:latest` and `:{tag}`
- Registries: `us-docker.pkg.dev/moonrhythm-containers/gcr.io/` and `registry.moonrhythm.io/`

## Module

```
module github.com/moonrhythm/parapet-ingress-controller
go 1.26.3
```

Key dependencies: `github.com/moonrhythm/parapet`, `k8s.io/client-go`, `go.opentelemetry.io`, `github.com/prometheus/client_golang`, `cloud.google.com/go/profiler`.

## Adding a new plugin

1. Add a `func MyPlugin(ctx plugin.Context)` to `plugin/` (new file or existing).
2. Read the annotation: `ctx.Ingress.Annotations["parapet.moonrhythm.io/my-annotation"]`.
3. Call `ctx.Use(...)` to append middleware, or write to `ctx.Routes` for route-level effects.
4. Register it in `cmd/parapet-ingress-controller/main.go` with `ctrl.Use(plugin.MyPlugin)` — order matters (plugins run in registration order per request).
5. Write a test in `plugin/my_plugin_test.go` using the pattern in `plugin/plugin_test.go`.

## Testing conventions

- Table-driven tests using `testify/assert` and `testify/require`
- `plugin_test.go` builds a minimal `plugin.Context` with a fake `*networking.Ingress`
- Use `httptest.NewRecorder()` and `httptest.NewRequest()` for HTTP assertions
- `state.Middleware()` must wrap handlers that need state access in tests
