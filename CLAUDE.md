# parapet-ingress-controller

A Kubernetes ingress controller built on the [parapet](https://github.com/moonrhythm/parapet) middleware framework. It watches Kubernetes Ingress, Service, Secret, and Endpoints resources and hot-reloads an `http.ServeMux` router without restarting the process.

## Repository layout

```
cmd/parapet-ingress-controller/   # binary entry-point (main.go, config.go)
controller.go                     # Controller struct — watch/reload logic
plugin/                           # annotation-driven middleware plugins
  plugin.go                       # core plugin type + built-in plugins
  auth.go                         # BasicAuth, ForwardAuth
  trace.go                        # OpenTelemetry tracing
proxy/                            # reverse-proxy implementation
  proxy.go, transport.go          # http.ReverseProxy wrapper
  gateway.go, dialer.go           # TCP dialing / gateway support
  buffer.go                       # buffer pool
route/                            # routing tables
  badaddr.go                      # RRLB (round-robin load balancer), bad-address tracking
cert/                             # TLS certificate table (SNI lookup)
k8s/                              # Kubernetes client helpers
  k8s.go, cluster.go, fs.go      # in-cluster / local kubeconfig init + list/watch helpers
metric/                           # Prometheus metrics
  requests.go, backendconns.go, host.go, reload.go
state/                            # per-request state map (passed via context)
debounce/                         # debounce helper used for reload coalescing
deploy/                           # raw Kubernetes YAML manifests
.github/workflows/                # CI (build.yaml) and release (release.yaml) pipelines
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
TLS secrets are loaded from `Secret.Data["tls.crt"]` / `["tls.key"]`. The `cert.Table` provides `GetCertificate` for SNI-based lookup, plugged directly into `tls.Config`.

### Proxy
`proxy.Proxy` wraps `httputil.ReverseProxy`. The upstream URL is resolved at request time via `route.Table.Lookup`. Protocol is controlled by the `parapet.moonrhythm.io/upstream-protocol` annotation (default: `http`).

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
