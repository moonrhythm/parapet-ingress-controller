# Go implementation (`go/`)

The Go implementation of parapet-ingress-controller, built on the [parapet](https://github.com/moonrhythm/parapet) middleware framework. It watches Kubernetes Ingress, Service, Secret, ConfigMap, and Endpoints resources and hot-reloads an `http.ServeMux` router without restarting the process.

> **One of two co-maintained implementations.** The shared behavior contract —
> annotations, env vars, metrics, WAF model, per-request order — is
> [`../SPEC.md`](../SPEC.md) (change it there first). The Rust implementation
> lives in [`../rust/`](../rust/) ([`../rust/README.md`](../rust/README.md)).
> This file is the **Go-specific** architecture guide; paths below are relative
> to `go/`. Cloud Profiler/Trace are Go-only. Shared assets (`deploy/`,
> `WAF.md`, `SPEC.md`, `conformance/`, `.github/`) live at the repo root.

## Repository layout

```
cmd/parapet-ingress-controller/   # binary entry-point (main.go, config.go)
controller.go                     # Controller struct — watch/reload logic (generic watchResource)
controller_waf.go                 # WAF wiring: global instance + zone registry, ConfigMap watch
retry.go                          # retryMiddleware — retries idempotent requests on upstream failure
wafrule/                          # WAF rule YAML DTO + parser (-> []waf.Rule)
geoip/                            # IPLocate ip-to-country/ip-to-asn .mmdb -> request.country/asn (WAF_GEOIP_DB/WAF_ASN_DB)
plugin/                           # annotation-driven middleware plugins
  plugin.go                       # core plugin type + built-in plugins
  auth.go                         # BasicAuth, ForwardAuth
  waf.go                          # WAFZone — bind ingress to a WAF zone by reference
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
  requests.go, backendconns.go, host.go, reload.go, waf.go
  cache.go                        # generic lock+map cache for per-label-set metric handles
state/                            # per-request state map (passed via context)
debounce/                         # debounce helper used for reload coalescing
Dockerfile                        # multi-stage Go build (CGO + cbrotli)
# repo root (shared): deploy/  WAF.md  SPEC.md  conformance/
# ../.github/workflows/: go-test / go-build / go-release .yaml (path-filtered to go/**)
```

## Key concepts

### Controller lifecycle
`Controller.Watch()` starts four goroutines that continuously watch Ingress, Service, Secret, and Endpoints resources (plus a fifth, ConfigMaps, when `WAF_ENABLED=true`). Changes are coalesced through a 300 ms `debounce.Debounce` before triggering a reload. On reload, a new `http.ServeMux` is built and swapped in under a `sync.RWMutex` — zero downtime. WAF ConfigMap changes are the exception: they recompile rulesets without rebuilding the mux (see the WAF concept below).

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

### WAF (opt-in, `WAF_ENABLED=true`)
A CEL-rule firewall on top of `parapet/pkg/waf`. **Full design in [`../WAF.md`](../WAF.md).** Two rulesets, both fed by label-marked ConfigMaps (`parapet.moonrhythm.io/waf: global|zone`), watched as a 5th resource:
- **Global** (`globalWAF`, mounted in `main.go`'s `m` chain before `ctrl`) — one baseline ruleset, honored only from `POD_NAMESPACE`, applied to all traffic.
- **Zones** (`zones atomic.Pointer[map[string]*waf.WAF]`, key `<namespace>/<name>`) — tenant rulesets an ingress binds via `parapet.moonrhythm.io/waf-zone`; `plugin.WAFZone` resolves the key (namespace-local, or `ns/id` cross-ref) and looks up the live registry per request.

Global runs first and is authoritative. **WAF reload is decoupled from the mux**: ConfigMap changes call `reloadWAFDebounced` (recompile + atomic swap) and never rebuild routes; `SetRules` is all-or-nothing so a bad ruleset keeps the last-good one. Rules parse via `wafrule/`; matches count `parapet_waf_matches{rule_id,action,scope}` (`metric/waf.go`). Code: `controller_waf.go`, `plugin/waf.go`, `wafrule/`.

**GeoIP** (`request.country`): when `WAF_GEOIP_DB` points at an IPLocate ip-to-country `.mmdb` (flat `country_code` schema, not MaxMind's nested `country.iso_code`), `main.go` opens it (`geoip/`, `maxminddb-golang`) and sets `WAFConfig.Country` to a resolver (client IP via `geoip.ClientIP`, parapet precedence → ISO code, else `"XX"`). `newWAF` assigns it to every WAF's `waf.WAF.Country` (the parapet hook added in v0.15.1), so `request.country` is set on the global and zone rulesets. nil resolver (no DB) → `request.country == ""`.

**ASN** (`request.asn`): the same pattern with `WAF_ASN_DB` → `geoip.OpenASN`/`(*ASNDB).ASN` (IPLocate stores `asn` as a string; parsed to `int64`) → `WAFConfig.ASN` → every WAF's `waf.WAF.ASN` (the parapet hook added in **v0.15.2**). nil resolver (no DB) or unplaceable IP → `request.asn == 0`.

## Annotation & configuration reference

The annotation reference, env-var table, and per-request order are the **shared
contract** — see [`../SPEC.md`](../SPEC.md). Go-specific notes: `auth.go` documents
the `basic-auth` / `forward-auth` formats; all `WAF_*` knobs are honored here,
including `WAF_COST_LIMIT`, `WAF_INSPECT_BODY`, and `WAF_DISABLE_MACROS` (which
the Rust port omits — see SPEC's divergence table).

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

All path-filtered to `go/**` so they never fire on Rust-only changes:
- **Push & PR touching `go/**`** → `go-test.yaml`: `go vet` + `go test -race` with coverage → Codecov
- **Push to `master`** → `go-build.yaml`: pushes two images tagged with `$GITHUB_SHA` (`:$sha` GOAMD64=v3, `:$sha-amd64v1` GOAMD64=v1). Docker build context is `go/`.
- **Push a tag** → `go-release.yaml`: same plus `:latest` and `:{tag}`
- Registries: `us-docker.pkg.dev/moonrhythm-containers/gcr.io/` and `asia-southeast3-docker.pkg.dev/moonrhythm-core/public/`

## Module

```
module github.com/moonrhythm/parapet-ingress-controller/go
go 1.26.3
```

The module lives in the `go/` subdirectory (the repo hosts two implementations), so the module path ends in `/go` and `go install` targets are `…/parapet-ingress-controller/go/cmd/parapet-ingress-controller`. Key dependencies: `github.com/moonrhythm/parapet`, `k8s.io/client-go`, `go.opentelemetry.io`, `github.com/prometheus/client_golang`, `cloud.google.com/go/profiler`.

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
