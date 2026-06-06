# parapet-ingress-controller (Go)

The Go implementation of parapet-ingress-controller, built on the [parapet](https://github.com/moonrhythm/parapet) middleware framework. It watches Kubernetes Ingress, Service, Secret, ConfigMap, and Endpoints resources and hot-reloads an `http.ServeMux` router without restarting the process.

> **Go is the sole maintained implementation.** The behavior contract —
> annotations, env vars, metrics, WAF model, per-request order — is
> [`SPEC.md`](SPEC.md). This file is the **Go-specific** architecture guide; the
> Go module lives at the repo root, so the paths below are relative to it. The
> shared assets (`deploy/`, `WAF.md`, `SPEC.md`, `EDGE.md`, `conformance/`) sit
> alongside the Go code at the repo root.
>
> ⚠️ **The Rust implementation (`rust/`) is DEPRECATED and FROZEN. Do not edit
> any file under `rust/`** — not for new features, not for SPEC parity, not for
> cleanup. It is kept only for historical reference. SPEC.md is no longer a
> two-way contract: change behavior in the Go code, and update SPEC.md to match,
> without porting anything to Rust. The Rust CI workflows have been removed.

## Before starting a task

**Always check the current git branch first** (`git branch --show-current`) and
confirm it's the right place for the work. If you're on `main` or on an unrelated
feature branch, create a new branch off `main` before making changes — don't pile
unrelated work onto an existing feature branch or commit straight to `main`.

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
trustcidr/                        # TRUST_PROXY spec -> parapet trust Conditional (CIDRs + cloudflare/google/bunny); shared by controller + edge
debounce/                         # debounce helper used for reload coalescing
edgecp/                           # edge control-plane lib (cert store, authz, reload, REST server)
cmd/edge-controlplane/            # edge control-plane binary (see EDGE.md)
edge/                             # edge proxy lib: certstore, cp (CP client), waf, refresh, forward (cache is parapet/pkg/cache)
cmd/edge-proxy/                   # out-of-cluster edge proxy binary (parapet framework; see EDGE.md)
Dockerfile                        # controller image (multi-stage Go build, CGO + cbrotli)
Dockerfile.edge-controlplane      # control-plane image (pure Go, distroless/static)
Dockerfile.edge                   # edge proxy image (pure Go, distroless/static + baked GeoIP)
# also at repo root: deploy/  WAF.md  SPEC.md  EDGE.md  conformance/  rust/ (DEPRECATED + FROZEN — do not edit)
# .github/workflows/: go-test / go-build / go-release .yaml (path-filtered to **/*.go + go.mod/go.sum);
#   edge-build / edge-e2e .yaml build + smoke-test the edge + control-plane images
```

### Edge proxy (`cmd/edge-proxy` + `edge/`)
The out-of-cluster edge, on the same parapet framework as the controller (see
[`EDGE.md`](EDGE.md)). It fetches cert+key + WAF rules from the in-cluster
control plane (`edge/cp.go`), terminates public TLS via a hot-swappable
`cert.Table` (`edge/certstore.go`, self-signed fallback on SNI miss, on-demand
fetch in serve-all mode), runs global + zone WAF (`edge/waf.go`, reusing
`parapet/pkg/waf` + `wafrule` + `geoip` exactly like the controller), optionally
optionally caches responses via `parapet/pkg/cache` (memory or disk backend,
selected by `EDGE_CACHE_BACKEND`), and forwards to parapet (`edge/forward.go`). Refresh loops are fail-static
(`edge/refresh.go`, `edge/wafrefresh.go`). It is **not** the controller — no k8s
client, no Ingress watch — so it lives beside, not inside, the controller. Like
the controller it honors `TRUST_PROXY` (shared `trustcidr` package): default `""`
keeps the first-hop distrust posture; set it (e.g. `cloudflare`) when the edge
sits behind another L7 proxy so the real client IP flows through to WAF/geo/log
and the upstream hop.

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

On a **connection failure** (dial error — no response from upstream), the proxy's `ErrorHandler` panics; `retryMiddleware` (`retry.go`) recovers it and retries the request (up to 5 times with backoff) — but only when the body hasn't been read, so non-idempotent requests aren't replayed. `proxy.IsRetryable` is **dial-error-only**: an upstream that *responds* — including 502/503 — has processed the request, so its response passes through to the client unchanged rather than being retried (retrying could duplicate side effects and amplify load on a failing backend). This matches the Rust port; see [`SPEC.md`](SPEC.md).

**Auto-h2c detection** (opt-in, `UPSTREAM_AUTO_H2C=true`, Go-only): `proxy.EnableAutoH2C(ttl)` swaps the gateway's plain-`http` path for `autoH2CTransport` (`proxy/autoh2c.go`), which speculatively tries h2c first and falls back to HTTP/1.1 when the upstream isn't HTTP/2. Each probe outcome — **positive (h2c) or negative (HTTP/1.1-only)** — is cached in a `sync.Map` **keyed per-Service** (`<ns>/<name>:<port>`, stamped into request `state` as `upstreamKey` by `makeHandler`; falls back to the dialed `host:port`), so the cache stays bounded as pods churn and a new pod of a known Service skips the probe. Entries carry a **TTL** (`UPSTREAM_AUTO_H2C_TTL`, default 10m): on expiry the upstream is re-probed, so a Service that gains or loses h2c support is re-detected without a restart (this replaces the earlier clear-on-reload). A **fresh** cached entry takes the fast path straight to the right transport — so steady h2c traffic is fully multiplexed and never serialized. Only **unknown/expired** upstreams reach the **single-flight** guard (`probing sync.Map`): one request probes while the rest use HTTP/1.1, so a cold start or TTL expiry can't trigger a herd of failed h2c connections. Fallback safety: **only bodyless requests probe.** The h2c client streams any request body as DATA frames (consuming it) before its read loop detects an HTTP/1.1 peer and fails — leaving nothing to replay over HTTP/1.1 and surfacing `http2: frame too large … looked like an HTTP/1.1 header`. So a request carrying a body (`hasBody` ⇒ `ContentLength != 0`, including chunked `-1`) is routed straight to the fallback **without probing or caching**; a later bodyless request establishes the verdict for the whole Service, after which bodied requests ride the cached transport via the fast path. Trade-off: a plain-http upstream that is h2c-only **and** only ever receives bodied requests never auto-upgrades — those should set `appProtocol: h2c` explicitly. A **dial error is not an h2c signal** — it propagates to the retry path and is never cached. WebSocket/Upgrade requests always take HTTP/1.1 (httputil.ReverseProxy has no RFC 8441 HTTP/2 path) and are never probed or cached; `https` and explicit `appProtocol: h2c` upstreams are untouched. Rust is frozen — not ported.

### WAF (opt-in, `WAF_ENABLED=true`)
A CEL-rule firewall on top of `parapet/pkg/waf`. **Full design in [`WAF.md`](WAF.md).** Two rulesets, both fed by label-marked ConfigMaps (`parapet.moonrhythm.io/waf: global|zone`), watched as a 5th resource:
- **Global** (`globalWAF`, mounted in `main.go`'s `m` chain before `ctrl`) — one baseline ruleset, honored only from `POD_NAMESPACE`, applied to all traffic.
- **Zones** (`zones atomic.Pointer[map[string]*waf.WAF]`, key `<namespace>/<name>`) — tenant rulesets an ingress binds via `parapet.moonrhythm.io/waf-zone`; `plugin.WAFZone` resolves the key (namespace-local, or `ns/id` cross-ref) and looks up the live registry per request.

Global runs first and is authoritative. **WAF reload is decoupled from the mux**: ConfigMap changes call `reloadWAFDebounced` (recompile + atomic swap) and never rebuild routes; `SetRules` is all-or-nothing so a bad ruleset keeps the last-good one. Rules parse via `wafrule/`; matches count `parapet_waf_matches{rule_id,action,scope}` (`metric/waf.go`). Code: `controller_waf.go`, `plugin/waf.go`, `wafrule/`.

**GeoIP** (`request.country`): `WAF_GEOIP_DB` defaults to the baked `/geoip/ip-to-country.mmdb` (set `""` to disable; a missing file at the default path is a quiet no-op, a missing explicit path logs an error). `main.go` opens it (`geoip/`, `maxminddb-golang`, flat `country_code` schema, not MaxMind's nested `country.iso_code`) and sets `WAFConfig.Country` to a resolver (client IP via `geoip.ClientIP`, parapet precedence → ISO code, else `"XX"`). `newWAF` assigns it to every WAF's `waf.WAF.Country` (the parapet hook added in v0.15.1), so `request.country` is set on the global and zone rulesets. nil resolver (no DB) → `request.country == ""`.

**ASN** (`request.asn`): the same pattern with `WAF_ASN_DB` (defaults to the baked `/geoip/ip-to-asn.mmdb`; `""` disables) → `geoip.OpenASN`/`(*ASNDB).ASN` (IPLocate stores `asn` as a string; parsed to `int64`) → `WAFConfig.ASN` → every WAF's `waf.WAF.ASN` (the parapet hook added in **v0.15.2**). nil resolver (no DB) or unplaceable IP → `request.asn == 0`.

## Annotation & configuration reference

The annotation reference, env-var table, and per-request order are the **shared
contract** — see [`SPEC.md`](SPEC.md). Go-specific notes: `auth.go` documents
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
make go-build-dev

# Build binary directly
go build -o parapet-ingress-controller \
  -ldflags "-w -s -X main.version=$(git describe --tags)" \
  -tags=cbrotli \
  ./cmd/parapet-ingress-controller
```

Before committing, run `gofmt -l .` (must print nothing) and `go vet ./...` — CI
fails on unformatted files. See the umbrella [`Makefile`](Makefile) for the
`make test` target (Go only; Rust is frozen and no longer built or tested).

### Docker image
- Builder: `golang:1.26.4-trixie` with `libbrotli-dev` (CGO enabled, `-tags=cbrotli`)
- Runtime: `debian:trixie-slim` with `libbrotli1` and `ca-certificates`
- Build args: `VERSION` (injected as `main.version`), `GOAMD64` (v3 default, v1 for compatibility image)

## CI / Release

All path-filtered to `**/*.go` + `go.mod`/`go.sum` (plus `Dockerfile*`):
- **Push & PR touching Go files** → `go-test.yaml`: `go vet` + `go test -race`
- **Push to `main`** → `go-build.yaml`: pushes two images tagged with `$GITHUB_SHA` (`:$sha` GOAMD64=v3, `:$sha-amd64v1` GOAMD64=v1). Docker build context is the repo root.
- **Push a tag** → `go-release.yaml`: same plus `:latest` and `:{tag}`
- Registries: `us-docker.pkg.dev/moonrhythm-containers/gcr.io/` and `asia-southeast3-docker.pkg.dev/moonrhythm-core/public/`

## Module

```
module github.com/moonrhythm/parapet-ingress-controller
go 1.26.4
```

The module lives at the repo root, so `go install` targets are `…/parapet-ingress-controller/cmd/parapet-ingress-controller`. (A deprecated, frozen Rust implementation lives in `rust/` — kept for reference only; do not edit it.) Key dependencies: `github.com/moonrhythm/parapet`, `k8s.io/client-go`, `go.opentelemetry.io`, `github.com/prometheus/client_golang`, `cloud.google.com/go/profiler`.

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
