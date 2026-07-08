# parapet-ingress-controller

A Kubernetes ingress controller built in Go on the [parapet](https://github.com/moonrhythm/parapet) middleware framework. It watches Kubernetes Ingress, Service, Secret, ConfigMap, and EndpointSlice resources and hot-reloads an `http.ServeMux` router without restarting the process.

> The behavior contract — annotations, env vars, metrics, WAF model,
> per-request order — is [`SPEC.md`](SPEC.md): change behavior in the code and
> update SPEC.md to match. This file is the architecture guide; the Go module
> lives at the repo root, so the paths below are relative to it.

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
controller_ratelimit.go           # rate-limit wiring: global set + zone registry, 2nd ConfigMap watch
controller_coraza.go              # Coraza (OWASP CRS/SecLang) wiring: global + zone registry, 3rd ConfigMap watch
retry.go                          # retryMiddleware — retries idempotent requests on upstream failure
corazawaf/                        # OWASP Coraza engine wrapper: hot-swap coraza.WAF + request-phase middleware (pure, edge-importable)
wafrule/                          # WAF rule YAML DTO + parser (-> []waf.Rule)
wafclaim/                         # edge→core X-Parapet-Waf claim header (wire contract shared by core + edge)
ratelimitrule/                    # rate-limit YAML DTO + parser + runtime (hot-swap Limiter, fixed/sliding strategies)
geoip/                            # IPLocate ip-to-country/ip-to-asn .mmdb -> request.country/asn (WAF_GEOIP_DB/WAF_ASN_DB)
plugin/                           # annotation-driven middleware plugins
  plugin.go                       # core plugin type + built-in plugins
  auth.go                         # BasicAuth, ForwardAuth
  waf.go                          # WAFZone — bind ingress to a WAF zone by reference
  ratelimitzone.go                # RateLimitZone — bind ingress to a rate-limit zone (same-ns only)
  corazazone.go                   # CorazaZone — bind ingress to a Coraza zone by reference (cross-ns allowed)
  zone.go                         # ZoneKey — shared zone-reference annotation resolver
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
  requests.go, backendconns.go, host.go, reload.go, waf.go, coraza.go
  cache.go                        # generic lock+map cache for per-label-set metric handles
state/                            # per-request state map (passed via context)
trustcidr/                        # TRUST_PROXY spec -> parapet trust Conditional (CIDRs + cloudflare/google/bunny); shared by controller + edge
debounce/                         # debounce helper used for reload coalescing
edgecp/                           # edge control-plane lib (cert store, authz, reload, REST server)
cmd/edge-controlplane/            # edge control-plane binary (see EDGE.md)
edge/                             # edge proxy lib: certstore, cp (CP client), waf, coraza, ratelimit, refresh, forward (cache is parapet/pkg/cache)
cmd/edge-proxy/                   # out-of-cluster edge proxy binary (parapet framework; see EDGE.md)
Dockerfile                        # controller image (multi-stage Go build, pure Go / no CGO, distroless/static)
Dockerfile.edge-controlplane      # control-plane image (pure Go, distroless/static)
Dockerfile.edge                   # edge proxy image (pure Go, distroless/static + baked GeoIP)
# also at repo root: deploy/  WAF.md  RATELIMIT.md  CORAZA.md  SPEC.md  EDGE.md  conformance/
# .github/workflows/: go-test / go-build / go-release .yaml (path-filtered to **/*.go + go.mod/go.sum);
#   edge-build / edge-e2e .yaml build + smoke-test the edge + control-plane images
#   (edge-build images are multi-arch: linux/amd64 + linux/arm64, cross-compiled, no QEMU)
```

### Edge proxy (`cmd/edge-proxy` + `edge/`)
The out-of-cluster edge, on the same parapet framework as the controller (see
[`EDGE.md`](EDGE.md)). It fetches cert+key + WAF rules from the in-cluster
control plane (`edge/cp.go`), terminates public TLS via a hot-swappable
`cert.Table` (`edge/certstore.go`, self-signed fallback on SNI miss, on-demand
fetch in serve-all mode), runs global + zone WAF (`edge/waf.go`, reusing
`parapet/pkg/waf` + `wafrule` + `geoip` exactly like the controller), optionally
enforces the ConfigMap-driven global+zone rate limits (`edge/ratelimit.go`,
`EDGE_RATELIMIT_ENABLED`, reusing `ratelimitrule` exactly like the controller;
per-edge counters, mounted after the WAF and before the cache), optionally
caches responses via `parapet/pkg/cache` (memory or disk backend,
selected by `EDGE_CACHE_BACKEND`; `EDGE_CACHE_CHUNKED` (default on) also caches
no-`Content-Length` chunked/on-the-fly-compressed bodies by buffering to derive a
length — safe because the `httputil.ReverseProxy` forwarder aborts on a truncated
upstream so a partial body never commits), and forwards to parapet (`edge/forward.go`) — **HTTP/2 by default**: h2c on the plaintext `:80` hop, ALPN-negotiated h2 (HTTP/1.1 fallback) on the re-encrypt `:443` hop, `EDGE_UPSTREAM_HTTP2=false` forces HTTP/1.1; WebSocket/Upgrade always rides HTTP/1.1 (`H2CTransport` downgrades it, the re-encrypt path routes it to a dedicated h1 transport). Refresh loops are fail-static
(`edge/refresh.go`, `edge/wafrefresh.go`, `edge/ratelimitrefresh.go`); by default the CP's `GET /v1/events`
SSE change stream (`edge/events.go` + `edgecp/events.go`, `EDGE_EVENTS_ENABLED`/`CP_EVENTS_ENABLED`) pokes
them on change — a version-vector wake-up signal only, so updates land in seconds while the jittered polls
stay the correctness floor (stream failure / 404 from an old CP ⇒ pure polling). It is **not** the controller — no k8s
client, no Ingress watch — so it lives beside, not inside, the controller. Like
the controller it honors `TRUST_PROXY` (shared `trustcidr` package): default `""`
keeps the first-hop distrust posture; set it (e.g. `cloudflare`) when the edge
sits behind another L7 proxy so the real client IP flows through to WAF/geo/log
and the upstream hop.

## Key concepts

### Controller lifecycle
`Controller.Watch()` starts five goroutines that continuously watch Ingress, Service, Secret, EndpointSlice, and (legacy fallback) Endpoints resources (plus a sixth, WAF ConfigMaps, when `WAF_ENABLED=true`, a seventh, rate-limit ConfigMaps, when `RATELIMIT_ENABLED=true`, and an eighth, Coraza ConfigMaps, when `CORAZA_ENABLED=true`). Changes are coalesced through a 300 ms `debounce.Debounce` before triggering a reload. On reload, a new `http.ServeMux` is built and swapped in atomically (`atomic.Pointer[routeState]`) — zero downtime. WAF, rate-limit, and Coraza ConfigMap changes are the exception: they recompile their rulesets/limit sets without rebuilding the mux (see the WAF, rate-limit, and Coraza concepts below).

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

Endpoint lookup is round-robin (`route.RRLB`). Pod IPs come from the Service's EndpointSlices (`discovery.k8s.io/v1`) — a Service may own several slices, so they're unioned (ready addresses only, keyed back to the Service via the `kubernetes.io/service-name` label). **EndpointSlices are authoritative**: a Service that owns at least one slice (even an empty one) is routed from its slices alone; only a Service with *no* slice falls back to its legacy `Endpoints` object (`aggregateServiceIPs` / `resolveTargetPort`, the no-mirror / `skip-mirror` case). Bad addresses (dial errors) are marked and skipped temporarily.

**ExternalName Services** (`spec.type: ExternalName`) are supported via a separate `route.Table` map (`addrToExternalName`, set by `reloadServiceDebounced` via `SetExternalNameRoutes` — full-replace, so it never races the incremental endpoint host-route path). They have no EndpointSlices, so `Table.Lookup` falls back to dialing `spec.externalName` (resolved by the dialer's `net.Resolver`) on the **service port** the ingress references (no `targetPort` indirection; no RRLB/bad-addr — single target). A pod-backed host route takes precedence over an ExternalName one (only transiently overlapping during a type change). See [`SPEC.md`](SPEC.md).

### TLS
TLS secrets are loaded from `Secret.Data["tls.crt"]` / `["tls.key"]`. The `cert.Table` provides `GetCertificate` for SNI-based lookup (exact match, then a single-label wildcard climb), plugged directly into `tls.Config`. By default only secrets referenced by an Ingress's `spec.tls.secretName` are loaded; set `LOAD_ALL_CERTS=true` to index every TLS-typed secret in the watch namespace (lets a wildcard cert serve SNI without per-ingress wiring).

### Proxy
`proxy.Proxy` wraps `httputil.ReverseProxy`. The upstream URL is resolved at request time via `route.Table.Lookup`. Protocol is controlled by the `parapet.moonrhythm.io/upstream-protocol` annotation (default: `http`).

On a **connection failure** (dial error — no response from upstream), the proxy's `ErrorHandler` panics; `retryMiddleware` (`retry.go`) recovers it and retries the request (up to 5 times with backoff) — but only when the body hasn't been read, so non-idempotent requests aren't replayed. `proxy.IsRetryable` is **dial-error-only**: an upstream that *responds* — including 502/503 — has processed the request, so its response passes through to the client unchanged rather than being retried (retrying could duplicate side effects and amplify load on a failing backend). See [`SPEC.md`](SPEC.md).

**Auto-h2c detection** (opt-in, `UPSTREAM_AUTO_H2C=true`, Go-only): `proxy.EnableAutoH2C(ttl)` swaps the gateway's plain-`http` path for `autoH2CTransport` (`proxy/autoh2c.go`), which speculatively tries h2c first and falls back to HTTP/1.1 when the upstream isn't HTTP/2. Each probe outcome — **positive (h2c) or negative (HTTP/1.1-only)** — is cached in a `sync.Map` **keyed per-Service** (`<ns>/<name>:<port>`, stamped into request `state` as `upstreamKey` by `makeHandler`; falls back to the dialed `host:port`), so the cache stays bounded as pods churn and a new pod of a known Service skips the probe. Entries carry a **TTL** (`UPSTREAM_AUTO_H2C_TTL`, default 10m): on expiry the upstream is re-probed, so a Service that gains or loses h2c support is re-detected without a restart (this replaces the earlier clear-on-reload). A **fresh** cached entry takes the fast path straight to the right transport — so steady h2c traffic is fully multiplexed and never serialized. Only **unknown/expired** upstreams reach the **single-flight** guard (`probing sync.Map`): one request probes while the rest use HTTP/1.1, so a cold start or TTL expiry can't trigger a herd of failed h2c connections. Fallback safety: **only bodyless requests probe.** The h2c client streams any request body as DATA frames (consuming it) before its read loop detects an HTTP/1.1 peer and fails — leaving nothing to replay over HTTP/1.1 and surfacing `http2: frame too large … looked like an HTTP/1.1 header`. So a request carrying a body (`hasBody` ⇒ `ContentLength != 0`, including chunked `-1`) is routed straight to the fallback **without probing or caching**; a later bodyless request establishes the verdict for the whole Service, after which bodied requests ride the cached transport via the fast path. Trade-off: a plain-http upstream that is h2c-only **and** only ever receives bodied requests never auto-upgrades — those should set `appProtocol: h2c` explicitly. A **dial error is not an h2c signal** — it propagates to the retry path and is never cached. WebSocket/Upgrade requests always take HTTP/1.1 (httputil.ReverseProxy has no RFC 8441 HTTP/2 path) and are never probed or cached; `https` and explicit `appProtocol: h2c` upstreams are untouched.

### WAF (opt-in, `WAF_ENABLED=true`)
A CEL-rule firewall on top of `parapet/pkg/waf`. **Full design in [`WAF.md`](WAF.md).** Two rulesets, both fed by label-marked ConfigMaps (`parapet.moonrhythm.io/waf: global|zone`), watched as a 5th resource:
- **Global** (`globalWAF`, mounted in `main.go`'s `m` chain before `ctrl`) — one baseline ruleset, honored only from `POD_NAMESPACE`, applied to all traffic.
- **Zones** (`zones atomic.Pointer[map[string]*waf.WAF]`, key `<namespace>/<name>`) — tenant rulesets an ingress binds via `parapet.moonrhythm.io/waf-zone`; `plugin.WAFZone` resolves the key (namespace-local, or `ns/id` cross-ref) and looks up the live registry per request.

Global runs first and is authoritative. **WAF reload is decoupled from the mux**: ConfigMap changes call `reloadWAFDebounced` (recompile + atomic swap) and never rebuild routes; `SetRules` is all-or-nothing so a bad ruleset keeps the last-good one. Rules parse via `wafrule/`; matches count `parapet_waf_matches{rule_id,action,scope}` (`metric/waf.go`). **`WAF_VALIDATED_PROXY`** (opt-in, default off) skips global+zone evaluation for requests whose peer already ran the same rules at the edge: a comma list of `edge-mtls` (peer client cert chains to the live edge CA via `trust.Manager.VerifyClientCert`; requires `EDGE_TRUST_CP_ENDPOINT`) and/or CIDRs/named groups (immediate TCP peer — parapet never rewrites `r.RemoteAddr`, so the check is sound mid-chain). The skip additionally requires the per-request claim header (`wafclaim.Header`, `X-Parapet-Waf`): the edge stamps it after its WAF evaluated the request (`EdgeWAF.ClaimStamp`, generation-gated so the empty boot ruleset never claims) and strips client-supplied values unconditionally (`edge.StripWAFClaim`, mounted even when `EDGE_WAF_ENABLED=false`); the core's `GlobalWAF()` wrapper deletes unvalidated claims so they never reach rules, the zone check, or the upstream — which is how the core tells a WAF-running edge apart per request. Parsed by `buildWAFValidatedProxy` (`cmd/parapet-ingress-controller/wafvalidated.go`) into `WAFConfig.SkipValidated`, honored by `GlobalWAF()` and `plugin.WAFZone`, counted as `parapet_waf_skips{scope}`; `true` is refused and a bad spec is fatal at startup (EDGE.md documents the authority trade-offs). Code: `controller_waf.go`, `plugin/waf.go`, `wafrule/`.

### Rate limiting (opt-in, `RATELIMIT_ENABLED=true`)
ConfigMap-driven request-rate limits mirroring the WAF's zone model under their own label (`parapet.moonrhythm.io/ratelimit: global|zone`), watched as a 6th resource (separate label key — selectors can't OR — and separate store/debounce). **Full design in [`RATELIMIT.md`](RATELIMIT.md).**
- **Global** (`globalRateLimit`, mounted right after the global WAF — WAF-blocked traffic never burns rate budget) — only honored from `POD_NAMESPACE`.
- **Zones** (`rlZones atomic.Pointer[map[string]*ratelimitrule.Limiter]`, key `<namespace>/<name>`) — bound via `parapet.moonrhythm.io/ratelimit-zone`, **same-namespace only** (deliberate divergence from `waf-zone`: zones carry shared counter state, so a cross-ns bind would be a cross-tenant DoS channel; `plugin.RateLimitZone` warns and ignores cross-ns refs).

Limits: `id` / `key` (a characteristic or composite list — `ip` with IPv6-/64 bucketing, `host` with unknown-Host collapsing, `asn`/`country` from the shared GeoIP resolvers (`RateLimitConfig.ASN/Country`; the WAF_GEOIP_DB/WAF_ASN_DB databases load when WAF **or** ratelimit is enabled, and SetLimits rejects geo keys when the resolver is missing), `header:<name>`/`cookie:<name>` with 128-byte value truncation but client-mintable cardinality — see RATELIMIT.md's warning) / `rate`+`window` (1s..1h) / `algorithm` (`fixed` = parapet `FixedWindowStrategy` directly — requires parapet ≥ v0.18.1, whose `After` computes the reset on the epoch grid (parapet#244; an epoch-grid canary test pins the floor); `sliding` = own two-generation-map reimplementation of parapet's math, retained after parapet v0.18.1 fixed the janitor leak (parapet#243) for its zero-goroutine storage, O(1) generation eviction, and stricter backward-clock semantics) / `mode` (`enforce|shadow`) / `status` (429|503) / `exclude` CIDRs / `filter` (optional CEL expression scoping the limit to matching requests — the WAF's exact expression surface via `waf.Predicate`, an additive export from `parapet/pkg/waf` reusing its `newCELEnv`+`buildRequestMap` so the two CEL surfaces can't drift; `key` still buckets, `filter` only gates; built once per request and shared across filtered limits; `request.body` always `""`; geo-ref without DB never matches (not a load error, unlike a geo *key*); eval error fails **open** (limit skipped); bad expr rejected at load; filter-only edits preserve counters since `filter` is out of `cfgKey`). `/.well-known/acme-challenge` is never limited. Reload mirrors the WAF (`rlReloadMu` for the debounce-overlap hazard, fingerprint skip, all-or-nothing `SetLimits` keeps last-good) and additionally **preserves live counters**: unchanged input isn't reapplied, and `SetLimits` carries strategies over when a limit's shaping config didn't change. Decisions count in `parapet_ratelimit_total{name,result}` with names `global:<id>` / `zone:<ns>/<name>:<id>` (the `zone:` prefix avoids colliding with the annotation limiters' `<ns>/<ingress>:<s|m|h>`). **Edge enforcement is opt-in** (`EDGE_RATELIMIT_ENABLED` on the edge + `CP_RATELIMIT_ENABLED` on the CP): the CP distributes the same ConfigMap sets via `GET /v1/ratelimit` (`edgecp/ratelimitstore.go` + `ratelimitreload.go`; path-aware route→zone bindings from `ratelimit-zone` same-ns only — the controller's own route keys, matched at the edge on a real `http.ServeMux` (`edge/zoneroute.go`, shared with the edge WAF; legacy host→zone still shipped for old edges) — plus a known-hosts list for host-key collapse; documents ship as `[]string` — `ratelimitrule.Parse` takes one YAML doc per string, never `"---"`-joined), and the edge runs them via `edge/ratelimit.go` (reuses `ratelimitrule.Limiter` with `metric/observe.RateLimit` — the leaf package, keeping the edge binaries off `metric`) after the edge WAF and before the cache; counters are per edge. See EDGE.md. Code: `controller_ratelimit.go`, `plugin/ratelimitzone.go`, `ratelimitrule/`, `edge/ratelimit.go`, `edgecp/ratelimitstore.go`.

### Coraza firewall (opt-in, `CORAZA_ENABLED=true`)
A second, **signature-based** WAF built on [OWASP Coraza](https://github.com/corazawaf/coraza) (ModSecurity SecLang + embedded OWASP CRS, pure-Go/no-CGO), **independent of and complementary to** the CEL WAF — both can run together or alone. Same global+zone model under its own label (`parapet.moonrhythm.io/coraza: global|zone`), watched as a 7th resource (separate label/store/debounce — selectors can't OR, and SecLang ≠ CEL). **Full design in [`CORAZA.md`](CORAZA.md).**
- **Global** (`globalCoraza`, mounted right after the global CEL WAF and before the global rate limit) — only honored from `POD_NAMESPACE`. Active iff a global ConfigMap exists.
- **Zones** (`corazaZones atomic.Pointer[map[string]*corazawaf.Instance]`, key `<namespace>/<name>`) — bound via `parapet.moonrhythm.io/coraza-zone`, **cross-namespace allowed** (the WAF model — rulesets are stateless config, unlike rate-limit zones). Active iff the zone ConfigMap exists, so "global off, one zone on" = no global ConfigMap + one bound zone.

The engine lives in `corazawaf/` (a pure, edge-importable package): a `coraza.WAF` is immutable, so `SetDirectives` builds a new one and swaps it via `atomic.Pointer` (empty input → nil → pass-through); all-or-nothing keeps last-good. The middleware runs **request phases only** (URI + headers always; request body opt-in via `CORAZA_REQUEST_BODY_LIMIT`, rebuilt so the upstream still gets the full body) — **response-body inspection is never enabled** (it would break streaming/cache/HTTP2). Matches come from `tx.MatchedRules()` (not the error callback, which only fires for logged rules) → `metric.CorazaMatch` / `parapet_coraza_matches{rule_id,severity,scope}` + `observe.CorazaEval`. Reload mirrors the WAF exactly (`corazaReloadMu` overlap guard, fingerprint skip, decoupled from the mux). **Edge enforcement** (`EDGE_CORAZA_ENABLED` + `CP_CORAZA_ENABLED`): the CP distributes rulesets via `GET /v1/coraza` (`edgecp/corazastore.go` + `corazareload.go`, route→zone bindings via `edge/zoneroute.go` — **no legacy host map**, Coraza is new), the edge runs them (`edge/coraza.go`, `corazarefresh.go`) as **defense-in-depth with no validated-proxy claim** — the core always re-runs its own Coraza (parapet stays authoritative). Code: `controller_coraza.go`, `corazawaf/`, `plugin/corazazone.go`, `metric/coraza.go`, `edge/coraza.go`, `edgecp/corazastore.go`.

**GeoIP** (`request.country`): `WAF_GEOIP_DB` defaults to the baked `/geoip/ip-to-country.mmdb` (set `""` to disable; a missing file at the default path is a quiet no-op, a missing explicit path logs an error). `main.go` opens it (`geoip/`, `maxminddb-golang`, flat `country_code` schema, not MaxMind's nested `country.iso_code`) and sets `WAFConfig.Country` to a resolver (client IP via `geoip.ClientIP`, parapet precedence → ISO code, else `"XX"`). `newWAF` assigns it to every WAF's `waf.WAF.Country` (the parapet hook added in v0.15.1), so `request.country` is set on the global and zone rulesets. nil resolver (no DB) → `request.country == ""`.

**ASN** (`request.asn`): the same pattern with `WAF_ASN_DB` (defaults to the baked `/geoip/ip-to-asn.mmdb`; `""` disables) → `geoip.OpenASN`/`(*ASNDB).ASN` (IPLocate stores `asn` as a string; parsed to `int64`) → `WAFConfig.ASN` → every WAF's `waf.WAF.ASN` (the parapet hook added in **v0.15.2**). nil resolver (no DB) or unplaceable IP → `request.asn == 0`.

## Annotation & configuration reference

The annotation reference, env-var table, and per-request order are the
**contract** — see [`SPEC.md`](SPEC.md). Implementation notes: `auth.go`
documents the `basic-auth` / `forward-auth` formats; the WAF tunables
(`WAF_COST_LIMIT`, `WAF_INSPECT_BODY`, `WAF_DISABLE_MACROS`) are documented in
[`WAF.md`](WAF.md).

## Build & run

```bash
# Run locally against current kubeconfig
KUBERNETES_LOCAL=true HTTP_PORT=8080 HTTPS_PORT=8443 go run ./cmd/parapet-ingress-controller

# Run tests
go test ./...

# Build Docker image via buildctl
make go-build-dev

# Build binary directly (pure Go, no CGO)
CGO_ENABLED=0 go build -o parapet-ingress-controller \
  -ldflags "-w -s -X main.version=$(git describe --tags)" \
  ./cmd/parapet-ingress-controller
```

Before committing, run `gofmt -l .` (must print nothing) and `go vet ./...` — CI
fails on unformatted files. See the umbrella [`Makefile`](Makefile) for the
`make test` target.

### Docker image
- Builder: `golang:1.26.5-trixie` (pure Go, `CGO_ENABLED=0`) — cross-compiles, so the image is multi-arch-capable (linux/amd64 + linux/arm64) without QEMU like the edge images
- Runtime: `gcr.io/distroless/static-debian12` (static binary; root variant so it can bind privileged :80/:443)
- Build args: `VERSION` (injected as `main.version`), `GOAMD64` (v3 default, v1 for compatibility image; honored only for amd64)

## CI / Release

All path-filtered to `**/*.go` + `go.mod`/`go.sum` (plus `Dockerfile*`):
- **Push & PR touching Go files** → `go-test.yaml`: `go vet` + `go test -race`
- **Push to `main`** → `go-build.yaml`: pushes two images tagged with `$GITHUB_SHA` — `:$sha` is a **multi-arch manifest** (linux/amd64 GOAMD64=v3 + linux/arm64; pure-Go cross-compile, no QEMU), and `:$sha-amd64v1` is the amd64-only GOAMD64=v1 compatibility image (no arm64 — GOAMD64 levels are amd64-only). Docker build context is the repo root.
- **Push a tag** → `go-release.yaml`: same plus `:latest` and `:{tag}`
- Registries: `us-docker.pkg.dev/moonrhythm-containers/gcr.io/` and `asia-southeast3-docker.pkg.dev/moonrhythm-core/public/`

## Module

```
module github.com/moonrhythm/parapet-ingress-controller
go 1.26.5
```

The module lives at the repo root, so `go install` targets are `…/parapet-ingress-controller/cmd/parapet-ingress-controller`. Key dependencies: `github.com/moonrhythm/parapet`, `k8s.io/client-go`, `go.opentelemetry.io`, `github.com/prometheus/client_golang`, `cloud.google.com/go/profiler`.

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
