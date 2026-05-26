# parapet-ingress-controller (Rust / Pingora)

The [Pingora](https://github.com/cloudflare/pingora) implementation of the
Kubernetes ingress controller. It watches Ingress / Service / Secret / ConfigMap /
Endpoints and hot-reloads its routing and TLS tables without restarting.

> **One of two co-maintained implementations** (the other is the parapet/Go build
> in [`../go/`](../go/)). They share one behavior contract — see
> [`../SPEC.md`](../SPEC.md). GCP Cloud Profiler and Cloud Trace are Go-only (no
> Rust SDK). `PHASE{0,3,5}.md` are the original de-risk/perf notes from the port's
> development.

The full request data path matches the contract: routing (all PathTypes), TLS/SNI
with full-chain serving, h2c, all `parapet.moonrhythm.io/*` annotations,
host/country concurrency, per-route rate limits, forward/basic auth, trust-proxy,
graceful drain, JSON access log, response compression, and the WAF. The shared
annotation/env/metrics reference is [`../SPEC.md`](../SPEC.md); Rust-specific
behavior and divergences are documented below.

## Layout

```
rust/
  controller/         # the crate (lib `controller`, bin `parapet-ingress-controller`)
    src/proxy/        # Pingora ProxyHttp: routing, upstream (http/https/h2c),
                      #   retry + bad-addr, middleware, metrics, SNI, server wiring
    src/{router,route,cert,config,reconcile,shared,k8s}.rs
                      #   pure routing/reconcile core (no pingora/kube deps)
  spike/              # throwaway Phase-0 de-risk proof (see PHASE0 findings)
  bench/              # k6 load harness (load.js + run.sh)
  Dockerfile          # multi-stage; distroless/cc-debian13 runtime (~41 MB)
  PHASE{0,3,5}.md     # de-risk findings / cluster validation / perf-parity gate
```

The core (`router`, `route`, `cert`, `config`, `reconcile`, `shared`, `k8s::fs`)
has no async / kube / pingora dependencies, so it builds and unit-tests in ~1s.

## Build & test

```bash
cd rust

# fast core (default features) — pure routing/reconcile/cert logic
cargo test -p parapet-ingress-controller

# full surface (proxy + cluster watch)
cargo test -p parapet-ingress-controller --features proxy,cluster

# lint / format (CI runs these)
cargo clippy -p parapet-ingress-controller --features proxy,cluster --all-targets
cargo fmt -p parapet-ingress-controller --check
```

### Cargo features

| Feature   | Pulls in            | Purpose |
|-----------|---------------------|---------|
| `cluster` | `kube-rs`           | live in-cluster watch (reflector stores) |
| `proxy`   | `pingora` (openssl) | the HTTP/HTTPS proxy server |

The binary requires **both** (`required-features = ["proxy", "cluster"]`). The
default (no-feature) build is the pure core used for fast iteration and tests.

> macOS: a gitignored `rust/.cargo/config.toml` points at Homebrew OpenSSL. CI and
> Docker resolve TLS via `pkg-config` / `libssl-dev` instead.

## Run

Against the live cluster (uses the in-cluster service account or your kubeconfig):

```bash
HTTP_PORT=8080 HTTPS_PORT=8443 \
  cargo run -p parapet-ingress-controller --features proxy,cluster
```

Against static manifests, no cluster (local dev / smoke tests):

```bash
KUBERNETES_BACKEND=fs KUBERNETES_FS=./path/to/manifests \
HTTP_PORT=8080 HTTPS_PORT=8443 \
  cargo run -p parapet-ingress-controller --features proxy,cluster
```

The Prometheus endpoint is served on `0.0.0.0:9187` (`/metrics`).

## Configuration (environment variables)

### Listeners & routing

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `80` | Plaintext (+ h2c) listener port |
| `HTTPS_PORT` | `443` | TLS listener port. **Set empty** (`HTTPS_PORT=`) to disable HTTPS and run HTTP-only (e.g. an internal-ingress controller); *unset* still defaults to 443 |
| `INGRESS_CLASS` | `parapet` | `ingressClassName` to handle |
| `WATCH_NAMESPACE` | `""` (all) | Restrict the watch to one namespace |
| `POD_NAMESPACE` | `""` | Current pod's namespace (informational; logged at startup) |

### Kubernetes data source

| Variable | Default | Description |
|---|---|---|
| `KUBERNETES_BACKEND` | `cluster` | `cluster` (kube-rs watch) or `fs` (static manifests, one-shot) |
| `KUBERNETES_FS` | — | Directory of YAML/JSON manifests; **required** when `KUBERNETES_BACKEND=fs` |

### TLS

| Variable | Default | Description |
|---|---|---|
| `LOAD_ALL_CERTS` | `false` | Load every `kubernetes.io/tls` secret in the watched namespace, not just those referenced by an Ingress's `spec.tls.secretName` (lets a wildcard cert serve SNI without per-ingress wiring) |

The TLS resolver serves the **full chain** from each secret's `tls.crt` (leaf +
intermediates) and selects the leaf by SNI (exact, then a single-label wildcard
climb). Unknown SNI gets a self-signed fallback — watch
`parapet_tls_sni_no_cert_total` if clients report `unknown authority`.

### Proxy / trust

| Variable | Default | Description |
|---|---|---|
| `TRUST_PROXY` | `""` | `true`, `false`, or a comma-separated list of CIDRs and/or shorthands (`cloudflare`, `google`, `bunny`). Controls whether incoming `X-Forwarded-*` is trusted |

### Connection timeouts & pooling

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_CONNECT_TIMEOUT` | `2s` | TCP connect timeout to an upstream pod (connect phase only — never data transfer) |
| `UPSTREAM_TOTAL_CONNECT_TIMEOUT` | `3s` | Connect + TLS-handshake timeout to an upstream pod |
| `TR_MAX_IDLE_CONNS_PER_HOST` | Pingora default (128) | Maps to Pingora's **process-global** upstream keepalive pool size (not per-host like Go's `Transport.MaxIdleConnsPerHost`) |

The connect-timeout defaults are sized for same-zone, intra-cluster pods
(single-digit-ms connects); they bound worst-case `MAX_RETRY × timeout` pileup
when a backend is overwhelmed. Raise them for cross-zone/region upstreams. Values
use Go-duration syntax: `1500ms`, `2s`, `1m`, `1h`, or a bare integer (seconds).

### Concurrency limits (opt-in)

| Variable | Default | Description |
|---|---|---|
| `HOST_CONCURRENT_CAPACITY` | `0` (off) | Max in-flight requests per host; reject (503) above it |
| `HOST_CONCURRENT_SIZE` | `0` | Extra queued requests allowed to wait (0 = no queue, reject immediately) |
| `HOST_COUNTRY_CONCURRENT_CAPACITY` | `0` (off) | Per-host+country in-flight cap |
| `HOST_COUNTRY_CONCURRENT_SIZE` | `0` | Per-host+country queue size |
| `HOST_COUNTRY_HEADER` | `""` | Comma-separated header names carrying the country code (enables the per-country limit) |

### Lifecycle, logging & debug

| Variable | Default | Description |
|---|---|---|
| `WAIT_BEFORE_SHUTDOWN` | `30s` | On SIGTERM, mark not-ready and keep serving this long before draining, so the LB/endpoints deregister this pod first (Go-duration syntax) |
| `DISABLE_LOG` | `false` | Suppress the JSON access log |
| `DEBUG_ENDPOINTS` | `false` | Serve `GET /debug/routes` (loaded route keys + cert SNIs + readiness) for diagnosis |
| `RUST_LOG` | `info` | Log filter for Pingora's internal `log` output (h2 handshake errors, etc.) |

### WAF (opt-in)

A CEL-rule firewall on the [`cel`](https://crates.io/crates/cel) crate, the port
of the Go controller's `parapet/pkg/waf`. A global baseline ruleset plus
per-tenant zones, all from label-marked ConfigMaps; an ingress binds a zone via
`parapet.moonrhythm.io/waf-zone`. **Full model and rule reference: [`../WAF.md`](../WAF.md).**

| Variable | Default | Description |
|---|---|---|
| `WAF_ENABLED` | `false` | Master switch. When off the proxy does no WAF work and the ConfigMap watch isn't started |
| `WAF_FAIL_MODE` | `open` | `open` (a rule eval error is logged and skipped) or `closed` (eval error → 500) |
| `WAF_EVAL_TIMEOUT` | `5ms` | Per-request deadline for the whole ruleset, checked between rules (Go-duration syntax) |
| `WAF_GEOIP_DB` | `""` | Path to a MaxMind GeoLite2/GeoIP2 `.mmdb` (`maxminddb` crate); enables `request.country` (ISO alpha-2 from the client IP). `""` when off, `"XX"` when the DB can't place the IP. Load failure is non-fatal |

Global rules are honored only from ConfigMaps labeled
`parapet.moonrhythm.io/waf: global` in `POD_NAMESPACE`; zones are ConfigMaps
labeled `parapet.moonrhythm.io/waf: zone` (the zone id is the ConfigMap name).
The WAF watch runs on its own reflector — rule edits recompile the rulesets
without rebuilding the router. The `fs` backend reads WAF ConfigMaps from the
manifest directory at startup (no live reload).

> Not configurable in this port: `TR_MAX_CONNS_PER_HOST` and
> `HTTP_SERVER_MAX_HEADER_BYTES` (no Pingora 0.8 equivalent). The metrics endpoint
> address (`:9187`) is fixed. WAF cost-limit / body-inspection / macro toggles
> (`WAF_COST_LIMIT`, `WAF_INSPECT_BODY`, `WAF_DISABLE_MACROS` in Go) are not
> supported here — see *Behavior notes* below.

## Metrics

Registered in the process-default registry and served at `:9187/metrics`. Names
and labels match the Go controller so existing dashboards keep working:

- `parapet_requests{host,status,method,ingress_name,ingress_namespace,service_type,service_name}`
- `parapet_service_duration_seconds{service_type,service_namespace,service_name}`
- `parapet_reload{success}`
- `parapet_host_active_requests{host,upgrade}`, `parapet_host_ratelimit_requests{host}`
- `parapet_backend_network_read_bytes{addr}` / `_write_bytes{addr}` (body bytes)
- `parapet_backend_connections{addr}` (in-flight-per-addr approximation; Pingora pools connections)
- `parapet_network_request_bytes` / `parapet_network_response_bytes`
- `parapet_tls_sni_no_cert_total{reason}` — TLS handshakes served the self-signed
  fallback (`reason` = `no_sni` | `no_match` | `parse_error`); a rising rate means
  clients see `unknown authority`
- `parapet_waf_matches{rule_id,action,scope}` — WAF rule matches (`scope` =
  `global` | `zone`); WAF blocks also increment `parapet_rejected_requests{reason="waf"}`
- `process_*` (Linux only; a custom `/proc` collector — `process_cpu_seconds_total`
  is float, ms-precision)

To bound cardinality under a flood, a `Host` the router doesn't serve (and any
non-standard HTTP method) is collapsed to the label value `other` rather than
creating an unbounded number of series.

**Known metric gaps vs Go:** `parapet_connections` (downstream connection gauge by
state — no Pingora `ConnState` equivalent) and `go_*` runtime metrics.

## Behavior notes / differences from Go

- **Retry is connection-only.** The proxy retries (up to 5×, marking the bad pod
  and round-robining) only on *connection* failures — `fail_to_connect` and a
  reused keepalive connection breaking before a response. It **never** retries on
  an upstream HTTP status (Go retried 502/503): once the upstream responds it has
  processed the request, so retrying could duplicate side effects and amplify load.
- **DDoS resilience.** Bounded upstream connect timeouts (above), host/method
  metric-cardinality bounding, a downstream `keepalive_request_limit`, and a 60s
  default downstream read timeout (Slowloris).
- **Two services share one state.** A plaintext+h2c service and a TLS+SNI service
  share one hot-swappable `Shared` (router/cert table behind `ArcSwap`); reloads
  are coalesced with a 300ms debounce.
- **WAF parity, with three intentional divergences from cel-go.** Rule *strings*
  are portable (a shared cross-impl test corpus guards this), but: (1) **no cost
  limit** — cel-rust has none, so the `WAF_EVAL_TIMEOUT` deadline is checked
  *between* rules (eval isn't interruptible mid-expression) and `regexMatch` uses
  the linear `regex` crate; (2) **body inspection is phase-2** — `request.body` is
  always empty, matching Go's default; (3) a **non-bool result or missing map key
  is a runtime error** (fail-open by default), since cel-rust is dynamically typed
  and can't reject it at compile time like cel-go's `OutputType` check.

## Docker

```bash
docker build -t parapet-ingress-controller:rust rust/
# optional CPU baseline (mirrors the Go GOAMD64 split):
docker build --build-arg TARGET_CPU=x86-64-v3 -t ...:rust rust/
```

- Builder: `rust` toolchain image; runtime: `gcr.io/distroless/cc-debian13` (~41 MB).
- `TARGET_CPU` build-arg sets `-C target-cpu=...`; use `x86-64-v3` for modern CPUs
  or `x86-64` (baseline, Go's `GOAMD64=v1` equivalent) for the compatibility image.

## CI

- `.github/workflows/rust-test.yaml` — fmt + clippy + test on push/PR.
- `.github/workflows/rust-build.yaml` — builds and pushes `rust-`-prefixed images
  on `master`.

Both are path-filtered to `rust/**`, so Go-only changes never trigger them.
