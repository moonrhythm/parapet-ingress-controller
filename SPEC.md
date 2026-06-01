# Behavior contract

This is the **single source of truth** for what the controller does — the
contract that **both** implementations ([`go/`](go/) and [`rust/`](rust/)) must
honor. When behavior changes, change it here first, then in both implementations
and the [`conformance/`](conformance/) fixtures.

Anything marked **Go-only** or **Rust-only** is an intentional divergence (with a
reason); everything else must behave identically across the two binaries.

## IngressClass

Handles Ingresses whose `ingressClassName` (or the legacy
`kubernetes.io/ingress.class` annotation) equals `INGRESS_CLASS` (default
`parapet`). Others are ignored.

## Routing

Routes are keyed `host + path`. PathType semantics:

| PathType | Registration |
|---|---|
| `Prefix` | both `host/path` and `host/path/` |
| `Exact` | `host/path` only (trailing slash stripped; root `/` falls back to prefix) |
| `ImplementationSpecific` | as-is |

Backends resolve to a Service `host:port`, then to pod IPs via Endpoints.
Endpoint selection is **round-robin**; an address that fails to dial is marked
**bad for 2s** and skipped (reactive health — no active probing). Host is
lowercased and port-stripped before matching.

**Retry is connection-only** (both implementations): a dial failure — or a
connection broken before any response — is retried up to 5× with backoff,
marking the pod bad and round-robining to another. An upstream that *responds* —
**including with 502/503** — is **never** retried; its response passes through to
the client unchanged. A responding upstream has already received and processed
the request, so retrying could duplicate side effects and amplify load on a
failing backend. Non-idempotent requests (body already read) are never retried.

## Annotations

All keys are prefixed `parapet.moonrhythm.io/`. Applied per-Ingress.

| Annotation | Values | Effect |
|---|---|---|
| `redirect-https` | `"true"` | 301 HTTP→HTTPS (skips `/.well-known/acme-challenge`) |
| `hsts` | `"preload"` / any | Strict-Transport-Security header |
| `redirect` | YAML map `host: url` (or `host: "code,url"`) | Host-level redirect rules |
| `ratelimit-s` / `-m` / `-h` | integer | Fixed-window requests per second / minute / hour |
| `body-limitrequest` | bytes (int64) | Max request body size (413 above) |
| `upstream-protocol` | `http` / `https` | Force upstream scheme |
| `upstream-host` | hostname | Override `Host` sent upstream |
| `upstream-path` | path prefix | Prepend path (+ optional query) upstream |
| `allow-remote` | comma-sep CIDRs | IP allowlist (403 otherwise; skips ACME) |
| `strip-prefix` | path prefix | Strip prefix from request path |
| `basic-auth` | `user:pass` | HTTP Basic Auth |
| `forward-auth` | YAML (`url`, `authRequestHeaders`, `authResponseHeaders`) | Delegate auth to an external service |
| `waf-zone` | zone id, or `ns/id` | Bind the Ingress to a WAF zone (see [WAF.md](WAF.md)) |
| `operations-trace` / `-project` / `-sampler` | `"true"` / project id / float ratio | **Go-only** Cloud Trace (no Rust SDK; see Profiler/Trace divergence) |

### Per-request order

1. host normalization → `/healthz` (IP-host only) → host/country concurrency limits
2. **global WAF** (before routing)
3. routing → per-route: `allow-remote` → **zone WAF** → `redirect-https` → rate limits → body limit → basic-auth → forward-auth
4. upstream proxy (with retry on connection failure + bad-addr skip)

### Request header normalization (both implementations)

Before the WAF reads the request and before forwarding upstream, an HTTP/2
request's **`Cookie` header must be reassembled into a single field**. Per RFC
7540 §8.1.2.5 an H2 client may split `Cookie` into multiple header fields for
HPACK compression; a proxy must rejoin the crumbs with `"; "` into one
`Cookie: a=1; b=2` so a backend (or the WAF) that reads only the first field
doesn't lose cookies — a dropped session cookie shows up as **random forced
logouts under HTTP/2**, browser-graded (Safari splits most aggressively).

- **Go** gets this for free: `net/http`'s HTTP/2 server reassembles `Cookie`
  before the request reaches proxy/middleware code.
- **Rust** must do it explicitly — **Pingora does not** reassemble; the controller
  and the edge proxy rejoin the crumbs in `request_filter` (`coalesce_cookies`).

## WAF

Full design in **[WAF.md](WAF.md)**. Summary: a global baseline ruleset
(ConfigMaps labeled `parapet.moonrhythm.io/waf: global`, honored only in
`POD_NAMESPACE`) plus tenant zones (labeled `…/waf: zone`, zone id = ConfigMap
name), bound per-Ingress by `waf-zone` (namespace-local or `ns/id`). CEL rules
with actions `log` / `allow` / `block`. Global runs first and is authoritative.
Rule **strings are portable** across both implementations; the
[`conformance/`](conformance/) CEL corpus guards that.

**GeoIP**: `WAF_GEOIP_DB` defaults to the IPLocate ip-to-country `.mmdb` baked into
the image (set `""` to disable), and rules can filter on `request.country`
(ISO 3166-1 alpha-2, from the client IP), e.g. `request.country == "TH"` or
`containsAny(request.country, ["CN", "RU"])`. The field is **always present**: `""`
when GeoIP is off, `"XX"` when the DB can't place the IP — so it never fails open on
a missing key. (Go exposes it via the `parapet/pkg/waf` `Country` resolver hook.)
When the DB is loaded, the resolved value is also sent **upstream** as the
`X-Forwarded-Country` header (overwriting any client-supplied value, so it can't be
spoofed); when GeoIP is off the header is left untouched.

**ASN**: `WAF_ASN_DB` defaults to the IPLocate ip-to-asn `.mmdb` baked into the
image (set `""` to disable), and rules can filter on `request.asn` (the autonomous
system number, an **int**, from the client IP), e.g. `request.asn == 13335`. Always
present: `0` when ASN lookup is off or the IP can't be placed (RFC 7607 reserved, so
`request.asn == 0` is a usable predicate and the field never fails open). Go exposes
it via the `parapet/pkg/waf` `ASN` resolver hook (parapet ≥ v0.15.2). When the DB is
loaded, the resolved value is also sent **upstream** as the `X-Forwarded-ASN` header
(overwriting any client-supplied value); when ASN lookup is off the header is left
untouched.

## Edge control plane (cert+key + WAF distribution)

Full design in **[EDGE.md](EDGE.md)**. An optional out-of-cluster **edge** proxy
(`rust/edge`, Pingora) terminates public TLS **locally** and runs the WAF. A
**Go** in-cluster **control plane** (`go/cmd/edge-controlplane`) distributes, per
edge, the cert+key and WAF rules for that edge's domains over an **HTTPS REST**
API (`GET /v1/certs?sni=…`, `GET /v1/waf`) authenticated by a **per-edge bearer
token** → allowed domains/zones. Contract-relevant invariants:

- **Cert+key distribution (not keyless)** — the edge holds the cert+key for its
  allowed domains and terminates TLS locally (no per-handshake round trip; certs
  refreshed on a timer, cached in memory only). The private key leaves the
  cluster; a compromised edge means **reissue/revoke those certs**. Bounded by
  domain sharding + short lifetimes + revocable per-edge token.
- **parapet stays authoritative** — the edge runs global + zone WAF as an
  early-drop layer, but parapet **re-runs the full WAF** inside and resolves
  zones from its own router. Edge-vs-parapet zone-resolution drift is non-fatal
  (parapet corrects it). Never disable parapet's WAF for edge traffic.
- **Same WAF contract** — the edge reuses the `rust/` CEL engine, so it's a third
  consumer of the [`conformance/`](conformance/) corpus; rule semantics are
  identical by construction. Rules ship as YAML over the wire.
- **Separate channel** — control plane on its own port/Service (`:8443`), HTTPS +
  bearer token, reachable only by edges over a private path, never on the public
  LoadBalancer.
- **Language split** — control plane is **Go** (reuses `go/cert`, `go/k8s`,
  `go/wafrule`); edge is **Rust** (Pingora). They share only the HTTP/JSON
  contract — no shared library.
- **Response cache (edge-only)** — the edge has an optional disk-backed HTTP
  response cache (`EDGE_CACHE_*`, off by default): **honor-origin** policy (caches
  only on explicit `Cache-Control`/`Expires` freshness; refuses
  `private`/`no-store`/`Set-Cookie`/`Vary: *`; ignores **client** request
  `Cache-Control`, CDN-style), `GET`/`HEAD`, LRU-bounded, restart-persistent,
  fail-static, `X-Cache: HIT|MISS`. **parapet does not cache**
  — there is no Go equivalent and no conformance obligation. A cache **hit** is
  served without contacting parapet, so parapet's authoritative WAF does not
  re-run on hits (only origin-opted-in public content is cached). See
  [EDGE.md](EDGE.md#response-cache-at-the-edge).
- **Cache purge (edge-only, design)** — invalidation is **pulled** from the
  control plane (`GET`/`POST /v1/purges`, a per-edge-scoped journal + cursor),
  mirroring cert/WAF distribution; no inbound port on the edge. Lazy **epoch**
  invalidation (global / host / url-keyed-on-`host⊕uri`) is checked at lookup —
  chosen because the on-disk hash mixes primary+`Vary` variance, so a URL's
  variants can't be enumerated for eager deletion. Epochs use the **edge's own
  clock** at apply time (no trusted CP timestamp; the cursor makes apply
  idempotent); a background reaper reclaims disk. Scopes: exact-URL (all
  variants), whole-host/zone, flush-all. Edge-only — no Go mirror, no conformance
  obligation. See [EDGE.md](EDGE.md#purge--invalidation).

## Configuration (environment variables)

| Variable | Default | Scope | Description |
|---|---|---|---|
| `HTTP_PORT` | `80` | both | HTTP (+ h2c) listener port |
| `HTTPS_PORT` | `443` | both | TLS port; **empty** = HTTP-only; unset = 443 |
| `INGRESS_CLASS` | `parapet` | both | IngressClassName to handle |
| `KUBERNETES_BACKEND` | cluster | both | Source of K8s objects: in-cluster watch (default) or `fs` (one-shot load of static manifests, no watch — local dev/smoke tests). **Go-only** also accepts `local` (kubectl proxy at `127.0.0.1:8001`) |
| `KUBERNETES_FS` | — | both | Directory of static manifests; **required** when `KUBERNETES_BACKEND=fs` |
| `WATCH_NAMESPACE` | `""` (all) | both | Restrict the watch to one namespace |
| `POD_NAMESPACE` | `""` | both | Controller's namespace (bounds global WAF rules) |
| `LOAD_ALL_CERTS` | `false` | both | Index every TLS secret, not just `spec.tls`-referenced |
| `TRUST_PROXY` | `""` | both | `true`/`false`/CIDRs (+ `cloudflare`/`google`/`bunny`) |
| `WAIT_BEFORE_SHUTDOWN` | `30s` | both | Drain delay on SIGTERM |
| `HOST_CONCURRENT_CAPACITY` / `_SIZE` | `0` | both | Per-host in-flight cap / queue size. Slot is released when upstream response headers arrive (or on a 101 upgrade), not at end-of-body — so SSE / WebSocket / long-poll streams don't pin a slot for the stream lifetime. The cap exists to shed load while upstreams are *unresponsive*. |
| `HOST_COUNTRY_CONCURRENT_CAPACITY` / `_SIZE` | `0` | both | Per-host+country cap / queue (same release semantics as `HOST_CONCURRENT_CAPACITY`) |
| `HOST_COUNTRY_HEADER` | `""` | both | Header(s) carrying the country code |
| `TR_MAX_IDLE_CONNS_PER_HOST` | stdlib / 128 | both | Upstream idle pool (Rust: process-global) |
| `DISABLE_LOG` | `false` | both | Suppress the access log |
| `WAF_ENABLED` | `false` | both | Master switch for the WAF |
| `WAF_FAIL_MODE` | `open` | both | `open` (skip on rule error) / `closed` (500) |
| `WAF_EVAL_TIMEOUT` | `5ms` | both | Per-request ruleset deadline |
| `WAF_GEOIP_DB` | `/geoip/ip-to-country.mmdb` | both | Path to an IPLocate ip-to-country `.mmdb` (flat `country_code` schema); sets `request.country`. Defaults to the baked-in DB; `""` disables. A missing file at the default path is a quiet no-op (`request.country` `""`); a missing explicit path is an error |
| `WAF_ASN_DB` | `/geoip/ip-to-asn.mmdb` | both | Path to an IPLocate ip-to-asn `.mmdb` (flat string `asn`); sets `request.asn`. Defaults to the baked-in DB; `""` disables. A missing file at the default path is a quiet no-op (`request.asn` `0`); a missing explicit path is an error |
| `HTTP_SERVER_MAX_HEADER_BYTES` | `16384` | **Go-only** | Max header size (no Pingora 0.8 equivalent) |
| `TR_MAX_CONNS_PER_HOST` | stdlib | **Go-only** | Max conns per host (no Pingora 0.8 equivalent) |
| `PROFILER` / `PROFILER_NAME` | `false` | **Go-only** | Cloud Profiler (no Rust SDK) |
| `WAF_COST_LIMIT` / `WAF_INSPECT_BODY` / `WAF_DISABLE_MACROS` | — | **Go-only** | cel-rust has no cost limit; body inspection is phase-2 |
| `UPSTREAM_CONNECT_TIMEOUT` | `2s` | **Rust-only** | TCP connect timeout to a pod (connect phase) |
| `UPSTREAM_TOTAL_CONNECT_TIMEOUT` | `3s` | **Rust-only** | Connect + TLS-handshake timeout |
| `DEBUG_ENDPOINTS` | `false` | **Rust-only** | Serve `GET /debug/routes` |

## Metrics

Prometheus, served on `:9187`. Names/labels match across implementations where
the metric exists in both.

| Metric | Scope |
|---|---|
| `parapet_requests{host,status,method,ingress_name,ingress_namespace,service_type,service_name}` | both |
| `parapet_service_duration_seconds{service_type,service_namespace,service_name}` | both |
| `parapet_reload{success}` | both |
| `parapet_host_active_requests{host,upgrade}` | both |
| `parapet_host_ratelimit_requests{host}` | both |
| `parapet_backend_connections{addr}` | both (Rust = in-flight-per-addr approximation) |
| `parapet_backend_network_read_bytes{addr}` / `_write_bytes{addr}` | both |
| `parapet_network_request_bytes` / `parapet_network_response_bytes` | both |
| `parapet_waf_matches{rule_id,action,scope}` | both (note: **no** `_total` suffix) |
| `parapet_connections{state}` | **Go-only** (no Pingora `ConnState` equivalent) |
| `go_*` runtime, Cloud Profiler/Trace | **Go-only** |
| `parapet_rejected_requests{reason}`, `parapet_tls_sni_no_cert_total{reason}`, `process_*` (custom `/proc`) | **Rust-only** (Go gets `process_*` from client_golang) |

Host and HTTP-method labels are collapsed to `other` for values the router
doesn't serve, to bound cardinality under a flood.

The byte counters (`parapet_backend_network_*_bytes`, `parapet_network_*_bytes`)
share names but **not magnitudes**: Go wraps the `net.Conn` so it counts wire
bytes (headers + TLS framing included); Rust counts only body bytes seen in the
filter phases (headers/framing excluded). Treat them as comparable in *shape*,
not absolute value.

## Intentional Go↔Rust divergences

- **WAF cost limit** — cel-rust has none; Rust checks `WAF_EVAL_TIMEOUT` between
  rules. **WAF body inspection** is phase-2 in Rust (`request.body` empty).
- **WAF CEL surface** — Go uses cel-go's full stdlib + macros; Rust uses
  cel-rust 0.13 (a subset). The portable surface (the contract) is documented in
  [`WAF.md`](WAF.md#cel-surface): `bool()`/`type()`/`dyn()` and the tz-arg time
  accessors are Go-only, `max()`/`min()`/`optional.*` are Rust-only,
  `WAF_DISABLE_MACROS` is Go-only, and no CEL extension libraries are enabled in
  either.
- **Cloud Profiler/Trace** are Go-only (no Rust SDK).
- See [`go/CLAUDE.md`-style notes in `CLAUDE.md`](CLAUDE.md) and
  [`rust/README.md`](rust/README.md) for the full per-impl detail.
