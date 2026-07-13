# Behavior contract

This is the **single source of truth** for what the controller does. When
behavior changes, change it here first, then in the code and the
[`conformance/`](conformance/) fixtures.

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

Backends resolve to a Service `host:port`, then to pod IPs via EndpointSlices
(`discovery.k8s.io/v1`; a Service's slices are unioned into one address set,
ready addresses only). EndpointSlices are authoritative; a Service with **no**
slice falls back to its legacy `Endpoints` object (the no-mirror / `skip-mirror`
case). Endpoint selection is **round-robin**; an address that
fails to dial is marked **bad for 2s** and skipped (reactive health — no active
probing). Host is lowercased and port-stripped before matching.

A Service of `type: ExternalName` is also supported: it has no EndpointSlices, so the
backend is dialed at its `spec.externalName` (an external DNS name, resolved at
connect time) on the **Service port the ingress references** (`targetPort` is a
pod concept and does not apply to a DNS CNAME — the port the ingress addresses is
used as-is). The referenced port must still be declared in the Service's
`spec.ports` (as for any backend). No round-robin/bad-address tracking applies
(a single target); `https`/`appProtocol` on the port work as usual, and the
`upstream-host` annotation overrides the forwarded `Host` (the client `Host` is
forwarded by default). A pod-backed route always wins over an ExternalName one
for the same Service host (only briefly possible across a type change).

**Retry is connection-only**: a dial failure — or a
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
| `redirect` | YAML map `host: url` (or `host: "code,url"`, `code` a 3xx) | Host-level redirect rules. The source host (the segment before the first `/`) must be a host the Ingress owns via `spec.rules[].host` or `spec.tls[].hosts` (exact, or an owned single-label `*.` wildcard); unowned sources are rejected so one tenant can't hijack another's host. A `code` outside 300–399 rejects the entry |
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
| `coraza-zone` | zone id, or `ns/id` | Bind the Ingress to a Coraza (OWASP CRS / SecLang) zone (see [CORAZA.md](CORAZA.md)); inert when `CORAZA_ENABLED` is off. Cross-namespace refs allowed (the WAF model — rulesets are stateless) |
| `ratelimit-zone` | zone id (same-namespace only) | Bind the Ingress to a rate-limit zone (see [RATELIMIT.md](RATELIMIT.md)); inert when `RATELIMIT_ENABLED` is off. Cross-namespace refs are NOT honored (zones carry shared counter state) |
| `operations-trace` / `-project` / `-sampler` | `"true"` / project id / float ratio | Cloud Trace |

### Per-request order

1. host normalization → `/healthz` (IP-host only) → host/country concurrency limits
2. **global WAF** → **global Coraza** (`CORAZA_ENABLED`) → **global rate limits** (`RATELIMIT_ENABLED`) (before routing)
3. routing → per-route: `allow-remote` → **zone WAF** → **zone Coraza** → `redirect-https` → **zone rate limits** → annotation rate limits → body limit → basic-auth → forward-auth
4. upstream proxy (with retry on connection failure + bad-addr skip)

The Coraza steps are an independent OWASP CRS / SecLang signature firewall layered after the CEL WAF and before rate limiting (so a Coraza block never burns rate budget). They have no validated-proxy skip — the core always re-runs them (see [CORAZA.md](CORAZA.md)).

When `WAF_VALIDATED_PROXY` matches the request's peer **and** the request
carries the edge's `X-Parapet-Waf` claim (stamped after the edge's WAF
evaluated it), the **global WAF** and **zone WAF** steps are skipped for that
request — counted as `parapet_waf_skips{scope}`; every other step is unchanged.

An HTTP/2 **extended-CONNECT WebSocket handshake** (RFC 8441, accepted only
when the process runs with `GODEBUG=http2xconnect=1`) is normalized **before
step 1** into the equivalent HTTP/1.1 upgrade shape — method `GET`,
`Connection: Upgrade` + `Upgrade: websocket`, the live tunnel stream detached
from `r.Body` (so WAF/Coraza body inspection sees the same empty body an h1
handshake has) — and then follows the same order; every step sees it exactly
as it sees an h1 WebSocket handshake. A `:protocol` other than `websocket` is
refused with 501. On acceptance the proxy performs the h1 upgrade toward the
pod itself (synthesizing `Sec-WebSocket-Key`, validating the pod's `Accept`)
and splices the pod connection to the h2 stream — unless the pod is
h2c-capable and advertises extended CONNECT itself, in which case the tunnel
is stream-to-stream over h2c (`UPSTREAM_WS_H2C`, default on; a pod that
doesn't advertise falls back to the h1 upgrade). See
[WEBSOCKET.md](WEBSOCKET.md).

### Request header normalization

Before the WAF reads the request and before forwarding upstream, an HTTP/2
request's **`Cookie` header must be reassembled into a single field**. Per RFC
7540 §8.1.2.5 an H2 client may split `Cookie` into multiple header fields for
HPACK compression; a proxy must rejoin the crumbs with `"; "` into one
`Cookie: a=1; b=2` so a backend (or the WAF) that reads only the first field
doesn't lose cookies — a dropped session cookie shows up as **random forced
logouts under HTTP/2**, browser-graded (Safari splits most aggressively).
`net/http`'s HTTP/2 server does this reassembly before the request reaches
proxy/middleware code, covering both the controller and the edge proxy — but it
is a load-bearing contract point: any future serving path that bypasses
`net/http` must reassemble explicitly.

## WAF

Full design in **[WAF.md](WAF.md)**. Summary: a global baseline ruleset
(ConfigMaps labeled `parapet.moonrhythm.io/waf: global`, honored only in
`POD_NAMESPACE`) plus tenant zones (labeled `…/waf: zone`, zone id = ConfigMap
name), bound per-Ingress by `waf-zone` (namespace-local or `ns/id`). CEL rules
with actions `log` / `allow` / `block`. Global runs first and is authoritative.
The supported rule-authoring surface is pinned by the
[`conformance/`](conformance/) CEL corpus, so engine upgrades can't silently
change what a rule matches.

**Skipping re-validation behind the edge** (`WAF_VALIDATED_PROXY`, default off):
a request skips the global and zone WAF at the core when **both** hold — its
peer matches the spec (`edge-mtls`: a TLS client cert chaining to the live edge
CA, requires edge auto-trust; and/or CIDRs/named groups: the immediate TCP
peer, for the plaintext edge→core hop) **and** it carries the `X-Parapet-Waf`
claim the edge stamps after its WAF evaluated the request. The claim is stamped
only once a CP rules snapshot has landed, so an edge on its empty boot ruleset
— or one with `EDGE_WAF_ENABLED=false` — forwards claimless requests that get
the full core WAF. The edge strips client-supplied claims unconditionally; the
core deletes the claim from any request it did not skip, so an unvalidated
claim never reaches CEL rules or the zone WAF, and the core's proxy deletes it
from **every** upstream request regardless of WAF config — the claim is a
core↔edge wire contract that backends never see. Everything else (rate limits,
auth, routing, geo headers) is unchanged, and non-matching traffic still gets
the full WAF. `true` is refused, and a bad spec (malformed CIDR, `edge-mtls`
without `EDGE_TRUST_CP_ENDPOINT`) is fatal at startup. Edge images that predate
the claim never stamp it — but they don't strip client-supplied claims either,
so with a mixed fleet a client could smuggle a claim through an old edge;
upgrade every edge before opting in (see the trade-offs in EDGE.md). See
[EDGE.md](EDGE.md#skipping-the-core-re-run-waf_validated_proxy-opt-in) for the
trade-offs this opt-in accepts.

**GeoIP**: `WAF_GEOIP_DB` defaults to the IPLocate ip-to-country `.mmdb` baked into
the image (set `""` to disable), and rules can filter on `request.country`
(ISO 3166-1 alpha-2, from the client IP), e.g. `request.country == "TH"` or
`containsAny(request.country, ["CN", "RU"])`. The field is **always present**: `""`
when GeoIP is off, `"XX"` when the DB can't place the IP — so it never fails open on
a missing key. (Exposed via the `parapet/pkg/waf` `Country` resolver hook.)
When the DB is loaded, the resolved value is also sent **upstream** as the
`X-Forwarded-Country` header (overwriting any client-supplied value, so it can't be
spoofed); when GeoIP is off the header is left untouched.

**ASN**: `WAF_ASN_DB` defaults to the IPLocate ip-to-asn `.mmdb` baked into the
image (set `""` to disable), and rules can filter on `request.asn` (the autonomous
system number, an **int**, from the client IP), e.g. `request.asn == 13335`. Always
present: `0` when ASN lookup is off or the IP can't be placed (RFC 7607 reserved, so
`request.asn == 0` is a usable predicate and the field never fails open). Exposed
via the `parapet/pkg/waf` `ASN` resolver hook (parapet ≥ v0.15.2). When the DB is
loaded, the resolved value is also sent **upstream** as the `X-Forwarded-ASN` header
(overwriting any client-supplied value); when ASN lookup is off the header is left
untouched.

## Rate limiting (ConfigMap-driven)

Full design in **[RATELIMIT.md](RATELIMIT.md)**. Summary: gated by
`RATELIMIT_ENABLED`, a global baseline limit set (ConfigMaps labeled
`parapet.moonrhythm.io/ratelimit: global`, honored only in `POD_NAMESPACE`)
plus tenant zones (labeled `…/ratelimit: zone`, zone id = ConfigMap name),
bound per-Ingress by `ratelimit-zone` — **same-namespace only**, a deliberate
divergence from `waf-zone` because zones carry shared counter state. Limits
are `id`/`key` (a characteristic or a composite list: `ip`, `host`, `asn`,
`country`, `header:<name>`, `cookie:<name>`; the GeoIP-backed keys require the
`WAF_GEOIP_DB`/`WAF_ASN_DB` databases, which load when either the WAF or rate
limiting is enabled) / `rate`+`window` (1s..1h) / `algorithm` (fixed, sliding)
/ `mode` (enforce, shadow) / `status` (429, 503) / `exclude` CIDRs / `filter`
(an optional CEL expression that **scopes** the limit to matching requests,
reusing the WAF's exact expression surface via one shared `waf.Predicate` —
`request.method`/`path`/`headers`/`country`/`asn`, the same helpers; `key` still
chooses the bucket. `request.body` is always `""` here; a geo reference without
the database never matches rather than erroring; a runtime eval error **fails
open** — the limit is skipped, never a rejection; a bad expression is rejected
at load). Reloads are debounced, mux-decoupled, all-or-nothing
(last-good kept), and preserve live counters for limits whose shaping config
(or only the `filter`) didn't change. `/.well-known/acme-challenge` is never limited. Counters are
per-pod. The edge proxy can opt in to enforcing the same global+zone sets
(`EDGE_RATELIMIT_ENABLED` + `CP_RATELIMIT_ENABLED`, distributed via
`GET /v1/ratelimit` like the WAF — see
[EDGE.md](EDGE.md#rate-limiting-at-the-edge)): counters there are per edge
(each layer counts what it sees; edge enforcement does not relieve the
core's), zone binding is host-level and same-namespace only, and edge limits
run after the edge WAF and **before** the edge cache — so cache hits are
limited at the edge, while the core's own counters still never see them.

## Edge control plane (cert+key + WAF distribution)

Full design in **[EDGE.md](EDGE.md)**. An optional out-of-cluster **edge** proxy
(`cmd/edge-proxy`, on the parapet framework) terminates public TLS **locally**
and runs the WAF. A **Go** in-cluster **control plane** (`cmd/edge-controlplane`)
distributes, per edge, the cert+key and WAF rules for that edge's domains over an
**HTTPS REST** API (`GET /v1/certs?sni=…`, `GET /v1/waf`) authenticated by a
**per-edge bearer token** → allowed domains/zones. Contract-relevant
invariants:

- **Cert+key distribution (not keyless)** — the edge holds the cert+key for its
  allowed domains and terminates TLS locally (no per-handshake round trip; certs
  refreshed on a timer, cached in memory only). The private key leaves the
  cluster; a compromised edge means **reissue/revoke those certs**. Bounded by
  domain sharding + short lifetimes + revocable per-edge token.
- **parapet stays authoritative** — the edge runs global + zone WAF as an
  early-drop layer, but parapet **re-runs the full WAF** inside and resolves
  zones from its own router. Edge-vs-parapet zone-resolution drift is non-fatal
  (parapet corrects it). That is the default; the opt-in `WAF_VALIDATED_PROXY`
  (see the WAF section above) skips the core re-run for strongly-identified
  edge hops, making the edge's WAF and zone resolution authoritative for that
  traffic.
- **Same WAF contract** — the edge reuses **`parapet/pkg/waf`** (the same Go CEL
  engine the controller uses) and `wafrule`, so rule semantics are identical by
  construction and it shares the [`conformance/`](conformance/) corpus via the Go
  surface. Rules ship as YAML over the wire.
- **Separate channel** — control plane on its own port/Service (`:8443`), HTTPS +
  bearer token, reachable only by edges over a private path, never on the public
  LoadBalancer.
- **Separate processes, shared libraries** — the control plane reuses `cert`,
  `k8s`, `wafrule`; the edge reuses `cert`, `wafrule`, `geoip`, and
  `parapet/pkg/waf`. They share only the HTTP/JSON contract on the wire (no
  shared in-process state).
- **Response cache (edge-only)** — the edge has an optional disk-backed HTTP
  response cache (`EDGE_CACHE_*`, off by default): **honor-origin** policy (caches
  only on explicit `Cache-Control`/`Expires` freshness; refuses
  `private`/`no-store`/`no-cache`/`Set-Cookie`/`Vary: *`; ignores **client**
  request `Cache-Control`, CDN-style), `GET`/`HEAD`, LRU-bounded, restart-
  persistent, fail-static, `X-Cache: HIT|MISS|STALE|BYPASS` (BYPASS = stamped on
  responses ineligible for caching — non-cacheable method, upgrade, Range, or
  override bypass — that the cache proxies straight to the origin). This is an **edge-only** feature:
  the parapet controller does not cache, so there is no controller equivalent and
  no conformance obligation. A cache **hit** is served without contacting parapet,
  so parapet's authoritative WAF does not re-run on hits (only origin-opted-in
  public content is cached). A GET is cached only with a `Content-Length` within
  the per-object cap (chunked GETs pass through uncached, to never store a
  truncated body). See
  [EDGE.md](EDGE.md#response-cache-at-the-edge).
- **Cache purge (edge-only)** — invalidation is **pulled** from the control plane
  (`GET`/`POST /v1/purges`, a per-edge-scoped journal + cursor), mirroring
  cert/WAF distribution; no inbound port on the edge. Lazy **epoch** invalidation
  (global / host / url-keyed-on-`host⊕uri` / path-prefix / tag) is checked at
  lookup via the `parapet/pkg/cache` `InvalidatedAfter` hook (parapet ≥ v0.17.0).
  Epochs use the **edge's own clock** at apply time (no trusted CP timestamp; the
  cursor makes apply idempotent, monotonic-clamped against an NTP step-back).
  Scopes: exact-URL (all variants), path-prefix (boundary-aware, path-only),
  whole-host, tag (surrogate keys from the origin's `Cache-Tag` header via parapet
  `Meta.Tags`, host-independent — distributed to every edge), flush-all. A
  background reaper
  (`EDGE_CACHE_PURGE_SWEEP_INTERVAL`) physically reclaims invalidated entries off
  the serving path, using `Storage.Range` + the host/uri/tags in `Meta` (parapet ≥
  v0.17.2); the in-memory record table is bounded by a count-cap fold into the
  global epoch (over-invalidates, never under-), and disk by the cache's LRU byte
  cap. Issuing a purge needs `CP_PURGE_ADMIN_TOKEN` (a stronger
  credential than the per-edge read tokens). Edge-only — no controller mirror, no
  conformance obligation. See
  [EDGE.md](EDGE.md#purge--invalidation).

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `80` | HTTP (+ h2c) listener port |
| `HTTPS_PORT` | `443` | TLS port; **empty** = HTTP-only; unset = 443 |
| `INGRESS_CLASS` | `parapet` | IngressClassName to handle |
| `KUBERNETES_BACKEND` | cluster | Source of K8s objects: in-cluster watch (default), `fs` (one-shot load of static manifests, no watch — local dev/smoke tests), or `local` (kubectl proxy at `127.0.0.1:8001`) |
| `KUBERNETES_FS` | — | Directory of static manifests; **required** when `KUBERNETES_BACKEND=fs` |
| `WATCH_NAMESPACE` | `""` (all) | Restrict the watch to one namespace |
| `POD_NAMESPACE` | `""` | Controller's namespace (bounds global WAF rules) |
| `LOAD_ALL_CERTS` | `false` | Index every TLS secret, not just `spec.tls`-referenced |
| `TRUST_PROXY` | `""` | `true`/`false`/CIDRs (+ `cloudflare`/`google`/`bunny`). Whether to honor inbound `X-Forwarded-*` (real client IP) from a trusted front proxy vs. overwrite with the peer. The edge proxy honors the same knob to sit behind an L7 proxy (e.g. Cloudflare) — see EDGE.md |
| `WAIT_BEFORE_SHUTDOWN` | `30s` | Drain delay on SIGTERM |
| `HOST_CONCURRENT_CAPACITY` / `_SIZE` | `0` | Per-host in-flight cap / queue size. Slot is released when upstream response headers arrive (or on a 101 upgrade), not at end-of-body — so SSE / WebSocket / long-poll streams don't pin a slot for the stream lifetime. The cap exists to shed load while upstreams are *unresponsive*. |
| `HOST_COUNTRY_CONCURRENT_CAPACITY` / `_SIZE` | `0` | Per-host+country cap / queue (same release semantics as `HOST_CONCURRENT_CAPACITY`) |
| `HOST_COUNTRY_HEADER` | `""` | Header(s) carrying the country code |
| `TR_MAX_IDLE_CONNS_PER_HOST` | stdlib / 128 | Upstream idle pool |
| `DISABLE_LOG` | `false` | Suppress the access log |
| `WAF_ENABLED` | `false` | Master switch for the WAF |
| `RATELIMIT_ENABLED` | `false` | Master switch for ConfigMap-driven rate limiting (global + zone sets; see [RATELIMIT.md](RATELIMIT.md)) |
| `CORAZA_ENABLED` | `false` | Master switch for the Coraza (OWASP CRS / SecLang) firewall (global + zone rulesets; see [CORAZA.md](CORAZA.md)). Global is active iff a global ConfigMap exists; each zone iff its ConfigMap exists |
| `CORAZA_REQUEST_BODY_LIMIT` | `0` | Bytes of request body Coraza inspects (`0` = URI + headers only; no body buffered). When set, up to this many bytes feed Coraza and the body is rebuilt so the upstream still receives it in full. Response-body inspection is never enabled |
| `WAF_FAIL_MODE` | `open` | `open` (skip on rule error) / `closed` (500) |
| `WAF_EVAL_TIMEOUT` | `5ms` | Per-request ruleset deadline |
| `WAF_GEOIP_DB` | `/geoip/ip-to-country.mmdb` | Path to an IPLocate ip-to-country `.mmdb` (flat `country_code` schema); sets `request.country` and serves rate-limit `country` keys (Go: loaded when `WAF_ENABLED` **or** `RATELIMIT_ENABLED`). Defaults to the baked-in DB; `""` disables. A missing file at the default path is a quiet no-op (`request.country` `""`); a missing explicit path is an error |
| `WAF_ASN_DB` | `/geoip/ip-to-asn.mmdb` | Path to an IPLocate ip-to-asn `.mmdb` (flat string `asn`); sets `request.asn` and serves rate-limit `asn` keys (Go: loaded when `WAF_ENABLED` **or** `RATELIMIT_ENABLED`). Defaults to the baked-in DB; `""` disables. A missing file at the default path is a quiet no-op (`request.asn` `0`); a missing explicit path is an error |
| `HTTP_SERVER_MAX_HEADER_BYTES` | `16384` | Max header size |
| `TR_MAX_CONNS_PER_HOST` | stdlib | Max conns per host |
| `PROFILER` / `PROFILER_NAME` | `false` | Cloud Profiler |
| `WAF_COST_LIMIT` / `WAF_INSPECT_BODY` / `WAF_DISABLE_MACROS` | — | CEL cost cap / body-bytes inspection / macro kill-switch (see WAF.md) |
| `WAF_VALIDATED_PROXY` | `""` | Skip the core's global+zone WAF for requests whose peer already ran the same rules (the edge proxy). Comma list of `edge-mtls` (peer client cert chains to the live edge CA; requires `EDGE_TRUST_CP_ENDPOINT`) and/or CIDRs/named groups (immediate TCP peer). Also requires the per-request `X-Parapet-Waf` claim the edge stamps after evaluating. `true` is refused; a bad spec is fatal at startup. Skips counted in `parapet_waf_skips{scope}`. See [EDGE.md](EDGE.md#skipping-the-core-re-run-waf_validated_proxy-opt-in) |
| `UPSTREAM_AUTO_H2C` | `false` | Speculatively try h2c on plain-`http` upstreams, fall back to HTTP/1.1 when unsupported. The verdict (h2c or HTTP/1.1-only) is cached per-Service with a TTL and re-probed on expiry; concurrent probes for a cold/expired upstream are single-flighted so they can't stampede failed connections. WebSocket/Upgrade always uses HTTP/1.1; `https` and explicit `appProtocol: h2c` upstreams are unaffected |
| `UPSTREAM_AUTO_H2C_TTL` | `10m` | How long a cached auto-h2c verdict is trusted before the upstream is re-probed (only when `UPSTREAM_AUTO_H2C` is on) |
| `UPSTREAM_WS_H2C` | `true` | Kill switch for core→pod WebSocket-over-h2c: a tunneled WebSocket to an h2c-capable pod (explicit `appProtocol: h2c`, or a fresh auto-h2c positive verdict) is attempted as an RFC 8441 extended CONNECT stream instead of an h1 upgrade dial; a pod that doesn't advertise the capability falls back to h1 (negative verdict cached 10m per Service). See [WEBSOCKET.md](WEBSOCKET.md) |
| `GODEBUG` | Dockerfile sets `http2xconnect=1` | Must contain `http2xconnect=1` for the core to **accept WebSocket-over-HTTP/2** (RFC 8441 extended CONNECT; see [WEBSOCKET.md](WEBSOCKET.md)). Read by `net/http` at process init — a `GODEBUG` set in a pod spec **replaces** the Dockerfile value, silently disabling acceptance (edges fall back to HTTP/1.1 per request); a startup warning is logged when the token is absent |

## Metrics

Prometheus, served on `:9187`.

| Metric | Notes |
|---|---|
| `parapet_requests{host,status,method,ingress_name,ingress_namespace,service_type,service_name}` | |
| `parapet_service_duration_seconds{service_type,service_namespace,service_name}` | |
| `parapet_reload{success}` | |
| `parapet_host_active_requests{host,kind}` | |
| `parapet_host_ratelimit_requests{host}` | |
| `parapet_backend_connections{addr}` | |
| `parapet_backend_network_read_bytes{addr}` / `_write_bytes{addr}` | |
| `parapet_network_request_bytes` / `parapet_network_response_bytes` | |
| `parapet_waf_matches{rule_id,action,scope}` | note: **no** `_total` suffix |
| `parapet_waf_skips{scope}` | requests that bypassed WAF evaluation via `WAF_VALIDATED_PROXY` (already validated at the edge); `scope` = `global\|zone`, no `_total` suffix |
| `parapet_waf_eval_duration_seconds{outcome,scope}` | histogram of per-request rule-eval latency; `outcome` = `pass\|allow\|block\|error`, fired once per evaluated request — the pass path `parapet_waf_matches` can't see |
| `parapet_coraza_matches{rule_id,severity,scope}` | Coraza (OWASP CRS / SecLang) rule matches; `scope` = `global\|zone`, no `_total` suffix |
| `parapet_coraza_eval_duration_seconds{outcome,scope}` | histogram of per-request Coraza request-phase eval latency; `outcome` = `pass\|block` |
| `parapet_ratelimit_total{name,result}` | `result` = `allowed\|limited`; `name` = `host` / `host-country` for the env-configured limiters, `<ns>/<name>:<s\|m\|h>` for annotation limiters, `global:<id>` / `zone:<ns>/<name>:<id>` for ConfigMap-driven limits — the `zone:` prefix keeps zone names disjoint from annotation names |
| `parapet_ws_tunnels{result}` | WebSocket-over-h2 extended-CONNECT handshakes at the core; `result` = `tunneled\|refused\|upstream_error\|bad_protocol`, no `_total` suffix (see [WEBSOCKET.md](WEBSOCKET.md)) |
| `parapet_ws_tunnel_active` | live spliced WebSocket-over-h2 sessions at the core |
| `parapet_ws_upstream_h2c{result}` | core→pod extended-CONNECT attempt outcomes; `result` = `ok\|not_supported\|error` — `not_supported` = the pod doesn't advertise the capability (fell back to h1), no `_total` suffix |
| `parapet_edge_ws_upstream{protocol,result}` | edge-side WebSocket upstream outcomes; `protocol` = `h2\|http1`, `result` = `ok\|fallback\|error` — `fallback` = the core didn't accept extended CONNECT (edge-only metric, reaches Prometheus via the CP's merged registry) |
| `parapet_connections{state}` | per-state connection gauge |
| `go_*` runtime, `process_*` (client_golang), Cloud Profiler/Trace | |

Host and HTTP-method labels are collapsed to `other` for values the router
doesn't serve, to bound cardinality under a flood.

On `parapet_host_active_requests`, the `kind` label classifies each in-flight
request into one mutually-exclusive connection bucket: `websocket` / `h2c` from
the `Upgrade` header (checked first, takes precedence), `other` for any other
`Upgrade` token, `sse` when there's no upgrade and the `Accept` header contains
`text/event-stream` (what the browser EventSource API sends), else `http` for
plain HTTP. The set is bounded to `{http, websocket, h2c, sse, other}` so a
client can't mint unbounded series with arbitrary `Upgrade` values.

The byte counters (`parapet_backend_network_*_bytes`, `parapet_network_*_bytes`)
count **wire bytes** (headers + TLS framing included) — the `net.Conn` is
wrapped, so they are not body-byte counts.
