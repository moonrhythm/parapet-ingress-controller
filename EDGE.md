# Edge control plane (cert+key distribution + WAF distribution)

An **out-of-cluster edge reverse proxy** that terminates public TLS locally and
runs the WAF, fronting the in-cluster parapet ingress controller. A small
in-cluster **control plane** distributes, per edge, only the certificates (and
private keys) and WAF rules for the domains that edge serves.

> Status: **Phases 1–4 implemented** (cert distribution, WAF distribution + edge
> global eval, zones at edge, disk response cache); Phase 5 (purge) is design only.
> Both the control plane (`cmd/edge-controlplane`, reusing `cert`, `k8s`,
> `wafrule`) and the **edge** (`cmd/edge-proxy` + `edge`, on the parapet
> framework) are **Go**. They share **only a language-neutral HTTP/JSON contract**
> (below) on the wire. Per [`CLAUDE.md`](CLAUDE.md) the contract changes here first.

> **Both Go (was: Go control plane + Rust edge).** The edge was originally
> Rust/Pingora (`rust/edge`) so the control plane and edge shared *nothing* in code
> — only the HTTP/JSON API. After recurring bugs in pingora 0.8 (the
> patched-vendored connection-pool / H2-idle leaks; see `rust/Cargo.toml`
> `[patch.crates-io]`), the edge was **migrated to Go** on the parapet framework,
> reusing the controller's `cert`/`wafrule`/`geoip` packages and `parapet/pkg/waf`.
> `rust/edge` has since been **removed** (it soaked in production; recoverable from
> git history). The control plane and edge still share only the wire contract — no shared
> in-process state — but, both being Go, they now draw on the same libraries. See
> [Implementation history](#implementation-history). (An even earlier iteration put
> a gRPC control plane in `rust/controlplane`; that was superseded when the design
> moved off keyless to a Go REST service.)

> **Design note — this replaced an earlier *keyless* design.** Keyless TLS (the
> private key stays in-cluster; the edge calls back to sign each handshake) puts
> one control-plane round trip on the critical path of every non-resumed
> handshake. That is fine when the control plane is co-located with the edge
> (sub-ms), but unacceptable at 200–300 ms RTT (≈ +1 RTT per cold handshake,
> tripling handshake latency, and a hard dependency: no control plane → no new
> handshakes). With edges far from the cluster we instead **ship the cert+key to
> the (domain-sharded) edge**, trading key-secrecy for latency and availability.
> See [The tradeoff](#the-tradeoff).

## Why this shape

The edge tier lives outside Kubernetes (closer to clients, absorbing volumetric
traffic); the cluster stays the source of truth:

1. **The edge holds only its domains' material.** An edge serving `acme.com`
   gets the cert+key and zone rules for `acme.com`, not the whole inventory.
   Authorization is tied to the edge's identity (a per-edge bearer token).
2. **TLS terminates locally on the edge.** No per-handshake round trip; certs are
   fetched *once* and refreshed on a timer. Latency is unaffected by edge↔cluster
   distance, and a brief control-plane outage doesn't stop the edge serving.
3. **The cluster stays authoritative for WAF.** The edge is a *lower* trust tier,
   so its WAF is an early-drop optimization; parapet re-runs the full WAF inside.
   A buggy, stale, or compromised edge can never mean an *unprotected* origin.
4. **One WAF engine everywhere.** The edge reuses `parapet/pkg/waf` (the same Go
   CEL engine the controller uses) + `wafrule`, so rule semantics are identical
   by construction and it shares the [`conformance/`](conformance/) corpus via the
   Go surface — no reimplementation.

## Topology

```
                              ┌─ in cluster ──────────────────────────────┐
client ──TLS──► edge (Go/parapet, outside k8s)                            │
                  │ terminates public TLS *locally* (holds cert+key)      │
                  │ runs global + zone WAF (early drop)                   │
                  │ optional disk response cache                          │
                  │                                                       │
                  ├── HTTPS GET (bearer token) ─► controlplane :8443      │
                  │     GET /v1/certs?sni=… → cert+key+ETag (allowed SNI) │
                  │     GET /v1/waf         → rules for edge domains      │
                  │   authz: bearer token → allowed domains/zones         │
                  │   reads: TLS Secrets, WAF ConfigMaps, Ingresses       │
                  │   refreshed on a timer; cached in memory only         │
                  │                                                       │
                  └── data: HTTP/1.1 :80 / re-encrypt :443 ─► parapet ─► svc│
                        (sets X-Forwarded-For/-Proto/-Country/-ASN)        │
                        parapet re-runs WAF authoritatively + routes       │
                              └──────────────────────────────────────────┘
```

### Two channels, kept apart

| Channel | From → to | Protocol | Exposure |
|---|---|---|---|
| **Data plane** | edge → parapet `:80`/`:443` | HTTP/1.1 or re-encrypted TLS | private path |
| **Control plane** | edge → controlplane `:8443` | HTTPS GET (server-TLS + bearer token) | private path, edge sources only |

Separate ports on separate Services. The control plane distributes **private
keys**, so it must never be on the public LoadBalancer. See
[Ports & exposure](#ports--exposure).

## Components

- **`cmd/edge-controlplane/`** (Go) — in-cluster HTTPS REST server. Reuses the
  Go controller's k8s client (`k8s`), cert table (`cert`), WAF rule parser
  (`wafrule`), and route/zone logic. Serves `GET /v1/certs?sni=…` (cert+key)
  and `GET /v1/waf` (rules). Not on the request path.
- **`cmd/edge-proxy/` + `edge/`** (Go) — a parapet-framework proxy. Reuses
  `cert.Table` for SNI resolution (plugged into `tls.Config.GetCertificate`,
  self-signed fallback on a miss), `wafrule` + `parapet/pkg/waf` for CEL
  evaluation, and `geoip` for `request.country`/`request.asn`. Maintains an
  in-memory cert store refreshed from `GET /v1/certs?sni=…` (`edge/certstore.go`,
  `edge/cp.go`), runs global + zone WAF (`edge/waf.go`), optionally caches
  responses via `parapet/pkg/cache` (memory or disk, selected by
  `EDGE_CACHE_BACKEND`), and forwards to parapet with `X-Forwarded-*`
  (`edge/forward.go`). Keys live in memory only, never on disk.

## Authorization (bearer token, two endpoints)

Each edge holds a **per-edge bearer token** presented as `Authorization: Bearer
<token>` on every control-plane request, over server-side HTTPS. The token maps
(control-plane side) to an **allowed set of domains/zones** — Phase 1 from a
static config (token → domains), later from a k8s Secret/ConfigMap. Allowed
hosts match exact + single-label-wildcard like `cert.Table`, plus a bare `"*"`
catch-all entry in the domain list that authorizes the token for **every** host
(the serve-all case below). Deny by default. One `authorize(token, host|zone)`
check gates both endpoints:

- `GET /v1/certs/{sni}` → require `sni ∈ allowed(token)`.
- `GET /v1/waf` → return only the zones / host-map entries for the token's domains.

Server-side TLS is mandatory here: it encrypts the token **and the returned
private key** in flight and lets the edge authenticate the control plane. The
edge **enforces this**: it refuses to start if `EDGE_CP_ENDPOINT` is not
`https://`, unless `EDGE_CP_ALLOW_PLAINTEXT=true` explicitly opts into a plaintext
control plane on a trusted private network (matching the control plane's own
optional plaintext mode). Tokens are revocable (drop from the table) and
rotatable, and requests are rate-limited to blunt enumeration.

> **Token risk (because this endpoint hands out private keys).** A leaked bearer
> token exposes every key in that token's allowed set until it's revoked — the
> token is a bearer credential, so anyone who captures it can replay it. Mitigate
> with **short-lived, rotated tokens**, a revocation list, per-edge scoping (the
> allow-set bounds the blast radius), and strict transport security (never log
> the token; HTTPS only; private network path). mTLS is the strictly stronger
> alternative for this surface and is a drop-in swap (replace the bearer check
> with client-cert SAN identity) if the token-handling burden ever outweighs the
> client-cert plumbing.

> This isolation only buys anything if **edges are sharded by domain**. If every
> edge may serve every domain (pure anycast/failover), every allowlist is "all"
> and the per-edge scoping is moot. Decide sharding first. For that case give the
> token a single `"*"` entry — an explicit all-domains grant — instead of trying
> to enumerate every domain; the token then carries the full blast radius, so
> rotate it aggressively.

## The HTTPS API (REST)

All requests carry `Authorization: Bearer <token>` over HTTPS. Reads, so `GET`
with ETag-based caching (`304` on a match):

```
GET /v1/certs?sni=<host>   Authorization: Bearer <token>   [If-None-Match: "<etag>"]
  200 {"chain_pem": "<leaf+intermediates PEM>", "key_pem": "<PEM>"}   ETag: "<etag>"
  304 (If-None-Match matched the current etag — edge keeps its cached copy)
  400 (missing sni)  401 (no/invalid token)  403 (sni ∉ allowed(token))  404 (no cert for sni)

GET /v1/waf           Authorization: Bearer <token>   [If-None-Match: "<etag>"]
  200 {"generation": N, "global_rules":"…", "zones":{…}, "host_zone_map":{…}}
       global_rules  : the platform baseline YAML (identical for every edge)
       zones         : zoneKey ("<ns>/<name>") → rules YAML, scoped to the edge's hosts
       host_zone_map : host → zoneKey, scoped to the edge's hosts
       (ETag is over the *scoped* payload, so 304 revalidation is per-edge-correct)

GET /v1/purges?since=<seq>   Authorization: Bearer <token>
  200 {"entries":[{"seq":N,"scope":"url|host|all","host":"…","uri":"…"}],
       "max_seq": N, "min_seq": M, "flush_required": false}
       entries        : journal entries with seq > since, SCOPED to the token's hosts
       flush_required : true when since < min_seq (the edge fell behind / the journal
                        was trimmed) → the edge does a lazy flush-all and jumps its
                        cursor to max_seq. Conservative: never under-invalidates.
  401 (no/invalid token)

POST /v1/purges       Authorization: Bearer <ADMIN token>   ← stronger cred than the read token
  {"scope":"url|host|all", "host":"…", "uri":"…"}  → appends to the journal, returns {"seq":N}
  401 (no/invalid admin token)  403 (host ∉ allowed(token))

GET /healthz          (no auth)
  200 always (liveness)
GET /healthz?ready=1  (no auth)
  200 once the cert store has loaded at least once; 503 until then (readiness)
```

`chain_pem` is leaf-first (leaf + intermediates). `key_pem` is the private key —
this is the material that now leaves the cluster; see [The tradeoff](#the-tradeoff).
The ETag is the strong validator for cache revalidation; the WAF `generation` is
the monotonic rollout counter surfaced for observability.

## Cert distribution flow

1. On startup and then every `refresh_interval`, the edge issues `GET
   /v1/certs/{sni}` for each SNI it serves (or refreshes the set it has), sending
   `If-None-Match` with its cached ETag.
2. The control plane authorizes the edge's token against the SNI, reads the
   cert+key from the k8s Secret, and returns it (or `304`).
3. The edge parses the PEM into a `tls.Certificate` (`tls.X509KeyPair`) and
   **atomically swaps** the rebuilt SNI index into its in-memory `cert.Table`
   (`edge/certstore.go`). Keys are **never written to disk**.
4. A handshake reads the live table via `tls.Config.GetCertificate` and serves the
   matched cert+key locally — no control-plane interaction on the handshake path
   (except the first handshake per new SNI in serve-all mode).

**Pinned vs serve-all.** `EDGE_DOMAINS` lists the SNIs to pre-fetch (the edge's
shard); a handshake for anything else gets the self-signed fallback. Leaving
`EDGE_DOMAINS` **empty** switches the edge to **serve-all**: on a handshake for
an SNI it doesn't have, it fetches that cert from the control plane on demand
(driven on the CP runtime; the handshake awaits it), caches it, and the periodic
refresh keeps it rotated. This adds one control-plane round trip to the *first*
handshake per new SNI. The CP's per-token authz is still the boundary — an SNI
the token isn't allowed for `403`s and falls back to self-signed — so serve-all
only truly serves "all" when the edge's token is authorized for all domains.

### Rotation ordering (the gotcha)

The edge serves a cached cert. On rotation the new cert must reach the edge
**before** the old one is distrusted, or handshakes fail in the gap. So: refresh
on a timer with overlap, honor the ETag/version, and on a fetch failure
**keep serving the cached cert** (fail-static) — never drop it.

## WAF at the edge

Unchanged from the keyless design — the WAF half never depended on how TLS keys
are handled. The edge runs **global + zone** WAF as a first layer:

1. Terminate TLS locally → build the `request` map. By default the edge is the
   first hop, so `request.remote_ip` is the **true peer**, and GeoIP/ASN are
   resolved from it at the edge — *more* accurate than parapet behind it. If the
   edge instead sits behind another L7 proxy (e.g. Cloudflare), set `TRUST_PROXY`
   so it honors the inbound `X-Forwarded-For` and `request.remote_ip` becomes the
   real client (see [Edge behind another proxy](#edge-behind-another-proxy-trust_proxy)).
   The edge loads the IPLocate
   `.mmdb`s via the same env contract as the controller (`WAF_GEOIP_DB` /
   `WAF_ASN_DB`; `""` disables; baked default path; ASN DB ~74 MB), so
   `request.country` / `request.asn` work for edge-evaluated rules. When a DB is
   loaded the edge also forwards `X-Forwarded-Country` / `X-Forwarded-ASN` to
   parapet (overwriting any client value), matching the controller's upstream
   behavior — including forwarding `X-Forwarded-ASN: 0` and `X-Forwarded-Country:
   XX` for an unplaceable IP when the DB is loaded (the Go edge follows the Go
   controller here; the former Rust edge omitted the ASN header when `asn==0`).
   With no DB loaded, `country` is `""` and `asn` is `0` and neither header is
   forwarded (the field is always present in the rule map, so a rule never errors)
   — such a rule simply won't early-drop at the edge, but parapet still re-runs it
   authoritatively.
2. **Global WAF** (always) → block early on match.
3. Resolve the zone from the `host_zone_map` → **zone WAF** → block on match.
4. If not blocked, forward to parapet with `X-Forwarded-For/-Proto/-Country/-ASN`.

Rule snapshots apply with the same **all-or-nothing compile + atomic swap +
keep-last-good** semantics as parapet's `SetRules`; on a fetch failure the edge
**fails static** (keeps last-good) — never fail-open to "no WAF".

### parapet stays authoritative (the backstop)

The control plane derives `host[/path] → zoneKey` from the Ingress objects
(reusing `controller`'s normalization + path matching) and ships it scoped to the
edge's domains. If the edge's resolution ever disagrees with parapet's router, it
is **non-fatal**: parapet re-runs global + zone WAF authoritatively and resolves
the zone from its own router. So:

- Edge WAF = early-drop optimization + DDoS shield (lower trust tier).
- parapet WAF = authority. **Do not disable parapet's WAF for edge traffic.**

Because the edge sets `X-Forwarded-For` and parapet trusts it
(`TRUST_PROXY=<edge CIDR>`), both evaluate against the same client IP.

### Edge behind another proxy (`TRUST_PROXY`)

The edge is internet-facing by default and trusts **no** upstream: parapet's
inbound proxy layer overwrites `X-Forwarded-For` / `X-Real-Ip` /
`X-Forwarded-Proto` with the true TCP peer + connection scheme, so a client can't
spoof its IP. That's the right posture when the edge is the first hop (directly,
or behind an **L4 / TCP-passthrough** LB that preserves the client IP).

When the edge instead sits behind another **L7** proxy that terminates TLS and
re-originates the connection (Cloudflare, an L7 load balancer, an API gateway),
the peer is *that proxy*, not the client — so geo/ASN, WAF IP rules, the access
log, and the forwarded `X-Forwarded-For` would all see the front proxy. Set
`TRUST_PROXY` to recover the real client IP. It is the **same knob with the same
spec as the in-cluster core** (`cmd/parapet-ingress-controller`), resolved by the
shared [`trustcidr`](trustcidr/) package:

| Value | Effect |
|---|---|
| `""` / `false` (default) | distrust — overwrite `X-Forwarded-*` with the peer (first-hop posture) |
| `true` | trust every remote (only behind a closed network you fully control) |
| CIDR list | trust those source IPs, e.g. `TRUST_PROXY=10.0.0.0/8,192.168.1.1/32` |
| named group(s) | `cloudflare` / `google` / `bunny` expand to that provider's published ranges; combinable, e.g. `TRUST_PROXY=cloudflare,10.0.0.0/8` |

Because parapet's proxy layer is the **outermost** handler (it runs before the
edge WAF, the geo-header middleware, the access log, and the forwarder), trusting
the front proxy flows the real client IP through the entire edge pipeline in one
shot. A malformed value fails fast at startup. Trust is **by source IP only** —
it is no stronger than the front proxy's own ingress filtering, so an attacker who
can reach the edge directly from a trusted CIDR can spoof `X-Forwarded-For`; keep
the edge reachable only from the front proxy.

> **Implementation parity:** the edge-side `TRUST_PROXY` knob currently exists in
> the **Go** edge (`cmd/edge-proxy`); the Rust edge does not yet honor it.

## Response cache at the edge

An optional **HTTP response cache** on the edge, off by default. The edge sits
close to clients and (above) can be 200–300 ms from the cluster, so serving a
cacheable object locally removes a full origin round trip. Enabled with
`EDGE_CACHE_ENABLED=true`.

> **Reusable parapet feature.** The cache is **`parapet/pkg/cache`** — a
> general response-cache middleware with a pluggable storage backend — not
> edge-specific code. The parapet *controller* doesn't enable it, so it carries no
> controller mirror or `conformance/` obligation; the edge is just its first
> consumer. Recorded as an edge divergence in [`SPEC.md`](SPEC.md).

### What it does

- **Pluggable backend (`parapet/pkg/cache`).** A middleware wrapping the upstream
  forwarder, with two storage backends selected by `EDGE_CACHE_BACKEND`:
  **`disk`** (default — sharded files + a JSON `.meta` sidecar; the body is
  **streamed** to a temp file, so it survives restarts and isn't bounded by RSS,
  which matters given the edge's memory-pressure history) and **`memory`** (bodies
  in RAM, lost on restart). Total size is bounded by an **LRU** keyed on body
  bytes (`EDGE_CACHE_MAX_SIZE`); per-object size by `EDGE_CACHE_MAX_FILE_SIZE`. A
  `Content-Length` over the cap is simply not cached (the client still gets the
  full response). A GET is cached **only with a `Content-Length`** and committed
  only once written bytes == `Content-Length` — so a truncated response (client
  disconnect, upstream error) is never stored; a chunked (no-`Content-Length`) GET
  passes through uncached (Go's `httputil.ReverseProxy` gives no clean
  end-of-stream signal to a wrapping `ResponseWriter`). HEAD has no body and is
  unaffected.
- **Honor-origin policy.** Caches **only** when the origin opts in via response
  `Cache-Control`/`Expires` freshness — no forced or heuristic TTL. Refuses
  `private`/`no-store`/`no-cache`, any `Set-Cookie`, and `Vary: *`. Honors `Vary`
  (keys per varied request header). `GET`/`HEAD` only; a conservative set of
  cacheable status codes. **Client** request `Cache-Control` (`no-cache`/
  `no-store`) is **ignored by design** — like a CDN, so a client can't bust the
  shared cache (a DoS vector); origins needing freshness simply mark responses
  uncacheable.
- **Cache lock.** Concurrent misses for one key collapse into a single origin
  fetch (no stampede): the first request fills while streaming to its own client
  and to disk; others wait (≤ a 2s timeout) then read the just-filled entry, or
  fall through to their own fetch if it turned out uncacheable.
- **Observability.** Sets `X-Cache: HIT|MISS` (HIT = served from the edge cache,
  MISS = fetched from parapet). Cache hit/miss counts are not yet a Prometheus
  metric; the edge does expose a `:9187` metrics endpoint (connections, bytes, Go
  runtime) — `EDGE_METRICS_LISTEN`, set `""` to disable.

### On-disk layout (sharded by hash)

```
<EDGE_CACHE_DIR>/<aa>/<variant>.body   response body bytes
<EDGE_CACHE_DIR>/<aa>/<variant>.meta   JSON sidecar: status, headers, vary, created, fresh-until, size
<EDGE_CACHE_DIR>/tmp/<variant>.<seq>   in-progress writes, atomically renamed
```

`variant` = `hash(primary ⊕ Vary-variance)`, where `primary = hash(host + method
+ scheme + uri)` and the variance is the request's values for the response's
`Vary` headers; `<aa>` is the first 2 hex chars (shard). Writes are temp-file +
fsync + atomic `rename`, with the `.meta` written **last** so its presence implies
a complete `.body`; a crash mid-write leaves only an orphan, reaped later. The LRU
accounting is in-memory, so on startup the edge **scans the cache dir and
re-admits** surviving entries (each `.meta` carries the body size + the primary's
`Vary` names, re-learned for keying) — the byte cap holds across restarts, and
orphans/torn writes/expired entries are reaped. The scan runs **in the background,
off the serving path** (it reads every `.meta`, so it can take seconds on a large
cache); the edge accepts traffic immediately and the byte cap simply lags until
the scan completes. Reaping is age-gated so a concurrent in-flight commit is never
deleted.

### WAF interaction (security note)

The cache phases run **after** `request_filter`, so the edge WAF still screens
every request, including cache hits. **But a hit is served without contacting
parapet, so parapet's authoritative WAF does not re-run on hits.** This is normal
CDN behavior: only origin-opted-in (`Cache-Control` public) content is cached —
content the origin has marked safe for a shared cache. Do not mark per-user or
authorization-sensitive responses publicly cacheable.

### Config

```
EDGE_CACHE_ENABLED       on/off (default false)
EDGE_CACHE_BACKEND       disk | memory (default disk)
EDGE_CACHE_DIR           cache root, disk backend only (default /var/cache/parapet-edge)
EDGE_CACHE_MAX_SIZE      total bytes cap, LRU-evicted (default 1073741824 = 1 GiB)
EDGE_CACHE_MAX_FILE_SIZE per-object bytes cap (default 8388608 = 8 MiB)
EDGE_CACHE_PURGE_POLL_INTERVAL   poll GET /v1/purges (default 10s; lower than the
                                 cert/WAF refresh — invalidation latency matters more)
EDGE_CACHE_PURGE_SWEEP_INTERVAL  background reaper cadence (default 300s)
```

`EDGE_CACHE_PURGE_POLL_INTERVAL` / `EDGE_CACHE_PURGE_SWEEP_INTERVAL` belong to the
**design-only** purge feature below and are **not read by any code yet**.

A fetch/IO error on the read path **fails static** (degrades to a cache miss →
serve from origin), never erroring the client request. **Not yet:**
stale-while-revalidate / stale-if-error, Range/partial caching, per-route policy
via Ingress annotations, chunked-GET caching (a GET needs a `Content-Length`),
and cache hit/miss Prometheus metrics (the `:9187` listener exists for
connection/byte/runtime metrics).

### Purge / invalidation

> **Status: design only — not implemented** (in neither the edge nor the control
> plane). The mechanism below was sketched against the former Rust/pingora cache;
> the equivalent will be built in `parapet/pkg/cache` (lazy epochs checked in the
> lookup gate + a background reaper) when Phase 5 lands. The CP `/v1/purges`
> endpoints do not exist yet either.

Invalidation is **pulled from the control plane**, exactly like cert and WAF
distribution: an operator publishes a purge once at the control plane and every
sharded edge converges on its own timer. There is **no inbound purge port on the
edge** (edges are out-of-cluster, often NAT'd), and the per-token host scoping is
the same boundary that gates `/v1/certs` and `/v1/waf`. Three scopes are
supported: **exact URL** (all `Vary` variants, both schemes, GET+HEAD),
**whole host/zone**, and **flush-all**.

**Why lazy epochs, not eager file deletion.** The on-disk filename is
`combined()` = `hash(primary ⊕ variance)`, where `primary = hash("METHOD scheme
uri")` and `variance` comes from `Vary`. So from a URL alone you **cannot
enumerate its variants' filenames** — there's no index, and the hash mixes the
two. `Storage::purge(CompactCacheKey)` needs the *exact* key (primary+variance),
which an operator purging a URL doesn't have. But `lookup` receives the full
`CacheKey` (namespace = host, primary *string* = `"GET https /a?x=1"`), so the
edge can match a request against a coarse predicate at lookup time regardless of
variance. That asymmetry is why purge is **lazy epoch invalidation** plus a
background reaper, not synchronous deletes.

**The invalidation table** (small, in-memory, persisted to
`<EDGE_CACHE_DIR>/purge-state` with the same temp+fsync+rename as the cache):

```
global:  Option<SystemTime>
host:    host                       → SystemTime    (lowercased host)
url:     hash(host ⊕ uri)           → SystemTime    (uri = path+query; method/scheme-agnostic)
cursor:  u64   (last journal seq applied — persisted in the SAME atomic write as the maps)
```

**Lookup gate**, added to `DiskCache::lookup` after decoding the sidecar:

```
invalid_after = max(global, host[namespace], url[hash(namespace ⊕ uri_of(primary))])  // absent ⇒ epoch 0
if meta.created() <= invalid_after { reap(.meta,.body) best-effort + notify eviction; return miss }
```

Keying the `url` map on `host ⊕ uri` (not the full primary) is deliberate: one
URL purge then covers **all methods, both schemes, and every `Vary` variant** —
the operator's mental model of "purge `/a`". Issue cost is **O(1)** (no scan, no
variance enumeration); the hot-path cost is one lock read + ≤3 map lookups + a
timestamp compare, and only on cache lookups (so zero when caching is disabled).

**Edge-clock epochs — no trusted CP timestamp.** An epoch is *"invalidate
everything cached before this edge learned of the purge"* = the edge's own wall
clock at first-apply. This removes any CP↔edge clock-skew dependency; the control
plane only has to **deliver** the directive. Idempotency comes from the cursor,
not the timestamp: the edge applies a journal `seq` only if `seq > cursor`, so an
entry is applied exactly once and "now-at-apply" is never replayed. The one
inherent gap — an in-flight miss whose origin fetch began before apply but commits
just after — is the same race every CDN purge has; the next TTL expiry or purge
covers it. (Clamp epochs to be monotonic non-decreasing so an NTP step back can't
un-purge.)

**Background reaper** (reuses the startup-scan background-thread pattern, off the
serving path) periodically applies the table to physically delete invalidated
files, update the LRU accounting, and **retire** table records: once a full sweep
completes *after* a record's timestamp, nothing older can remain, so the record is
dropped. This is what bounds the `url` map (it holds only URLs purged within
roughly one sweep interval) and reclaims disk; the lazy gate already guarantees
correctness immediately, and the LRU byte cap holds regardless.

**Distribution loop.** The control plane keeps a bounded append-only journal
(`{seq, scope, host?, uri?}`, monotonic `seq`, `min_seq` = oldest retained). The
edge polls `GET /v1/purges?since=<cursor>` on `EDGE_CACHE_PURGE_POLL_INTERVAL`; on
`flush_required` it bumps the `global` epoch and sets `cursor = max_seq`, else it
applies each new entry once and atomically persists `{maps, cursor}`. Purges are
issued by an admin `POST /v1/purges` (a **stronger** credential than the per-edge
read token); auto-sourcing a `host` purge on cert rotation or Ingress change is a
natural later addition.

## Ports & exposure

```
edge           :443   public TLS (terminated locally)       EDGE_HTTPS_LISTEN
               :80    public plaintext (on; ""=disable)     EDGE_HTTP_LISTEN
parapet        :80    data (HTTP/1.1 from edge)            unchanged role, now behind edge
               :443   data (re-encrypt from edge)
               :9187  metrics
controlplane   :8443  HTTPS GET (server-TLS + bearer)       NEW — Go, own Service
                      (or plaintext HTTP on a trusted private network — TLS off)
                      distributes PRIVATE KEYS; NetworkPolicy: edge sources only;
                      NOT on the public LB
```

### Plaintext HTTP listener (no redirect — the core decides)

`EDGE_HTTP_LISTEN` (default `0.0.0.0:80`; set to `""` to disable) adds a second,
plaintext listener to the same proxy service. The edge **does not** redirect
http→https itself; it forwards the request to parapet with `X-Forwarded-Proto:
http` (the scheme is set from the terminating listener — `r.TLS`, surfaced as
`X-Forwarded-Proto` by the parapet server — so the TLS listener still forwards
`https`). parapet's per-ingress `redirect-https` plugin
then makes the decision — 301 to https, or serve — exactly as it does without the
edge. The global/zone WAF runs on this listener too. Keeping the redirect policy
in the core means it stays a single source of truth (annotation-driven, with the
`/.well-known/acme-challenge` carve-out) rather than being duplicated at the edge.

## The tradeoff

Shipping the key removes the latency/availability costs of keyless, at a real
security cost: the public **private key now lives outside the cluster**, on the
edge, for that edge's allowlisted domains. A compromised edge therefore **leaks
those keys** (not merely "can sign while live") — recovery means **reissuing /
revoking the certs**, not just dropping a token. Mitigations:

- **Sharding** bounds each edge to its own domains' keys.
- **Memory-only** key cache (never on disk) keeps at-rest exposure minimal.
- **Short cert lifetimes + rotation** shrink the useful-leak window.
- Per-edge **token authz** gates which keys an edge may fetch; tokens revocable.

This is a deliberate move of the dial toward latency/simplicity, appropriate when
the edge cannot be co-located with the cluster. If key-secrecy dominates and the
edge *can* be co-located, prefer keyless (recoverable in git history).

## Fail modes

| Failure | Behavior |
|---|---|
| `GET /v1/certs` unreachable | Edge keeps serving cached cert+key (**fail static**); retries with backoff. New handshakes unaffected. |
| `GET /v1/waf` unreachable | Edge keeps last-good rules (**fail static**). Never "no WAF". |
| Bad rule snapshot | All-or-nothing compile rejects the batch; previous good ruleset stays live. |
| Edge compromised | Leaks its allowlisted domains' keys → **reissue/revoke those certs**; revoke the edge's token. Other edges/domains unaffected. |
| Cert rotation gap | Overlapping refresh + fail-static avoid a window where the edge has no usable cert. |
| Cache read IO error | Degrades to a cache miss (**fail static**) → served from parapet. Never errors the client request. |
| Cache dir unwritable | Cache init fails → caching disabled for the process (logged); the edge still proxies normally. |
| `GET /v1/purges` unreachable | Edge keeps its applied epochs + cursor (**fail static**); retries with backoff. Pending purges are *delayed, not lost* — the journal+cursor catch up. Stale-serving window bounded by object TTL. |
| Purge cursor gap (`since < min_seq`) | CP returns `flush_required` → edge bumps the global epoch (lazy flush-all) and jumps to `max_seq`. Conservative; never under-invalidates. |
| `purge-state` lost/corrupt | Cursor resets to 0 → next poll is a gap → flush-all. Cursor + maps share **one atomic write** so they can't desync. |

## Conformance

The edge reuses `parapet/pkg/waf` (the controller's Go CEL engine), so it passes
the existing [`conformance/waf-cel-corpus.md`](conformance/waf-cel-corpus.md) by
construction — via the same Go surface the controller is checked against.
The HTTPS API and the "edge evaluates global+zone WAF identically to parapet,
which remains authoritative" property are recorded in [`SPEC.md`](SPEC.md).

## Build layout

- **Control plane** is a Go binary in the Go module (now at the repo root)
  (`cmd/edge-controlplane`, image `Dockerfile.edge-controlplane`), reusing
  `cert`, `k8s`, `wafrule`.
- **Edge** is a Go binary in the same Go module (`cmd/edge-proxy` + the
  `edge` lib, image `Dockerfile.edge`), on the parapet framework, reusing
  `cert`, `wafrule`, `geoip`, and `parapet/pkg/waf`. Pure Go (no CGO/
  brotli) → static binary on `distroless/static`, with the IPLocate GeoIP MMDBs
  baked like the controller image.

Both build/test with the Go toolchain (`go test ./... && go vet ./...`).
They never share in-process state; the HTTP/JSON contract above is their entire
runtime interface (they do share Go libraries at compile time).

`.github/workflows/edge-build.yaml` builds both images (tags `:controlplane-<sha>`
and `:edge-<sha>`); `edge-e2e.yaml` runs the cluster-free smoke test
(`deploy/edge/e2e/run.sh`). Image tag prefixes are component-keyed (not
language-keyed), so `:edge-<sha>` carried over the Rust→Go migration unchanged.

## Implementation history

The edge was originally **Rust/Pingora** (`rust/edge`, openssl backend, a
`rust/` workspace member depending on the `controller` crate). It was migrated to
**Go** on the parapet framework after recurring memory bugs in pingora 0.8 —
notably the per-peer `ConnectionPool` leak (cloudflare/pingora#748) and the
downstream HTTP/2 idle-connection leak, both worked around with patched-vendored
crates (`rust/Cargo.toml` `[patch.crates-io]`) but not fully resolved upstream.
The Go edge reuses the controller's Go libraries (`cert`, `wafrule`, `geoip`,
`parapet/pkg/waf`), so it shares the WAF/GeoIP contract by construction and gets
HTTP/2 `Cookie` reassembly for free from `net/http`. `rust/edge` was **removed**
after the Go edge soaked in production — it is recoverable from git history if
needed. (The Rust **controller** implementation stays in `rust/`; only the Rust
*edge* was retired.)

## Phasing

1. **Cert+key distribution** — controlplane `/v1/certs` (bearer authz) + edge
   in-memory cert store, timer refresh, local TLS termination, forwarding.
   **(done)**
2. **WAF distribution + edge global eval** — `/v1/waf` (global ruleset,
   `generation`), edge consumes + evaluates global, fails static. **(done)**
3. **Zones at edge** — host→zone map derivation + per-edge zone scoping + edge
   zone evaluation, with the parapet-authoritative backstop. **(done)** Zone
   resolution at the edge is **host-level** (an Ingress binds a zone and lists
   hosts; the control plane derives `host → zoneKey` from Ingress objects and
   ships it scoped to the edge's allowed hosts, alongside the zone rulesets).
   Path-precise zone resolution stays parapet's authoritative job — if the edge's
   host-level binding ever diverges, parapet corrects it on its re-run.
4. **Response cache** — optional disk-backed HTTP cache (`EDGE_CACHE_*`),
   honor-origin policy, LRU-bounded, restart-persistent, fail-static. **(done)**
   See [Response cache at the edge](#response-cache-at-the-edge). Edge-only (no
   parapet-core equivalent).
5. **Cache purge / invalidation** — CP purge journal + `GET`/`POST /v1/purges`,
   edge poll loop with a persisted cursor, lazy epoch invalidation (global / host /
   url) checked at lookup, and a background reaper for disk reclaim. Scopes:
   exact-URL (all variants), whole-host/zone, flush-all. **(design)** See
   [Purge / invalidation](#purge--invalidation). Edge-only. Path-prefix and
   Cache-Tag purge are deferred (prefix needs a scan; tags must be recorded at
   admit time) — the epoch table extends to both later.
