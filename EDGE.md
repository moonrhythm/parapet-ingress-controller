# Edge control plane (cert+key distribution + WAF distribution)

An **out-of-cluster edge reverse proxy** that terminates public TLS locally and
runs the WAF, fronting the in-cluster parapet ingress controller. A small
in-cluster **control plane** distributes, per edge, only the certificates (and
private keys) and WAF rules for the domains that edge serves.

> Status: **design + Phase 1 in progress.** The control plane is **Go**
> (`go/cmd/edge-controlplane`, reusing `go/cert`, `go/k8s`, `go/wafrule`); the
> edge is **Rust** (`rust/edge`, Pingora). They share **only a language-neutral
> HTTP/JSON contract** (below) — no shared library, so the two languages are
> fully decoupled. Per [`CLAUDE.md`](CLAUDE.md) the contract changes here first.

> **Language split.** The control plane reads k8s objects and is a natural fit
> for the Go controller's existing cert/k8s/wafrule packages, so it lives in
> `go/`. The edge needs Pingora, so it stays in `rust/`. Nothing is shared in
> code — the HTTP/JSON API is the entire interface. (An earlier iteration put a
> gRPC control plane in `rust/controlplane`; that was superseded when the design
> moved off keyless and to a Go REST service.)

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
4. **One WAF language everywhere.** The edge reuses `controller::waf` (cel-rust)
   verbatim, so it's a third consumer of the same CEL contract the
   [`conformance/`](conformance/) corpus already guards — no reimplementation.

## Topology

```
                              ┌─ in cluster ──────────────────────────────┐
client ──TLS──► edge (Pingora, outside k8s)                               │
                  │ terminates public TLS *locally* (holds cert+key)      │
                  │ runs global + zone WAF (early drop)                   │
                  │                                                       │
                  ├── HTTPS GET (bearer token) ─► controlplane :8443      │
                  │     GET /v1/certs/{sni} → cert+key+ETag (allowed SNI) │
                  │     GET /v1/waf         → rules for edge domains (Ph.2)│
                  │   authz: bearer token → allowed domains/zones         │
                  │   reads: TLS Secrets, WAF ConfigMaps, Ingresses       │
                  │   refreshed on a timer; cached in memory only         │
                  │                                                       │
                  └── data: h2c :80 / re-encrypt :443 ──► parapet ───► svc │
                        (sets X-Forwarded-For/-Proto/-Country/-ASN)        │
                        parapet re-runs WAF authoritatively + routes       │
                              └──────────────────────────────────────────┘
```

### Two channels, kept apart

| Channel | From → to | Protocol | Exposure |
|---|---|---|---|
| **Data plane** | edge → parapet `:80`/`:443` | HTTP (h2c) or re-encrypted TLS | private path |
| **Control plane** | edge → controlplane `:8443` | HTTPS GET (server-TLS + bearer token) | private path, edge sources only |

Separate ports on separate Services. The control plane distributes **private
keys**, so it must never be on the public LoadBalancer. See
[Ports & exposure](#ports--exposure).

## Components

- **`go/cmd/edge-controlplane/`** (Go) — in-cluster HTTPS REST server. Reuses the
  Go controller's k8s client (`go/k8s`), cert table (`go/cert`), WAF rule parser
  (`go/wafrule`), and route/zone logic. Serves `GET /v1/certs/{sni}` (cert+key)
  and `GET /v1/waf` (rules). Not on the request path.
- **`rust/edge/`** (Rust) — a Pingora proxy (openssl TLS backend, same as the
  controller). Reuses `controller::cert::{Table, LoadedCert}` for SNI resolution
  and the `TlsAccept::certificate_callback` pattern from
  `controller::proxy::cert` to install the matched cert+key locally. Maintains an
  in-memory cert store refreshed from `GET /v1/certs?sni=…`, and (Phase 2+)
  `controller::waf` for CEL evaluation. Forwards to parapet with `X-Forwarded-*`.

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
private key** in flight and lets the edge authenticate the control plane. Tokens
are revocable (drop from the table) and rotatable, and requests are rate-limited
to blunt enumeration.

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
3. The edge parses the PEM into an openssl chain+key (cached via
   `LoadedCert::parsed()`) and **atomically swaps** it into its in-memory
   `cert::Table`. Keys are **never written to disk**.
4. A handshake reads the live table and installs the matched cert+key locally —
   no control-plane interaction on the handshake path.

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

1. Terminate TLS locally → build the `request` map. The edge is the first hop, so
   `request.remote_ip` is the **true peer**, and GeoIP/ASN are resolved from it at
   the edge — *more* accurate than parapet behind it. The edge loads the IPLocate
   `.mmdb`s via the same env contract as the controller (`WAF_GEOIP_DB` /
   `WAF_ASN_DB`; `""` disables; baked default path; ASN DB ~74 MB), so
   `request.country` / `request.asn` work for edge-evaluated rules. When a DB is
   loaded the edge also forwards `X-Forwarded-Country` / `X-Forwarded-ASN` to
   parapet (overwriting any client value), matching the controller's upstream
   behavior. With no DB loaded, `country` is `""` and `asn` is `0` (the field is
   always present, so a rule never errors) — such a rule simply won't early-drop
   at the edge, but parapet still re-runs it authoritatively.
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

## Response cache at the edge

An optional **HTTP response cache** on the edge, off by default. The edge sits
close to clients and (above) can be 200–300 ms from the cluster, so serving a
cacheable object locally removes a full origin round trip. Enabled with
`EDGE_CACHE_ENABLED=true`.

> **Edge-only feature.** The edge is Rust-only by design (see *Language split*);
> there is no Go edge, so this is **not** a parapet-core behavior change and
> carries no `go/` mirror or `conformance/` obligation. parapet itself does not
> cache. Recorded as an edge divergence in [`SPEC.md`](SPEC.md).

### What it does

- **Disk-backed.** Pingora 0.8 ships only an in-memory `MemCache` ("testing");
  there is no disk Storage in the OSS release (cloudflare/pingora#210), so the
  edge implements the `pingora::cache::Storage` trait against the filesystem
  (`rust/edge/src/diskcache.rs`). A disk cache survives restarts and isn't bounded
  by RSS (matters given the edge's memory-pressure history). Total size is bounded
  by an LRU eviction manager (`EDGE_CACHE_MAX_SIZE`); per-object size by
  `EDGE_CACHE_MAX_FILE_SIZE`, enforced by pingora's own size tracker — a
  `Content-Length` over the cap is simply not cached (the client still gets the
  full response); an oversize **chunked** response is aborted mid-stream.
- **Honor-origin policy.** Caches **only** when the origin opts in via response
  `Cache-Control`/`Expires` freshness — no forced or heuristic TTL. Refuses
  `private`/`no-store`, any `Set-Cookie`, and `Vary: *`. Honors `Vary` (keys per
  varied request header). `GET`/`HEAD` only; cacheable status codes per RFC.
  **Client** request `Cache-Control` (`no-cache`/`no-store`) is **ignored by
  design** — like a CDN, so a client can't bust the shared cache (a DoS vector);
  origins needing freshness simply mark responses uncacheable.
- **Cache lock.** Concurrent misses for one key collapse into a single origin
  fetch (no stampede).
- **Observability.** Sets `X-Cache: HIT|MISS` (HIT = served from the edge cache,
  MISS = fetched from parapet). No metrics endpoint yet — the edge exposes none.

### On-disk layout (sharded by hash)

```
<EDGE_CACHE_DIR>/<aa>/<hash>.body   response body bytes
<EDGE_CACHE_DIR>/<aa>/<hash>.meta   framed sidecar: CacheMeta + CompactCacheKey
<EDGE_CACHE_DIR>/tmp/<hash>.<seq>.* in-progress writes, atomically renamed
```

Writes are temp-file + fsync + atomic `rename`, with the `.meta` written **last**
so its presence implies a complete `.body`; a crash mid-write leaves only an
orphan, reaped later. The eviction manager's accounting is in-memory, so on
startup the edge **scans the cache dir and re-admits** surviving entries (the
sidecar carries the `CompactCacheKey` for exactly this) — the byte cap holds
across restarts, and orphans/torn writes are reaped. The scan runs **in the
background, off the serving path** (it reads every `.meta`, so it can take
seconds on a large cache); the edge accepts traffic immediately and the byte cap
simply lags until the scan completes. Reaping is age-gated so a concurrent
in-flight commit is never deleted.

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
EDGE_CACHE_DIR           cache root (default /var/cache/parapet-edge)
EDGE_CACHE_MAX_SIZE      total bytes cap, LRU-evicted (default 1073741824 = 1 GiB)
EDGE_CACHE_MAX_FILE_SIZE per-object bytes cap (default 8388608 = 8 MiB)
```

A fetch/IO error on the read path **fails static** (degrades to a cache miss →
serve from origin), never erroring the client request. **Not yet:** purge/
invalidation API, stale-while-revalidate / stale-if-error, Range/partial caching,
per-route policy via Ingress annotations, and cache metrics + a `:9187` listener.

## Ports & exposure

```
edge           :443   public TLS (terminated locally)       EDGE_HTTPS_LISTEN
               :80    public plaintext (on; ""=disable)     EDGE_HTTP_LISTEN
parapet        :80    data (h2c from edge)                 unchanged role, now behind edge
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
http` (the scheme is detected per connection from the TLS digest, so the TLS
listener still forwards `https`). parapet's per-ingress `redirect-https` plugin
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

## Conformance

The edge reuses `controller::waf`, so it passes the existing
[`conformance/waf-cel-corpus.md`](conformance/waf-cel-corpus.md) by construction.
The HTTPS API and the "edge evaluates global+zone WAF identically to parapet,
which remains authoritative" property are recorded in [`SPEC.md`](SPEC.md).

## Build layout

- **Control plane** is a Go binary in the existing `go/` module
  (`go/cmd/edge-controlplane`), reusing `go/cert`, `go/k8s`, `go/wafrule`. Built
  and tested with the Go toolchain (`cd go && go test ./... && go vet ./...`).
- **Edge** is a Rust binary using Pingora's **openssl** TLS backend (the
  controller's backend), so it's a normal member of the `rust/` workspace — no
  separate workspace, no boringssl. It depends on `controller` with the `proxy`
  feature (for `cert::LoadedCert::parsed()` + later `waf`).

The two never link; the HTTP/JSON contract above is their entire interface.

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
