# Cache overrides (ConfigMap-driven, global + zones)

Per-request **cache policy overrides** at the edge response cache, with a
**global** baseline set (platform-owned) plus opt-in **zones** (tenant-owned)
that an ingress binds by reference — the same zone model as the [WAF](WAF.md)
and [rate limiting](RATELIMIT.md), under its own marker label. A rule scopes
itself with a CEL `filter` (the WAF's exact expression surface) and then either
**forces** a caching policy onto an otherwise-uncacheable (or
short-lived) origin response, or **bypasses** the cache entirely for matching
requests. The runtime is `parapet/pkg/cache`'s own per-request hooks
(`Options.Cacheable`, `Options.Override`); the parser lives in
[`cacherule/`](cacherule/).

> Status: **proposed** (design locked, pre-implementation). Edge-only — see
> [Scope](#scope-and-non-goals). Gated by `EDGE_CACHE_OVERRIDE_ENABLED` on the
> edge + `CP_CACHE_ENABLED` on the control plane (off by default — disabled
> means no ConfigMap watch on the CP, no `/v1/cache` endpoint, no per-request
> work on the edge). It requires `EDGE_CACHE_ENABLED=true`: an override only
> steers the cache, so with no cache there is nothing to steer.

> **Why this exists.** The edge cache is strictly **honor-origin** (see
> [EDGE.md](EDGE.md#response-cache-at-the-edge)): it caches *only* when the
> origin opts in with explicit `Cache-Control`/`Expires` freshness, and never
> invents a TTL. That is the correct default, but it leaves two real gaps an
> operator cannot close from the origin: an origin you **don't control** (or one
> that forgot to send cache headers) is permanently uncacheable, and an origin
> that **over-shares** (sends cacheable headers on a per-user or dynamic path)
> can't be fenced off without an origin redeploy. Cache overrides are the edge's
> escape hatch for both — *force* the first, *bypass* the second — scoped by CEL
> so the policy lands only where the operator means it to.

This complements, not replaces, the cache's built-in policy:

| Layer | Configured by | What it decides |
|---|---|---|
| Honor-origin policy | origin response `Cache-Control`/`Expires` | the default: cache iff the origin opts in |
| **Global overrides** | ConfigMap `…/cache: global` | force/bypass across **all** edge traffic |
| **Zone overrides** | ConfigMap `…/cache: zone` + `cache-zone` annotation | force/bypass across a tenant's ingresses |

## Override schema (the contract)

Each ConfigMap `data` value is one `overrides:` document. Multiple keys (and
multiple global ConfigMaps) are kept as a `[]string` and parsed one document
each — **never `---`-joined** (the same wire rule as rate limits: `Parse` takes
one document per string and would silently drop everything after the first
`---`).

```yaml
overrides:
  - id: static-assets       # required; unique in the set; [A-Za-z0-9._-], <= 63 chars
    action: cache           # cache (default) | bypass
    filter: |               # optional CEL — the override applies only when true
      request.path.startsWith("/static/")
    ttl: 1h                 # required for action=cache; forced freshness lifetime (Go duration, 1s..max)
    policy: balanced        # conservative | balanced (default) | aggressive  — how far the force reaches
    stale_while_revalidate: 30s   # optional; serve stale + refresh in background (rides the force, needs ttl)
    stale_if_error: 1h            # optional; serve stale when a revalidation errors (needs ttl)
    status: [200, 301, 404] # optional; only force these origin response statuses
    mode: enforce           # enforce (default) | shadow
    priority: 100           # ascending; first match wins among cache rules
  - id: never-cache-account
    action: bypass          # matching requests skip the cache entirely
    filter: |
      request.path.startsWith("/account/") || request.headers["authorization"] != ""
    priority: 10
```

- **`action`** selects which of the cache's two per-request hooks the rule
  drives:
  - **`cache`** — on a cache fill, force a policy (`ttl`/`policy`/stale windows)
    into the stored entry. Drives `parapet/pkg/cache`'s `Options.Override`.
  - **`bypass`** — the matching request never touches the cache (served straight
    from the origin, no `X-Cache` header, no egress accounting). Drives
    `Options.Cacheable` → `false`. A bypass **takes precedence** over any
    `cache` rule (the cache evaluates `Cacheable` before it ever considers a
    fill), so a `bypass` is an absolute carve-out.
- **`filter`** is an optional CEL expression that **scopes** the override: empty
  means "every request", otherwise the rule applies only where it matches. It is
  the **exact same surface as the [WAF](WAF.md)** — `request.method`,
  `request.path`, `request.host`, `request.headers[...]`, `request.country`/
  `request.asn`, the helpers (`ipInCidr`, `regexMatch`, `containsAny`, `lower`,
  `urlDecode`, …) — compiled through the one shared `waf.Predicate`, identical to
  the rate-limit `filter`, so the three CEL surfaces cannot drift. A `cache`
  rule may additionally narrow by response `status` (below), which CEL can't see
  at request time. Semantics that matter:
  - **`request.body` is always `""`** — the cache runs late in the chain but
    never buffers the request body, so a `filter` cannot inspect it. Everything
    else in the request model is present.
  - A geo reference (`request.country`/`request.asn`) **without the GeoIP
    database** is not a load error — the field is just `""` / `0`, so the filter
    simply never matches and the rule stays inert. Wire `WAF_GEOIP_DB`/
    `WAF_ASN_DB` to make it match (the resolvers load when the edge WAF, rate
    limiting, **or** cache overrides are enabled).
  - **A runtime eval error biases toward NOT caching** — see
    [the fail direction](#evaluation-precedence-and-the-fail-direction). This is
    the one place this feature inverts the rate-limiter's fail-*open*: there, not
    throttling is the safe action; here, not caching is.
  - A bad expression is rejected at **load** (all-or-nothing, like every other
    field): the set keeps its last-good overrides and the input is retried, so a
    typo never silently changes caching at request time.
- **`ttl`** is the forced freshness lifetime and is **required for
  `action: cache`** — `parapet/pkg/cache` treats a non-positive TTL as "don't
  force", so a `cache` rule without one would do nothing (rejected at load).
  Already-cached entries keep the TTL that was baked in at *their* fill time;
  changing a `ttl` re-policies only **future** fills (see
  [Reload semantics](#reload-semantics-stateless-fills-bake-in)).
- **`policy`** selects how far the force reaches over the origin's own
  `Cache-Control` (it maps to `parapet/pkg/cache`'s `OverrideMode`; the forced
  policy is baked into the **stored** entry only — the served `Cache-Control`
  stays the origin's and does not propagate downstream):
  - **`conservative`** — fill freshness only when the origin declares **none**;
    otherwise honor the origin entirely (`no-cache`/`no-store`/`private` and any
    explicit `max-age` are respected). Safest; the right choice for "cache what
    the origin forgot to mark".
  - **`balanced`** (default) — force freshness, overriding `no-cache`/`max-age`/
    `Expires`, but still **refuse** a response that is unsafe to share:
    `no-store`, `private`, `Set-Cookie`, `Vary: *`, a non-cacheable status, an
    oversize body, or an `Authorization`-bearing request without a shared opt-in.
    The correct default for forcing a TTL onto static assets.
  - **`aggressive`** — override almost everything, **including the
    `Authorization` gate**. ⚠️ **DANGER: cross-user leak.** The cache key ignores
    `Cookie`/`Authorization`, so forcing past the `Authorization` gate stores one
    user's authenticated response under a shared key and serves it to others.
    Only use it for endpoints with **no per-user or secret data**, or where the
    origin sends `Vary: Authorization`. A filter eval error **never** applies an
    `aggressive` rule (the fail-safe below). Prefer `balanced` unless you are
    certain.
- **`stale_while_revalidate` / `stale_if_error`** force the RFC 5861 windows for
  this rule's fills (serve stale immediately while a background refresh runs /
  serve stale when a revalidation errors). They ride the same forced policy, so
  they **require a `ttl`**. For fleet-wide stale serving **without** forcing a
  TTL — i.e. applied to every honor-origin entry the cache already keeps — set
  the `EDGE_CACHE_DEFAULT_SWR`/`EDGE_CACHE_DEFAULT_SIE` env defaults instead (an
  explicit per-rule window wins over the default).
- **`status`** narrows a `cache` rule to specific origin response statuses (the
  `Override` hook sees the response, unlike CEL). Empty means "every cacheable
  status the cache already accepts" (`200, 203, 204, 300, 301, 308, 404, 410`).
  Ignored for `bypass` (there is no response yet when `Cacheable` runs).
- **`mode: shadow`** evaluates the rule and **counts** it
  (`parapet_cache_override_total{result="shadow"}`) but does **not** change
  caching — ship shadow, watch the metric to confirm the rule matches what you
  expect, then flip to `enforce`. The same rollout story as WAF `action: log`
  and rate-limit `mode: shadow`.
- **`priority`** orders `cache` rules; the **first** matching `cache` rule wins
  (lower number first; ties break by `id`). `bypass` rules are not ordered
  against each other — any matching bypass bypasses.

## Delivery: ConfigMaps, one marker label

The label key **`parapet.moonrhythm.io/cache`** marks a ConfigMap as
cache-override input; the value selects the role — exactly the WAF's and
rate-limit's model, under a separate key (a Kubernetes label selector can't OR
two keys):

| Label | Meaning | Where it's honored |
|---|---|---|
| `parapet.moonrhythm.io/cache: global` | contributes to the global set | only in the control plane's own namespace (`POD_NAMESPACE`) |
| `parapet.moonrhythm.io/cache: zone` | one zone; zone ID = ConfigMap **name** | any watched namespace |

Restricting `global` to `POD_NAMESPACE` is the security boundary: only the
platform team can change caching for all traffic (force-caching is a
correctness-sensitive lever). Tenants get RBAC `edit` on their own zone
ConfigMaps. A ConfigMap carrying the `cache` label **and** a `waf`/`ratelimit`
label is refused by the cache reload (one ConfigMap per feature).

### Zone binding

```yaml
metadata:
  annotations:
    parapet.moonrhythm.io/cache-zone: assets        # bare id → ingress's own namespace
    # parapet.moonrhythm.io/cache-zone: platform/assets   # ns/id → cross-namespace reference
```

Every domain/path on that ingress is matched against the `assets` zone's
overrides (in addition to the global set).

**Resolution allows cross-namespace references** (`ns/id`), following the
**`waf-zone` model, not `ratelimit-zone`**. The distinction is deliberate and
turns on shared state: a rate-limit zone carries **shared counter state**, so a
cross-namespace bind would let one tenant burn another's budgets (a cross-tenant
DoS) — hence same-namespace-only there. A cache-override zone, like a WAF zone,
is **stateless config**: binding tenant A's override zone to tenant B's ingress
applies A's policy to **B's own** traffic only — consensual, and it cannot harm
A. So there is no tenancy reason to forbid it. (The one caveat is surrogate-key
/ `Cache-Tag` purge, whose tag namespace is shared cross-tenant — but this
feature sets no tags; see [Scope](#scope-and-non-goals).)

A key that resolves to no zone — deleted, not yet created, or a **new** zone
whose first config was rejected — applies no zone overrides (the global set
still applies, and the origin's own policy still governs). Like the WAF's zone
miss, this fails toward the honor-origin default by design.

## Evaluation: precedence and the fail direction

Per request, the edge resolves the request's bound zone (path-aware, on the same
`http.ServeMux` route map as the edge WAF and rate limiter — see
[edge zone routing](EDGE.md#rate-limiting-at-the-edge)) and evaluates the global
set first, then the zone set:

- **Bypass is a union, and authoritative.** If **any** matching `bypass` rule
  fires in *either* the global or the zone set, the request bypasses the cache.
  Most-restrictive wins, so a platform guardrail (`global` "never cache
  `/admin`") can't be undone by a tenant, and a tenant can still add its own
  carve-outs. Bypass is decided at `Cacheable` time, before any lookup or fill.
- **Force is first-match, global before zone.** Among `cache` rules, evaluation
  runs the global set (by `priority`) then the zone set (by `priority`), and the
  **first** match wins — so a narrow global force is authoritative, and
  everything the platform doesn't claim falls through to the tenant's zone. This
  mirrors the WAF's "global first, authoritative" stance. (Write global `cache`
  rules narrowly; broad global forces leave tenants no room.)

**The fail direction — caching is the dangerous action, so errors bias *away*
from it.** A filter eval error (timeout, cost-limit, panic, type error) is
resolved toward **not caching**, never toward more caching:

- a `bypass` rule whose filter errors → **bypass anyway** (treat as matched);
- a `cache` rule whose filter errors → **skip the force** (honor the origin), and
  an `aggressive` rule in particular is **never** applied on an error.

The underlying principle is the same as the rate limiter's ("fail toward the
non-disruptive action") — only the safe action differs: there it's *don't
throttle* (fail open), here it's *don't serve shared/forced cache*. This matters
most for `aggressive`, which removes parapet's `Authorization`/`Set-Cookie`/
`private` backstops: a buggy expression must never be the reason a per-user
response is force-cached under a shared key.

The CEL surface, cost budget, and macro policy are **parapet's defaults**
(cost `1e6`, macros on) — identical to the edge WAF and edge rate limiter, which
also run on `waf` defaults. (The in-cluster `WAF_COST_LIMIT`/`WAF_DISABLE_MACROS`
knobs are controller-only; the edge has no equivalent.) The request snapshot is
built **once per request** and shared across all rules' filters; a set with no
filtered rules pays nothing.

### Per-request order at the edge

The override hooks live **inside** the existing cache middleware, so they need
no new chain position — the cache already sits after the WAF and rate limiter
and before the forwarder:

```
edge WAF → edge rate limits → X-Forwarded-Country/-ASN
→ RESPONSE CACHE (Cacheable: bypass rules · Override: cache rules) → forwarder
```

Consequences: a `bypass` is evaluated on every cacheable (`GET`/`HEAD`) request,
so a cache **hit** still pays one zone-resolve + the bypass filters; a `cache`
force is evaluated only on a **miss fill** (a hit already carries its baked
policy), so steady hit traffic never re-evaluates `cache` rules.

## Distribution: control plane → edge

Cache overrides ride the **same machinery as the edge rate limits** (see
[EDGE.md](EDGE.md#rate-limiting-at-the-edge)), so the wire contract, fail-static
posture, and change-notification path are all reused, not reinvented:

- The CP watches the `parapet.moonrhythm.io/cache` ConfigMaps (global honored
  only from `POD_NAMESPACE`; multi-feature ConfigMaps refused) and derives the
  `cache-zone` route→zone bindings from Ingresses on the shared Ingress watch —
  **cross-namespace allowed** (the `waf-zone` rule, not `ratelimit-zone`'s).
- It serves them at **`GET /v1/cache`**: `{ generation, global_overrides
  []string, zones map[string][]string, route_zone_map }` plus the `ETag` header.
  There is **no `host_zone_map`** — cache overrides are a new feature, so only the
  path-aware route binding is shipped (no legacy host-level wire form to support).
  Documents stay **`[]string` end to end** — one ConfigMap data value per
  string — and the CP neither parses nor reserializes them, exactly as for
  `/v1/ratelimit`. The `ETag` is computed with `generation` zeroed so
  byte-identical content from any CP replica mints the same validator (304 across
  replicas); payloads are per-token **scoped** to the edge's allowed hosts.
- The edge polls on `EDGE_REFRESH_INTERVAL` (jittered, single-flight,
  fail-static) and is **poked** by the `/v1/events` SSE stream (a new
  `cache` field in the snapshot) so a change lands in seconds, with polling as
  the correctness floor.
- **Apply is all-or-nothing and withholds the etag on failure.** A parse or
  compile error keeps the last-good set live and does **not** advance the
  etag/generation, so the next poll re-fetches (200, not 304) and re-logs — the
  twice-bitten edge gotcha: storing the etag on a rejected apply would 304 the
  broken input forever and bury it after one warning.

## Reload semantics (stateless; fills bake in)

Cache overrides are **stateless** — unlike rate limits, a rule carries no live
counter, so the reload story is just *all-or-nothing compile + keep last-good*,
with none of the per-limit strategy/counter carry-over machinery:

- An **unchanged** set (content fingerprint match) is not recompiled.
- A **bad** set (YAML error, invalid rule, bad CEL) is rejected whole; that set
  keeps its last-good overrides and the input is retried on the next reload.

The one durable subtlety is **TTL is baked at fill time.** A `cache` rule forces
its `ttl`/`policy` into an entry **when that entry is filled**; the stored entry
then lives out that policy independently. Editing a rule's `ttl` therefore
re-policies only **future** fills — already-cached entries keep their original
forced lifetime until they expire or are **purged**. To force re-evaluation
immediately, purge the affected URLs/prefix/host through the existing cache
purge path (see [EDGE.md](EDGE.md#the-https-api-rest)). This is inherent to
forcing-at-fill and is the same reason an origin `max-age` change doesn't
retroactively shorten already-cached copies.

## Configuration

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `EDGE_CACHE_ENABLED` | edge | `false` | the response cache (prerequisite) |
| `EDGE_CACHE_OVERRIDE_ENABLED` | edge | `false` | fetch + apply cache overrides (no-op unless the cache is on) |
| `CP_CACHE_ENABLED` | control plane | `false` | watch `…/cache` ConfigMaps and serve `GET /v1/cache` |
| `EDGE_CACHE_DEFAULT_SWR` | edge | `0` (off) | fleet-wide RFC 5861 stale-while-revalidate floor for honor-origin entries |
| `EDGE_CACHE_DEFAULT_SIE` | edge | `0` (off) | fleet-wide RFC 5861 stale-if-error floor for honor-origin entries |

The canonical env-var and annotation entries live in [`SPEC.md`](SPEC.md); the
edge-side detail lives in [`EDGE.md`](EDGE.md). `EDGE_CACHE_DEFAULT_SWR`/`_SIE`
are independent of overrides (they wire `parapet/pkg/cache`'s
`DefaultStaleWhileRevalidate`/`DefaultStaleIfError`, previously unwired at the
edge) and are documented here because per-rule `stale_*` builds on the same
RFC 5861 surface.

## Metrics

Every in-scope decision counts in
**`parapet_cache_override_total{name,action,result}`** on the edge's `:9187`
endpoint, alongside the existing `parapet_cache_total{host,result,edge_id}`
(HIT/MISS/…, host bounded by the knownHost oracle) and `parapet_cache_egress_bytes`:

- `action` = `cache` | `bypass`.
- `result` = `applied` | `shadow` | `error` (a rule whose filter excludes the
  request is **not** counted — only in-scope decisions appear, like the rate
  limiter).
- `name`, collision-free with the rate limiter's identical scheme:

  | name | source |
  |---|---|
  | `global:<id>` | global override `<id>` |
  | `zone:<ns>/<name>:<id>` | zone override `<id>` in zone `<ns>/<name>` |

A `cache` rule increments at **fill** time (it only shapes a miss); a `bypass`
rule increments at **request** time. The `id` is bounded to `[A-Za-z0-9._-]`
(no `/` or `:`) so it can't break the metric name.

## Scope and non-goals

- **Edge-only — the one asymmetry vs. WAF and rate limiting.** Those run in both
  the in-cluster controller and the edge; caching exists **only at the edge**
  (`parapet/pkg/cache`), so there is nothing to override in-cluster. This feature
  therefore touches **`edge/` + `edgecp/` + `cacherule/` only** — no
  `controller*.go`, and **no `plugin.CacheZone`**: the `cache-zone` annotation is
  consumed solely by the CP to build the route→zone map for the edge, never by an
  in-cluster enforcement path. Recorded as an edge divergence in
  [`SPEC.md`](SPEC.md), like the cache itself.
- **It steers the cache; it is not a second cache.** All the heavy lifting —
  single-flight fills, `Vary` keying, the LRU byte cap, disk persistence, purge —
  stays in `parapet/pkg/cache`. Overrides only feed its two decision hooks
  (`Cacheable`, `Override`), so a force can never make the cache do something the
  cache itself refuses (an oversize body, a `Set-Cookie`/`Vary: *` response under
  `balanced`, a non-`GET`/`HEAD` method).
- **No surrogate-key / `Cache-Tag` authoring (yet).** A rule cannot set a
  `Cache-Tag` on the stored entry. This keeps the cross-tenant tag namespace
  (which `Cache-Tag`-scoped purge shares — see
  [EDGE.md](EDGE.md#the-https-api-rest)) out of tenant zones, which is what makes
  cross-namespace zone binding safe. Tag authoring would have to reintroduce a
  same-namespace constraint and is a deliberate non-goal here.
- **No request-Cache-Control honoring.** Like a CDN, the cache ignores a
  client's `no-cache`/`no-store` by design (a shared-cache DoS vector); overrides
  don't change that — they are operator policy, not client-driven.
- **Forward-auth-gated ingresses are forced non-cacheable.** An ingress with the
  `parapet.moonrhythm.io/forward-auth` annotation has every response stamped
  `Cache-Control: private` by the in-cluster controller (`plugin.ForwardAuth`).
  The edge cache is honor-origin and its key ignores `Cookie`, so without this a
  cached `200` for a gated host would be served to anonymous users (the forward-
  auth subrequest gates the request path, but a cache **hit** answers before the
  request ever reaches the controller). `private` makes the shared edge cache
  refuse to store/serve it, and it is honored even under an aggressive override
  (a store-sensitivity refusal a force-cache rule cannot defeat — see
  `parapet/pkg/cache` `policy.go`). This is the deployment-access edge-cache
  bypass (SPEC §9): the override travels **with the response**, so there is no
  separate gated-host list to distribute and no propagation window.
- **No new CEL surface.** Request matching is the `filter` field, the WAF's
  expression surface through the one shared `waf.Predicate`; response narrowing
  is the non-CEL `status` list. There is no `response.*` CEL surface (the
  `Override` hook's response access is exposed only as `status`).

## Where the code will live

| Concern | Mirror of | New |
|---|---|---|
| YAML DTO + parse + compile (filters via `waf.Predicate`) | `ratelimitrule/` | `cacherule/` |
| CP store (global `[]string`, zones, route/host→zone, gen+etag) | `edgecp/ratelimitstore.go` | `edgecp/cachestore.go` |
| CP ConfigMap reloader (cross-ns binding allowed) | `edgecp/ratelimitreload.go` | `edgecp/cachereload.go` |
| CP endpoint `GET /v1/cache` + `EventsSnapshot.Cache` | `edgecp/server.go`, `events.go` | handler + field |
| Edge fetch | `edge/cp.go` `FetchRateLimit` | `FetchCache` |
| Edge runtime (compiled global+zone + matcher; `Cacheable`/`Override` hooks) | `edge/ratelimit.go` | `edge/cache_override.go` |
| Edge refresh loop (jitter + ticker + poke, withhold etag on error) | `edge/ratelimitrefresh.go` | `edge/cacheoverriderefresh.go` |
| Wire hooks into `cache.Options` + read `EDGE_CACHE_DEFAULT_SWR/_SIE` | — | `cmd/edge-proxy/main.go` |
| Metric leaf (keeps edge off `metric`) | `metric/observe/ratelimit.go` | `metric/observe/cacheoverride.go` |
