# Rate limiting (ConfigMap-driven, global + zones)

Request-rate limiting in the request path, with a **global** baseline set
(platform-owned) plus opt-in **zones** (tenant-owned) that an ingress binds by
reference — the same zone model as the [WAF](WAF.md), under its own marker
label. Strategies build on `parapet/pkg/ratelimit`; the parser and
runtime live in [`ratelimitrule/`](ratelimitrule/).

> Status: **implemented** in the Go controller (`controller_ratelimit.go`,
> `plugin/ratelimitzone.go`, `ratelimitrule/`), gated by `RATELIMIT_ENABLED`
> (off by default — disabled means no ConfigMap watch, no mount, no per-request
> work). **Go-only**: the frozen Rust port has no counterpart, and the edge
> proxy does not run these limits (see [Scope](#scope-and-non-goals)).

This complements, not replaces, the existing limiters:

| Layer | Configured by | What it bounds |
|---|---|---|
| Host / host+country concurrency | `HOST_*CONCURRENT_*` env | in-flight requests while upstreams are unresponsive |
| **Global rate limits** | ConfigMap `…/ratelimit: global` | request rate across **all** traffic |
| **Zone rate limits** | ConfigMap `…/ratelimit: zone` + `ratelimit-zone` annotation | request rate across a tenant's ingresses |
| Annotation rate limits | `ratelimit-s/-m/-h` on one ingress | request rate per single ingress |

## Limit schema (the contract)

Each ConfigMap `data` value is one `limits:` document; multiple keys (and
multiple global ConfigMaps) are concatenated in deterministic (sorted) order.

```yaml
limits:
  - id: per-ip              # required; unique in the set; [A-Za-z0-9._-], <= 63 chars
    key: ip                 # one characteristic, or a list composed into one bucket key:
                            #   key: [ip, header:x-api-key]
    rate: 100               # required; admitted requests per window per bucket
    window: 1m              # required; Go duration, 1s..1h
    algorithm: fixed        # fixed (default) | sliding
    mode: enforce           # enforce (default) | shadow
    status: 429             # 429 (default) | 503
    message: Too Many Requests
    exclude:                # optional: client CIDRs that skip this limit
      - 10.0.0.0/8
```

- **`key`** lists the characteristics whose per-request values compose into the
  bucket key (default `ip`; a YAML scalar is one characteristic, a list is a
  composite — e.g. `[ip, header:x-api-key]` = "per IP per API key"):

  | Characteristic | Bucket value | Cardinality |
  |---|---|---|
  | `ip` | client IP from parapet's trusted `X-Real-IP` (honors `TRUST_PROXY`); IPv4 per address, **IPv6 per /64** so one eyeball network can't mint unbounded keys; an unparsable value buckets by its raw string | bounded by real clients |
  | `host` | request Host (lowercased, port-stripped); hosts the router doesn't serve collapse into one shared bucket — applies to the global set and to zones bound to host-less catch-all rules | bounded by served hosts + 1 |
  | `asn` | the client's autonomous system number (the WAF's `request.asn` GeoIP resolver); requires the ASN DB (`WAF_ASN_DB`) — **rejected at load when it isn't available**, since every client would silently share one bucket | bounded (~100k ASNs) |
  | `country` | the client's ISO country (the WAF's `request.country` resolver, `XX` when unplaceable); requires the GeoIP DB (`WAF_GEOIP_DB`), rejected at load without it | bounded (~250) |
  | `header:<name>` | the named request header's value (first value, case-insensitive name); missing header ⇒ one shared `""` bucket | **client-controlled — see warning** |
  | `cookie:<name>` | the named cookie's value (case-sensitive name, like `http.Request.Cookie`); missing ⇒ shared `""` bucket | **client-controlled — see warning** |

  `ip-host` is kept as an alias for `[ip, host]`. Duplicate characteristics in
  one key are rejected. Header/cookie values are truncated to 128 bytes for the
  bucket key (over-long values share their prefix's bucket — conservative).

  ⚠️ **`header`/`cookie` cardinality warning**: unlike every other
  characteristic, the bucket value is freely mintable by clients — an attacker
  can send a new value per request and hold one map entry each until the
  window retires it (~1–2 windows). Use them for values your edge can vouch
  for (API keys behind auth, session cookies), keep windows short, and ship
  `mode: shadow` first. The `asn`/`country` keys exist precisely as the
  bounded alternatives for "group clients coarser than per-IP".
- **`window`** is capped at **1h** deliberately: a limiter holds every distinct
  bucket key seen within ~1–2 windows in memory, so the cap bounds the worst
  case to what the pre-existing per-hour annotation limiter already allowed.
  Fixed windows are **epoch-aligned** (`1h` resets on the hour, UTC).
- **`algorithm`**:
  - `fixed` — plain per-window counter (parapet's `FixedWindowStrategy`).
    Cheapest; admits up to 2× `rate` across a window boundary.
  - `sliding` — sliding-window counter: the previous window's count fades out
    linearly, smoothing the boundary burst. Same admit/`After` math as
    parapet's `SlidingWindowStrategy`, kept as a local reimplementation in
    `ratelimitrule`: storage is two whole-window generations retired wholesale
    at each boundary — no background goroutine, no per-entry sweeps under the
    lock — and a backward clock step never forgets counts (parapet's per-item
    roll does, over-admitting on recovery). The original motivation (parapet's
    janitor leaked per hot reload) was fixed upstream in v0.18.1; the fork
    stays for the stricter semantics above. It is an approximation (assumes
    uniform arrival in the previous window; error typically under ~1% of
    `rate`).
- **`mode: shadow`** takes and **counts** every decision
  (`parapet_ratelimit_total{result="limited"}`) but never rejects — ship
  shadow, watch the metric, then flip to `enforce` (the same rollout story as
  WAF `action: log`).
- **`status`** is restricted to 429/503 so the status-derived
  `parapet_rejected_requests` reason stays truthful. Rejections carry
  `Retry-After` (rounded **up** to whole seconds) when the strategy can bound
  the wait, plus `message` as the body.
- **`exclude`** skips the limit for matching client IPs — size it for load
  balancer health checkers, which probe many hosts from a small shared CIDR
  and would otherwise aggregate into one `ip` bucket.

`/.well-known/acme-challenge` is **never** rate limited (hard-coded, like
`redirect-https` and `allow-remote`): platform-injected middleware must not
break certificate issuance, and ACME validation probes come from unpublished
IPs.

Limits evaluate in declaration order; the first rejection wins. A request
rejected by a later limit has already consumed tokens from earlier ones (same
semantics as chaining parapet limiters), so put the most-restrictive limit
first to minimize wasted budget.

## Delivery: ConfigMaps, one marker label

The label key **`parapet.moonrhythm.io/ratelimit`** marks a ConfigMap as
rate-limit input; the value selects the role — exactly the WAF's model, under a
separate key (a Kubernetes label selector can't OR two keys, so it is a 6th
watch):

| Label | Meaning | Where it's honored |
|---|---|---|
| `parapet.moonrhythm.io/ratelimit: global` | contributes to the global set | only in the controller's own namespace (`POD_NAMESPACE`) |
| `parapet.moonrhythm.io/ratelimit: zone` | one zone; zone ID = ConfigMap **name** | any watched namespace |

Restricting `global` to `POD_NAMESPACE` is the security boundary: only the
platform team can throttle all traffic. Tenants get RBAC `edit` on their own
zone ConfigMaps. A ConfigMap carrying **both** the waf and ratelimit labels is
refused by the rate-limit reload (one ConfigMap per feature).

### Zone binding

```yaml
metadata:
  annotations:
    parapet.moonrhythm.io/ratelimit-zone: acme
```

Every domain/path on that ingress shares the `acme` zone's buckets — one edit
lands on all of a tenant's ingresses, and traffic across them draws from the
same budget.

**Resolution is namespace-local only** — `ns/id` is accepted only when `ns` is
the ingress's own namespace. This is a deliberate divergence from `waf-zone`
(which honors cross-namespace references): a WAF zone is stateless config,
harmless to its owner wherever it's applied, but a rate-limit zone carries
**shared counter state** — honoring a cross-namespace bind would let any tenant
attach another tenant's zone and burn its per-key budgets (a cross-tenant
denial of service). A cross-namespace reference is logged and ignored.

A key that resolves to no zone — deleted, not yet created, or a **new** zone
whose first config was rejected — passes traffic through unlimited (the global
limits still apply). Like the WAF's zone miss, this fails open by design;
`parapet_ratelimit_total` going silent for a zone is the signal to look.

## Reload semantics (decoupled from the router, counters preserved)

Rate-limit ConfigMap changes are debounced and **never rebuild the mux** — a
limit edit is a `SetLimits` + registry swap, mirroring the WAF reload exactly,
with one addition unique to rate limiting: **live counters survive reloads**
wherever possible.

- An **unchanged** ConfigMap (content fingerprint match) is not reapplied at
  all — instances and counters untouched.
- A **changed** zone reuses its `Limiter` instance, and `SetLimits` carries
  each limit's strategy over when its shaping config (`key`, `algorithm`,
  `rate`, `window`) is unchanged — editing a `message`, or a sibling limit,
  resets nothing. A limit whose shaping config changed starts fresh (one
  window of extra budget, converging within two windows for `sliding`).
- A **bad** batch (YAML error, invalid limit) is rejected all-or-nothing: that
  set keeps its last-good limits, everything else is untouched, and the input
  is retried (not skipped) on the next reload.

## Per-request order

```
host/country concurrency limits → access log/metrics → global WAF
→ GLOBAL RATE LIMITS → router → allow-remote → zone WAF → redirect-https
→ ZONE RATE LIMITS → annotation rate limits → body limit → auth → upstream
```

Global limits run **after** the global WAF, deliberately: WAF-blocked traffic
never burns rate budget, and a rate-limited client still can't dodge WAF
matching/metrics. (The reverse would shed limiter rejections before spending
CEL evaluation on them — defensible, but not chosen.) Consequence: limiter
rejections are access-logged and counted like WAF blocks, and a tenant under
attack burns global budget for requests that may later be rejected by
allow-remote, the zone WAF, or zone/annotation limits.

## Metrics

Every decision counts in `parapet_ratelimit_total{name,result}`
(`result = allowed|limited`), the same metric the host/annotation limiters use,
with two new (collision-free) name forms:

| name | source |
|---|---|
| `global:<id>` | global limit `<id>` |
| `zone:<ns>/<name>:<id>` | zone limit `<id>` in zone `<ns>/<name>` |

(The `zone:` prefix exists because a bare `<ns>/<name>:<id>` could collide with
the annotation limiters' `<ns>/<ingress>:<s|m|h>` names.) Enforced rejections
also surface in the standard request metrics (status 429/503) — do **not**
expect them in `parapet_host_ratelimit_requests`, which belongs to the host
concurrency limiter. Note on the status-derived rejection reason: a 429
rejection counts under the rate-limit reason, while `status: 503` rejections
are deliberately uncounted there (503 is not a tracked edge-rejection status)
— with 503 you observe rejections via `parapet_ratelimit_total` and the
status-labeled request metrics only.

## Memory bounds

Per-limit memory is O(distinct bucket keys in the last ~1–2 windows): `fixed`
clears its map each boundary, `sliding` retires whole generations. The 1h
window cap, IPv6 /64 bucketing, and unknown-Host collapsing bound the envelope
to what the pre-existing annotation limiters already allowed — but an ip-keyed
limit on heavy public traffic still holds one entry per active client; size
`window` accordingly (shorter windows = smaller maps). An idle limiter retains
its last generations until the next request or until its zone is deleted.

## Scope and non-goals

- **Per-pod limits.** Like every limiter in this codebase, counters are local
  to each controller replica — N replicas admit up to N× `rate`. A
  Redis-backed distributed strategy (parapet has `RedisFixedWindowStrategy`)
  is a possible follow-up.
- **No edge distribution.** The edge control plane serves certs + WAF rules
  only; the edge proxy enforces nothing from this feature, and edge **cache
  hits** are served without reaching the controller — uncounted and unlimited.
- **No request matching.** Limits apply to every request on the bound scope;
  path/header conditions are the WAF's job (CEL), not a second expression
  language here. (Keying — who shares a bucket — is the `key` characteristics
  above; a likely v2 addition is `none`, one aggregate bucket per limit.)
- **No concurrency strategies.** In-flight caps stay with the env-configured
  host limiters (`Put`/release semantics don't fit the zone model's
  hot-swapped, take-only chain).
