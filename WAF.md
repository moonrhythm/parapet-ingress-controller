# WAF (Web Application Firewall)

A CEL-rule firewall in the request path, with a **global** baseline ruleset
(platform-owned) plus opt-in **zones** (tenant-owned) that an ingress binds by
reference. The engine is [`parapet/pkg/waf`](https://github.com/moonrhythm/parapet/tree/master/pkg/waf)
reused verbatim in the controller.

> Status: **implemented** in the controller (`controller_waf.go`,
> `plugin/waf.go`, `wafrule/`), gated by `WAF_ENABLED` (off by default).
> See [`CLAUDE.md`](CLAUDE.md) and [`SPEC.md`](SPEC.md).

## Why this shape

The controller is multi-tenant: many customers, many domains, one proxy. The
design goals, in order:

1. **A platform baseline that tenants can't punch through** — block scanners,
   SQLi, known-bad bots globally; a tenant rule must never `allow`-override it.
2. **Tenant self-service without blast radius** — a customer edits *one* place
   and it lands on *all* their domains and *nobody else's*.
3. **Rule edits decoupled from routing** — a rule change must not rebuild the
   router or churn every ingress.
4. **A stable rule language** — rules are operator-authored strings that live
   outside this repo, so the supported authoring surface is pinned by the
   [conformance corpus](conformance/waf-cel-corpus.md) and must survive engine
   upgrades unchanged.

The Cloudflare "zone" model satisfies all four: rules live in ConfigMaps, an
ingress references a zone by ID, and the global ruleset is always-on.

## Rule schema (the contract)

Both delivery channels parse this YAML. It maps 1:1 onto `waf.Rule`.

```yaml
rules:
  - id: block-sqli            # required, unique within a ruleset
    description: classic SQLi in query string
    expression: regexMatch(lower(urlDecode(request.query)), "(union\\s+select|or\\s+1=1)")
    action: block             # log | allow | block   (default: log)
    status: 403               # block only; default 403
    message: Forbidden        # block only; default "Forbidden"
    priority: 100             # ascending — lower runs first
```

- `expression` is a CEL expression returning `bool`. Variables and functions are
  fixed by `pkg/waf` (see [CEL surface](#cel-surface)).
- `action`:
  - `block` — terminate with `status`/`message`.
  - `allow` — short-circuit **this ruleset only** and proceed down the normal
    chain (allowlists, e.g. trusted health checkers). It does **not** bypass
    other rulesets (a global `allow` still enters zone evaluation).
  - `log` — record the match (metric + log) and keep evaluating. The default, so
    a rule with no `action` is a safe shadow rule.
- Rules run in ascending `priority`; equal priorities keep declaration order.
- `SetRules` compiles the whole batch **all-or-nothing**: one bad rule rejects
  the batch and the previous good ruleset stays live. A bad ConfigMap can't
  brick the WAF.

## CEL surface

A rule `expression` is a [CEL](https://github.com/google/cel-spec) expression
that **must evaluate to `bool`** (a non-bool expression is rejected at compile
time). There is exactly **one variable** — `request` — no protobuf message
types, and no other bindings. The engine is cel-go's standard library (via
`parapet/pkg/waf`). **The surface below is the supported rule-authoring
contract** — author against it; the
[conformance corpus](conformance/waf-cel-corpus.md) pins it so a cel-go /
`parapet/pkg/waf` upgrade can't silently change what a rule matches.

Not every function in the [CEL language definition](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
is available — see the unsupported list below, and CEL **extension libraries
are off** (no string-ext `split`/`join`/`format`, no math/encoder/sets/lists
ext). Use the custom functions for those needs.

### The `request` map (snake_case, ModSecurity-style)

```
request.method  host  path  query  uri  proto  scheme  remote_ip  country  asn
        content_length  headers{}  cookies{}  args{}  user_agent  referer  body
```

`headers`/`args`/`cookies` are single-valued maps; header keys are lowercased.
`content_length` and `asn` are ints; everything else is a string.
`body` is empty unless body inspection is enabled (off by default).
`country` is the GeoIP country code — see [GeoIP](#geoip-requestcountry).
`asn` is the GeoIP autonomous system number (an int) — see [ASN](#asn-requestasn).

### Custom functions (the WAF primitives)

Added by the WAF itself — these cover almost every rule you'll write:

| Function | Result | Notes |
|---|---|---|
| `ipInCidr(ip, cidr)` | bool | string args; an unparseable `ip` → `false` (a bad `cidr` errors) |
| `regexMatch(s, pattern)` | bool | RE2 (linear, no catastrophic backtracking), compiled-pattern cache |
| `containsAny(s, list)` | bool | `s` contains any non-empty substring in `list` |
| `hasPrefixAny(s, list)` | bool | `s` starts with any non-empty prefix in `list` |
| `lower(s)` / `upper(s)` | string | case fold |
| `urlDecode(s)` | string | = Go `url.QueryUnescape`: `+`→space, `%XX`→byte, malformed→`""` |

Query strings are **not** auto-decoded — apply `urlDecode` yourself so
`?q=1+UNION+SELECT` is normalized before a regex sees it.

### Standard CEL (the supported surface)

**Operators** — logical `!` `&&` `||` and the ternary `cond ? a : b`; comparison
`==` `!=` `<` `<=` `>` `>=`; arithmetic `+` `-` `*` `/` `%` and unary `-`;
membership `x in list` / `x in map`; indexing `list[i]` / `map["key"]`.

**Macros** — `has(request.headers.foo)`, plus the comprehensions
`list.all(x, p)`, `list.exists(x, p)`, `list.exists_one(x, p)`,
`list.map(x, e)`, `list.filter(x, p)`. **Macros can be switched off** with
`WAF_DISABLE_MACROS=true`, so don't rely on a macro in a rule that
must keep working under a hardened global config.

**Functions** —

| Function | Result | Notes |
|---|---|---|
| `s.contains(sub)` | bool | substring test |
| `s.startsWith(p)` / `s.endsWith(p)` | bool | |
| `s.matches(re)` | bool | RE2; the stdlib twin of `regexMatch(s, re)` |
| `size(x)` / `x.size()` | int | string (codepoints), bytes, list, or map |
| `int` `uint` `double` `string` `bytes` | conv | numeric/string conversions |
| `timestamp(s)` / `duration(s)` | ts / dur | RFC3339 / Go-duration string |
| `getFullYear` `getMonth` `getDate` `getDayOfMonth` `getDayOfWeek` `getDayOfYear` `getHours` `getMinutes` `getSeconds` `getMilliseconds` | int | timestamp/duration accessors, **UTC** (`getMonth` is 0-based) |

The timestamp/duration helpers are listed for completeness; the `request` map has
no time field, so rules rarely need them.

### Not pinned / not available

- **Available but unpinned** (cel-go has them, the corpus doesn't cover them —
  avoid in rules that must survive engine upgrades): the `bool()`,
  `type()`, and `dyn()` conversions, and the timezone-string overload of the
  timestamp accessors (e.g. `ts.getHours("America/New_York")`).
- **Unavailable** (not in cel-go's standard library): `max()`,
  `min()`, and the `optional.*` helpers (`optional.of`, `hasValue`, `orValue`, …).
- **Off** — CEL extension libraries (string `split`/`join`/`format`/
  `replace`/`substring`/`indexOf`/`charAt`/`trim`/`lowerAscii`/`upperAscii`,
  and math/encoder/sets/lists ext), protobuf message construction / struct
  literals, and any variable other than `request`. Reach for the custom
  functions instead (e.g. `lower(s)` for `lowerAscii(s)`).

## GeoIP (`request.country`)

`WAF_GEOIP_DB` defaults to the **IPLocate ip-to-country** `.mmdb` baked into the
image (`/geoip/ip-to-country.mmdb`); point it at a custom path, or set `""` to
disable. It resolves the client IP to an ISO 3166-1 alpha-2 country, exposed to
rules as `request.country`:

```yaml
rules:
  - id: allow-th-only
    expression: request.country != "TH"
    action: block
  - id: block-geos
    expression: containsAny(request.country, ["CN", "RU", "KP"])
    action: block
```

`request.country` is **always present** in the request map, so a rule referencing
it never errors on a missing key (no fail-open):

- `""` — GeoIP disabled (`WAF_GEOIP_DB` set to `""`, or no DB at the path).
- `"XX"` — DB loaded but the IP couldn't be placed (private range, not in DB).
- an ISO code (e.g. `"TH"`) otherwise.

So `request.country != "TH"` blocks unknowns too — the safe default for an
allow-list. The client IP is the same one used for `request.remote_ip`
(X-Real-IP → X-Forwarded-For → peer), so it honors `TRUST_PROXY`.

Whenever the DB is loaded, the resolved country is also forwarded **upstream** as
the `X-Forwarded-Country` header — overwriting any client-supplied value so a
backend can trust it (`"XX"` for an unplaceable IP). With GeoIP off the header is
left untouched.

The DB is the [IPLocate ip-to-country](https://github.com/iplocate/ip-address-databases)
MMDB. Its records are **flat** — `country_code` at the top level — unlike MaxMind
GeoIP2, which nests it under `country.iso_code`; the resolver reads the
flat schema. Any standard `.mmdb` reader works on the file; only the record layout
differs, so a MaxMind GeoLite2-Country `.mmdb` will **not** resolve here.

**Implementation.** The controller exposes it through the `parapet/pkg/waf`
`Country` resolver hook, wired to a `maxminddb-golang` lookup. It decodes a flat
`{ country_code }` record, loads the DB once at startup,
and treats a load failure as non-fatal (country stays `""`).

**Providing the DB.** It exceeds a ConfigMap's 1 MB limit, so either:

- **Bake at build time** (the controller and edge Dockerfiles, the default). The
  IPLocate ip-to-country
  `.mmdb` is downloaded straight from GitHub — no account or license key — into the
  image at `/geoip/ip-to-country.mmdb`:

  ```bash
  docker build -t img .     # bakes the DB by default
  # then run with: WAF_GEOIP_DB=/geoip/ip-to-country.mmdb
  ```

  Override `--build-arg GEOIP_DB_URL=<url>` to bake a different `.mmdb`, or pass an
  empty value to bake none. Simple to deploy, but the DB is as stale as the image
  (rebuild to refresh).

- **Mount at runtime** — an updater sidecar / initContainer or a volume, with
  `WAF_GEOIP_DB` pointing at the mount. Refreshes without a rebuild.

IPLocate's free databases are **CC BY-SA 4.0**: keep the attribution to
[iplocate.io](https://www.iplocate.io) where the data is used. No EULA or license
key is required.

## ASN (`request.asn`)

`WAF_ASN_DB` defaults to the **IPLocate ip-to-asn** `.mmdb` baked into the image
(`/geoip/ip-to-asn.mmdb`); point it at a custom path, or set `""` to disable. It
resolves the client IP to its autonomous system number, exposed to rules as
`request.asn`:

```yaml
rules:
  - id: block-asn
    expression: request.asn == 13335
    action: block
```

`request.asn` is an **integer, always present**:

- `0` — ASN lookup disabled (`WAF_ASN_DB` set to `""`, or no DB at the path) **or**
  the IP couldn't be placed. `0` is reserved by RFC 7607, so `request.asn == 0` is a
  usable "unknown AS" predicate and a rule referencing the field never fails open.
- the AS number otherwise.

It is exposed as a CEL **int** (not uint), so rules use plain integer literals
(`request.asn == 13335`, not `13335u`). The client IP is resolved the same way as
`request.country`, so it honors `TRUST_PROXY`. IPLocate's ip-to-asn records are
flat, with `asn` stored as a *string* that the resolver parses to an integer.

Whenever the DB is loaded, the resolved ASN is also forwarded **upstream** as the
`X-Forwarded-ASN` header (overwriting any client-supplied value; `0` for an
unplaceable IP). With ASN lookup off the header is left untouched.

**Implementation.** The controller exposes it through the `parapet/pkg/waf` `ASN`
resolver hook (added in parapet v0.15.2). The DB is loaded
once at startup; a load failure is non-fatal (`request.asn` stays 0).

**Providing the DB** mirrors GeoIP, with its own `WAF_ASN_DB` env var. The
controller and edge
Dockerfiles bake the ip-to-asn `.mmdb` to `/geoip/ip-to-asn.mmdb` by default
(`ASN_DB_URL`). It is much larger than the country DB (~74 MB), so pass
`--build-arg ASN_DB_URL=` (empty) to skip baking it if you don't need
`request.asn`, or override the URL / mount it at runtime instead.

## Delivery: ConfigMaps, one marker label

A single label key **`parapet.moonrhythm.io/waf`** marks a ConfigMap as WAF
input; its value selects the role:

| Label | Meaning | Where it's honored |
|---|---|---|
| `parapet.moonrhythm.io/waf: global` | contributes to the global ruleset | only in the controller's own namespace (`POD_NAMESPACE`) |
| `parapet.moonrhythm.io/waf: zone` | one zone; zone ID = ConfigMap **name** | any watched namespace |

One label key means one watch with one existence selector
(`LabelSelector: "parapet.moonrhythm.io/waf"`) catches both; the controller
splits global vs zone by value. Each ConfigMap's `data` values are each a
`rules:` document; multiple keys (and multiple global ConfigMaps) are
concatenated.

Restricting `global` to `POD_NAMESPACE` is the security boundary: only whoever
controls the controller's namespace (the platform team) can define baseline
rules. Tenants get RBAC `edit` on their own zone ConfigMaps and nothing else.

### Zone binding

An ingress binds a zone with one annotation:

```yaml
metadata:
  annotations:
    parapet.moonrhythm.io/waf-zone: acme
```

Every domain/path on that ingress is now governed by the `acme` zone. **Resolution is namespace-local with explicit cross-ref:**

```
val = annotations["parapet.moonrhythm.io/waf-zone"]
key = val.contains("/") ? val                          # "team-x/acme"  → that exact (ns, name)
                        : ingress.namespace + "/" + val # "acme"         → same-namespace zone
zone = registry[key]   # miss → no zone rules (global still applies); not an error
```

A bare ID resolves to a zone ConfigMap of that name in the ingress's own
namespace; `team-x/acme` references a zone in another namespace (e.g. a shared
platform zone). Cross-ref only resolves if the controller watches that namespace
(`WATCH_NAMESPACE=""`, the default, watches all). Cross-namespace binding lets a
tenant *apply* another's ruleset to their own traffic (harmless to the owner);
*editing* is still RBAC-gated per ConfigMap.

## Evaluation order

Per request: **global WAF (always) → zone WAF (if bound and resolves).** Global
runs first and is authoritative — a platform `block` terminates before the zone
is consulted, so a tenant can't override it. `allow` is per-ruleset (see above).

## The key property: WAF reload is decoupled from the router

Binding is by **ID resolved at request time**, so rule lifecycle and routing
lifecycle are independent:

- Ingress / Service / Secret / Endpoint change → rebuild the router (as today).
- Global or zone ConfigMap change → recompile *that one ruleset* and atomically
  swap the registry. **No mux rebuild, no plugin re-run.** A new zone, or a
  tenant editing rules, is just a `SetRules` on a stable instance / a map swap,
  picked up on the next request. A broken zone ConfigMap fails `SetRules`
  all-or-nothing: that zone keeps its last-good rules; global and every other
  zone are untouched.

## Go controller design

The engine is free (`pkg/waf`); the work is plumbing.

- **Shared parser** (`wafrule/`): YAML `rules:` doc → `[]waf.Rule`, `action`
  string → `waf.Action`. Used by both the global and zone paths.
- **k8s** (`k8s/`): `GetConfigMaps` / `WatchConfigMaps` with a label selector
  (cluster client applies it server-side; fs client returns all and the
  controller filters).
- **Controller** holds `globalWAF *waf.WAF` and
  `zones atomic.Pointer[map[string]*waf.WAF]` (key `<namespace>/<name>`). A 5th
  watch (ConfigMaps), debounced like the others, feeds both via
  `reloadWAF` — and does **not** touch `ctrl.mux`. Zone instances are reused
  across reloads so a bad edit keeps the zone's last-good ruleset.
  `newWAF(scope)` applies the env config and wires `OnMatch` → metrics + log.
- **`plugin.WAFZone(lookup)`**: reads `waf-zone`, resolves the key, injects a
  middleware that does a live `lookup(key)` per request and evaluates the zone's
  `*waf.WAF`. Registered after `AllowRemote`, before `RedirectHTTPS`.
- **Global mount**: `m.Use(ctrl.GlobalWAF())` in `main.go`, immediately before
  `m.Use(ctrl)` — so blocks are access-logged and counted, and `request.host`
  is already normalized.
- **Metrics/log**: `metric.WAFMatch(ruleID, action, scope)` →
  `parapet_waf_matches{rule_id,action,scope}` (bounded: rule IDs are
  operator-defined, action∈3, scope∈{global,zone}). Eval errors and match lines
  go to slog.

### Configuration (env)

| Env | Default | Description |
|---|---|---|
| `WAF_ENABLED` | `false` | Master switch — when off, no watch, no mount, zero per-request cost |
| `WAF_FAIL_MODE` | `open` | `open` (rule eval error → allow + log) or `closed` (→ 500) |
| `WAF_EVAL_TIMEOUT` | `5ms` | Per-request deadline for the whole ruleset |
| `WAF_COST_LIMIT` | `1000000` | CEL cost cap per rule |
| `WAF_INSPECT_BODY` | `0` | Inspect up to N body bytes (0 = `request.body` is empty) |
| `WAF_DISABLE_MACROS` | `false` | Refuse rules using `all`/`exists`/`map`/`filter` |

### RBAC

The controller needs `get/list/watch configmaps` (added to
`deploy/role-cluster.yaml` and `deploy/role-namespaced.yaml`). Tenants get
`edit` on their own zone ConfigMaps via their own RBAC.

## Rollout

Ship rules `action: log` first (shadow mode), watch
`parapet_waf_matches{action="log"}` for false positives, then flip to
`block`. Keep `WAF_FAIL_MODE=open` in production: during a config bug,
fail-open (one rule briefly inactive) beats fail-closed (every request 500s).

## Examples

Global baseline (in the controller's namespace):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-global
  namespace: parapet-ingress-controller
  labels:
    parapet.moonrhythm.io/waf: global
data:
  rules.yaml: |
    rules:
      - id: block-scanners
        expression: containsAny(lower(request.user_agent), ["sqlmap", "nikto", "acunetix"])
        action: block
      - id: block-sqli
        expression: regexMatch(lower(urlDecode(request.query)), "(union\\s+select|or\\s+1=1)")
        action: block
```

A tenant zone (in the tenant's namespace), bound by their ingresses:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: acme
  namespace: acme-prod
  labels:
    parapet.moonrhythm.io/waf: zone
data:
  rules.yaml: |
    rules:
      - id: allow-office
        expression: ipInCidr(request.remote_ip, "203.0.113.0/24")
        action: allow
        priority: 0
      - id: block-admin-external
        expression: hasPrefixAny(request.path, ["/admin", "/internal"])
        action: block
        priority: 100
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: acme-prod
  annotations:
    parapet.moonrhythm.io/waf-zone: acme   # → acme-prod/acme
spec:
  ingressClassName: parapet
  rules: [ ... ]
```
