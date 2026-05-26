# WAF (Web Application Firewall)

A CEL-rule firewall in the request path, with a **global** baseline ruleset
(platform-owned) plus opt-in **zones** (tenant-owned) that an ingress binds by
reference. The engine is [`parapet/pkg/waf`](https://github.com/moonrhythm/parapet/tree/master/pkg/waf)
reused verbatim in the Go controller, and reimplemented on
[cel-rust](https://github.com/cel-rust/cel-rust) in the Rust port (`rust/`) for
CEL-string parity.

> Status: **implemented** in both the Go controller (`controller_waf.go`,
> `plugin/waf.go`, `wafrule/`) and the Rust port (`rust/controller/src/waf.rs`,
> behind the `waf` feature), gated by `WAF_ENABLED` (off by default). The Go
> controller is the production binary; see `CLAUDE.md`.

## Why this shape

The controller is multi-tenant: many customers, many domains, one proxy. The
design goals, in order:

1. **A platform baseline that tenants can't punch through** — block scanners,
   SQLi, known-bad bots globally; a tenant rule must never `allow`-override it.
2. **Tenant self-service without blast radius** — a customer edits *one* place
   and it lands on *all* their domains and *nobody else's*.
3. **Rule edits decoupled from routing** — a rule change must not rebuild the
   router or churn every ingress.
4. **One rule language across Go and Rust** — a rule authored once works in both
   binaries while the migration runs.

The Cloudflare "zone" model satisfies all four: rules live in ConfigMaps, an
ingress references a zone by ID, and the global ruleset is always-on.

## Rule schema (the contract)

Both delivery channels and both languages parse this YAML. It maps 1:1 onto
`waf.Rule`.

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

Top-level `request` map (snake_case, ModSecurity-style):

```
request.method  host  path  query  uri  proto  scheme  remote_ip
        content_length  headers{}  cookies{}  args{}  user_agent  referer  body
```

`headers`/`args`/`cookies` are single-valued maps; header keys are lowercased.
`body` is empty unless body inspection is enabled (off by default).

Custom functions: `ipInCidr(ip,cidr)`, `regexMatch(s,pattern)` (RE2, cached),
`containsAny(s,list)`, `hasPrefixAny(s,list)`, `lower(s)`, `upper(s)`,
`urlDecode(s)`. Query strings are **not** auto-decoded — apply `urlDecode`
yourself so `?q=1+UNION+SELECT` is normalized before a regex sees it.

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

## Rust port design (`rust/`)

Reimplement the engine on cel-rust; the integration is *simpler* than the Go
plugin model because nothing compiled lives in the router.

- **Fast core preserved**: `config.rs` parses `waf_zone: Option<String>` (a pure
  string — no cel). The cel engine lives in a new `waf.rs` behind a `waf` cargo
  feature (pulls `cel` + `regex`); `proxy` enables it.
- **State**: `Shared.global_waf: Arc<Waf>` and
  `Shared.zones: ArcSwap<HashMap<ZoneId, Arc<Waf>>>` (`arc-swap` is already a
  dep — the Rust analog of Go's `atomic.Pointer` swap). A ConfigMap reflector
  (mirroring `cluster.rs`'s `reflect!`) compiles and swaps them, independent of
  `Shared::rebuild` (the router reconcile).
- **Phases**: global in `request_filter` (before `router.lookup`); zone in
  `apply_route_filters` via `ctx.config.waf_zone → shared.zones.load().get(key)`,
  after `allow_remote`, before `redirect_https` — mirroring the Go order. All
  request-time lookups; nothing compiled on the hot path.
- **Metrics**: `parapet_waf_matches` in `proxy/metrics.rs`, same labels.

### Intentional divergences (document like the retry note)

- **Cost limit**: cel-rust has none. Approximate it with a wall-clock deadline
  checked **between** rules (cel-rust eval isn't mid-expression interruptible);
  inputs are small maps. Use the `regex` crate (RE2-style, linear) for
  `regexMatch` so a single rule can't backtrack-blow-up — same guarantee Go's
  `regexp` gives.
- **Body inspection**: ships in a later phase. v1 is header-only
  (`request.body == ""`), matching Go's default (`InspectBody=0`). Phase 2
  buffers up to N bytes in `request_body_filter` for body-dependent rules.
- **Dialect drift**: cel-rust ≠ cel-go on macro semantics and some
  type-coercion edges. Mitigation: a shared `(expression, request, expected)`
  fixture exercised by both the Go and Rust test suites.

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
