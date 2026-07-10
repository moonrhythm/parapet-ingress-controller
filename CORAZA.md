# Coraza firewall (OWASP CRS / SecLang)

`CORAZA_ENABLED=true` turns on a second, **signature-based** web-application
firewall built on the [OWASP Coraza](https://github.com/corazawaf/coraza)
engine. It speaks ModSecurity **SecLang** and ships the embedded **OWASP Core
Rule Set (CRS)**, so a ruleset can `Include @crs-setup.conf.example` +
`Include @owasp_crs/*.conf` to get managed coverage for SQLi, XSS, path
traversal, scanner fingerprints, and the rest of the CRS without writing any
rules.

It is **complementary to**, not a replacement for, the CEL [WAF](WAF.md):

| | CEL WAF (`WAF_ENABLED`) | Coraza (`CORAZA_ENABLED`) |
|---|---|---|
| Rule language | CEL expressions (custom logic) | SecLang / OWASP CRS (signatures) |
| Best at | geo/asn/host/header business rules | generic attack patterns |
| Source | `…/waf` ConfigMaps, `waf-zone` | `…/coraza` ConfigMaps, `coraza-zone` |

Both can run together or independently. Coraza is mounted **after** the CEL WAF
and **before** rate limiting, so a Coraza block never burns rate budget.

## Model — global + zone (same as the WAF)

Coraza follows the WAF's global+zone model exactly, under its own label key
`parapet.moonrhythm.io/coraza` (a separate label and watch — label selectors
can't OR two keys, and SecLang is a different language than CEL).

- **Global** (`…/coraza: global`) — one baseline ruleset, honored **only from
  the controller's own namespace** (`POD_NAMESPACE`), applied to all traffic.
  Mounted in `main.go`'s server chain right after the global CEL WAF.
- **Zone** (`…/coraza: zone`) — a tenant ruleset whose registry key is
  `<namespace>/<name>`. An Ingress binds one with
  `parapet.moonrhythm.io/coraza-zone: <id>` (namespace-local) or `ns/id`
  (cross-reference — **cross-namespace allowed**, the WAF model, since a Coraza
  ruleset is stateless config). Resolved live on the request path, so zone edits
  and new zones take effect without a route rebuild.

### Independent toggle: "global off, one zone on"

`CORAZA_ENABLED` gates the subsystem. Within it, **global is active iff a global
ConfigMap exists, and each zone is active iff its ConfigMap exists**. To run a
single zone with no global baseline: don't create a global ConfigMap, create one
zone ConfigMap, and bind it from an Ingress with `coraza-zone`. The global
instance stays a cheap pass-through.

## Request phases only

Coraza runs the **request** phases: connection, URI, headers, and phase 2.
**Phase 2 always evaluates, even for bodyless requests** — most CRS detections
(SQLi 942xxx, XSS 941xxx) and the CRS anomaly-blocking evaluation rule (949110)
are phase 2, so a GET query-string attack blocks with no body and with body
inspection off. Request-body **bytes** feed phase 2 only when
`CORAZA_REQUEST_BODY_LIMIT` opts in (up to that many bytes). When body
inspection is on, the buffered prefix is fed to Coraza and the body is rebuilt so
the **upstream still receives it in full**; a read error fails open (body
inspection skipped, request proceeds). With the limit at `0` (default) no body is
buffered — phase 2 sees the URI, args, and headers only.

**Response-body inspection is deliberately never enabled.** Engaging CRS phase-4
(response) rules would force buffering the response and break the reverse proxy's
streaming, the edge response cache, and HTTP/2. CRS rules that target the
response simply don't fire.

A block writes the rule's status (default `403`; a `redirect` action with a
target becomes an HTTP redirect). Matches are surfaced from
`tx.MatchedRules()` (not Coraza's error callback, which only fires for rules that
engaged logging), so metrics count every match.

## Hot reload

ConfigMap changes call a debounced reload that recompiles and atomically swaps
the affected instances — it never rebuilds the route mux (rules are decoupled
from routing, exactly like the WAF). A compiled `coraza.WAF` is immutable, so a
new one is built and the pointer swapped; `SetDirectives` is **all-or-nothing**,
so a bad ruleset is rejected and the **last-good** instance stays live. Unchanged
input (fingerprint match) skips the SecLang recompile. The reload pass is
serialized (`corazaReloadMu`) against the debounce's overlapping-fire hazard.

## Edge enforcement (defense-in-depth)

`EDGE_CORAZA_ENABLED` on the edge + `CP_CORAZA_ENABLED` on the control plane run
the same rulesets at the out-of-cluster edge, distributed via `GET /v1/coraza`
(scoped per edge, ETag-revalidated, fail-static — mirrors `/v1/waf`). Zone
bindings are the controller's own **path-aware** route patterns matched on a real
`http.ServeMux` (`edge/zoneroute.go`, shared with the edge WAF). There is **no
legacy host-level binding** (Coraza is new — no old edges) and **no
validated-proxy claim**: unlike the CEL WAF's `WAF_VALIDATED_PROXY` offload, the
edge Coraza is purely an early-drop layer and the **core always re-runs its own
Coraza** (parapet stays authoritative). Per-edge match logging is debug-only; the
edge stays off the `metric` package.

## Configuration

| Env | Default | Effect |
|---|---|---|
| `CORAZA_ENABLED` | `false` | Master switch (controller) |
| `CORAZA_REQUEST_BODY_LIMIT` | `0` | Request-body inspection bytes (`0` = no body bytes fed; phase 2 still evaluates URI/args/headers) |
| `EDGE_CORAZA_ENABLED` | `false` | Run Coraza at the edge |
| `EDGE_CORAZA_REQUEST_BODY_LIMIT` | `0` | Edge request-body inspection bytes |
| `CP_CORAZA_ENABLED` | `false` | Distribute Coraza rulesets from the control plane |

| Annotation | Values | Effect |
|---|---|---|
| `parapet.moonrhythm.io/coraza-zone` | `id` or `ns/id` | Bind the Ingress to a Coraza zone (cross-namespace allowed) |

| Metric | Notes |
|---|---|
| `parapet_coraza_matches{rule_id,severity,scope,zone}` | one per matched rule; `scope` = `global\|zone`; `zone` = the zone registry key `<ns>/<name>` (`""` for global) — rule ids are shared CRS ids, so `zone` is what attributes a match to a tenant |
| `parapet_coraza_eval_duration_seconds{outcome,scope}` | per-request request-phase eval latency; `outcome` = `pass\|block` |

## Example

A global baseline that turns on CRS at paranoia level 1:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coraza-global
  namespace: <controller-namespace>   # POD_NAMESPACE — global is namespace-bounded
  labels:
    parapet.moonrhythm.io/coraza: global
data:
  crs.conf: |
    SecRuleEngine On
    SecRequestBodyAccess On
    Include @crs-setup.conf.example
    Include @owasp_crs/*.conf
```

These are the **only include forms that resolve**: coraza's `Include` is a plain
`fs.ReadFile` against the embedded CRS filesystem, globbing only when the path
contains `*`, and that filesystem holds `@crs-setup.conf.example` (a file) and
`@owasp_crs/` (a directory). The bare `Include @crs-setup` / `Include
@owasp_crs` forms fail to compile — loudly, which is what you want, since a
compile error keeps the last-good ruleset (pass-through for a brand-new zone)
and surfaces only in the controller log. `corazawaf/crs_test.go` pins both the
resolving and the non-resolving forms.

A per-tenant zone with a custom signature, bound from an Ingress:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: acme
  namespace: cust1
  labels:
    parapet.moonrhythm.io/coraza: zone
data:
  rules.conf: |
    SecRuleEngine On
    SecRule REQUEST_URI "@contains /wp-admin" "id:100001,phase:1,deny,status:403,msg:'blocked wp-admin'"
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: acme-web
  namespace: cust1
  annotations:
    parapet.moonrhythm.io/coraza-zone: acme
spec: { } # ...
```

To enforce CRS bodily attacks (POST SQLi/XSS), set
`CORAZA_REQUEST_BODY_LIMIT` (e.g. `131072`) and `SecRequestBodyAccess On` in the
ruleset.

## Code

- `corazawaf/` — the hot-swappable engine + request-phase middleware (pure, no
  metric/k8s imports; edge-importable)
- `controller_coraza.go`, `plugin/corazazone.go`, `metric/coraza.go`,
  `metric/observe/coraza.go` — controller wiring
- `edge/coraza.go`, `edge/corazarefresh.go` — edge enforcement
- `edgecp/corazastore.go`, `edgecp/corazareload.go`, `edgecp/server.go`
  (`/v1/coraza`) — control-plane distribution
