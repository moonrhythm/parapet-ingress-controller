# parapet-ingress-controller

[![Go Test](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/go-test.yaml/badge.svg?branch=master)](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/go-test.yaml)
[![Rust Test](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/rust-test.yaml/badge.svg?branch=master)](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/rust-test.yaml)
[![codecov](https://codecov.io/gh/moonrhythm/parapet-ingress-controller/branch/master/graph/badge.svg)](https://codecov.io/gh/moonrhythm/parapet-ingress-controller)
[![Go Report Card](https://goreportcard.com/badge/github.com/moonrhythm/parapet-ingress-controller)](https://goreportcard.com/report/github.com/moonrhythm/parapet-ingress-controller)

A Kubernetes ingress controller. The page you're reading is the **usage**
contract — Ingresses, annotations, WAF, and metrics work the same regardless of
which build you run.

## Implementations

The controller ships as **two co-maintained implementations of one behavior
contract** ([`SPEC.md`](SPEC.md)):

| | [`go/`](go/) | [`rust/`](rust/) |
|---|---|---|
| Framework | [parapet](https://github.com/moonrhythm/parapet) | [Pingora](https://github.com/cloudflare/pingora) |
| Image | `…/parapet-ingress-controller:<tag>` | `…/parapet-ingress-controller:rust-<sha>` |
| Notes | the established build; Cloud Profiler/Trace | smaller image, no Go runtime; see [`rust/README.md`](rust/README.md) |

Both honor the same Ingresses, annotations, env vars, and metric names. Where
they intentionally differ, [`SPEC.md`](SPEC.md) marks it **Go-only** / **Rust-only**.
Pick per deployment; they're interchangeable behind the same contract.

## Deploy

See deploy config at [deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/master/deploy)
directory.

## Usage

Create ingress with `ingressClassName: parapet`

### Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    parapet.moonrhythm.io/hsts: preload
    parapet.moonrhythm.io/redirect: |
      example.com: https://www.example.com
    parapet.moonrhythm.io/redirect-https: "true"
  name: ingress
spec:
  ingressClassName: parapet
  rules:
  - host: www.example.com
    http:
      paths:
      - backend:
          service:
            name: example
            port:
              name: http
      - path: /assets/
        backend:
          service:
            name: gcs
            port:
              name: https
  - host: api.example.com
    http:
      paths:
      - backend:
          service:
            name: api-example
            port:
              name: http
  tls:
  - secretName: tls-www
  - secretName: tls-api
```

## Plugins

Plugins use annotation in ingress to config. The full annotation reference,
env-var table, and per-request order are in [`SPEC.md`](SPEC.md) (the contract
both implementations track); the Go plugins live in [`go/plugin`](go/plugin).

## Configuration

The controller is configured through environment variables (see the
[deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/master/deploy)
manifests for the full set). Notable options:

- `INGRESS_CLASS` (default `parapet`) — the `ingressClassName` to handle.
- `WATCH_NAMESPACE` (default all) — restrict the controller to one namespace.
- `TRUST_PROXY` — `true`, `false`, or comma-separated CIDRs (supports the `cloudflare` shorthand).
- `LOAD_ALL_CERTS` (default `false`) — load every TLS-typed secret in the watch
  namespace, not just those referenced by an Ingress's `spec.tls`. Lets a
  wildcard certificate serve SNI without wiring its secret into each ingress.

## Web Application Firewall (WAF)

An opt-in CEL-rule firewall with a platform-wide **global** ruleset plus
per-tenant **zones** that an ingress binds by reference. Rules live in ConfigMaps
and hot-reload without restarting the controller or rebuilding routes. Full
design and the complete CEL reference: [WAF.md](WAF.md).

### Enable it

Set `WAF_ENABLED=true` on the controller (off by default; when off the WAF does no
work). The controller's ServiceAccount needs `list`/`watch` on `configmaps` —
already in the [deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/master/deploy)
role manifests.

### Write rules

Each ConfigMap `data` value is a YAML document of rules. A rule is a CEL
expression returning a bool plus an action — `log` (record, continue), `allow`
(short-circuit this ruleset and pass), or `block`:

```yaml
rules:
  - id: block-sqli
    expression: regexMatch(lower(urlDecode(request.query)), "(union\\s+select|or\\s+1=1)")
    action: block
  - id: allow-office
    expression: ipInCidr(request.remote_ip, "203.0.113.0/24")
    action: allow
    priority: 0          # lower priority runs first
```

Variables (`request.method`, `.path`, `.query`, `.headers[...]`, `.remote_ip`, …)
and functions (`ipInCidr`, `regexMatch`, `containsAny`, `hasPrefixAny`, `lower`,
`upper`, `urlDecode`) are documented in [WAF.md](WAF.md).

### GeoIP country filtering (`request.country`)

Rules can filter on `request.country` (ISO 3166-1 alpha-2) with no extra config:
the controller images **bake in** the free
[IPLocate ip-to-country](https://github.com/iplocate/ip-address-databases) `.mmdb`,
and `WAF_GEOIP_DB` **defaults** to it (`/geoip/ip-to-country.mmdb`). Just enable the
WAF and write rules — point `WAF_GEOIP_DB` elsewhere for a custom DB, or set it to
`""` to disable:

```yaml
rules:
  - id: th-only
    expression: request.country != "TH"     # blocks unplaceable IPs too
    action: block
```

`request.country` is always present — `""` when GeoIP is off, `"XX"` when the IP
can't be placed, otherwise the ISO code — so a rule never fails open on a missing
key. The bundled data is from [IPLocate.io](https://www.iplocate.io) under
CC BY-SA 4.0 (keep the attribution); see [WAF.md](WAF.md) to swap or update it.

### ASN filtering (`request.asn`)

Filter on `request.asn` (the autonomous system number, an integer) the same way —
the [IPLocate ip-to-asn](https://github.com/iplocate/ip-address-databases) `.mmdb`
is baked in and `WAF_ASN_DB` **defaults** to it (`/geoip/ip-to-asn.mmdb`):

```yaml
rules:
  - id: block-asn
    expression: request.asn == 13335
    action: block
```

`request.asn` is always present — `0` when ASN lookup is off or the IP can't be
placed (so `request.asn == 0` is a usable "unknown AS" predicate). The ip-to-asn DB
is large (~74 MB), so pass `--build-arg ASN_DB_URL=` (empty) to skip baking it, or
set `WAF_ASN_DB=""` to disable the lookup. See [WAF.md](WAF.md).

### Global ruleset

Applies to all traffic. Create it in the controller's own namespace
(`POD_NAMESPACE`) with the label `parapet.moonrhythm.io/waf: global`:

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
        expression: containsAny(lower(request.user_agent), ["sqlmap", "nikto"])
        action: block
```

### Zones (per-tenant)

A zone is a ConfigMap labeled `parapet.moonrhythm.io/waf: zone`; its **name** is
the zone id. Create it in the tenant's namespace and bind ingresses to it with the
`parapet.moonrhythm.io/waf-zone` annotation:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: acme                 # zone id
  namespace: acme-prod
  labels:
    parapet.moonrhythm.io/waf: zone
data:
  rules.yaml: |
    rules:
      - id: block-admin
        expression: hasPrefixAny(request.path, ["/admin", "/internal"])
        action: block
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: acme-prod
  annotations:
    parapet.moonrhythm.io/waf-zone: acme       # -> acme-prod/acme
spec:
  ingressClassName: parapet
  # ...
```

A bare id resolves to a zone in the ingress's own namespace; use `namespace/zone`
to reference a shared zone elsewhere (e.g. `team-x/acme`). The global ruleset runs
first and is authoritative — a zone cannot `allow`-override a global `block`.
Editing a tenant's zone affects only the ingresses bound to it.

### Rollout

Ship rules with `action: log` first (shadow mode), watch
`parapet_waf_matches{action="log"}` for false positives, then switch to `block`.
Keep `WAF_FAIL_MODE=open` (the default) so a rule evaluation error fails open
rather than dropping legitimate traffic.

## Metrics

Parapet ingress controller support prometheus metrics by add prometheus annotations to pod template.

```yaml
annotations:
  prometheus.io/port: "9187"
  prometheus.io/scrape: "true"
```

### Supported Metrics

#### Ingress Metrics

- parapet_requests{host, status, method, ingress_name, ingress_namespace, service_type, service_name}
- parapet_service_duration_seconds{service_type, service_namespace, service_name}
- parapet_backend_connections{addr}
- parapet_backend_network_read_bytes{addr}
- parapet_backend_network_write_bytes{addr}
- parapet_reload{success}
- parapet_host_ratelimit_requests{host}
- parapet_host_active_requests{host, upgrade}
- parapet_waf_matches{rule_id, action, scope}

#### Metrics directly use from parapet

- parapet_connections{state}
- parapet_network_request_bytes{}
- parapet_network_response_bytes{}

## License

MIT

The controller images bake IP geolocation data from
[IPLocate.io](https://www.iplocate.io), licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). If you ship an
image with the GeoIP database baked in (the default), keep that attribution.
