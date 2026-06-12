# parapet-ingress-controller

[![Go Test](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/go-test.yaml/badge.svg?branch=main)](https://github.com/moonrhythm/parapet-ingress-controller/actions/workflows/go-test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/moonrhythm/parapet-ingress-controller)](https://goreportcard.com/report/github.com/moonrhythm/parapet-ingress-controller)

A Kubernetes ingress controller built on the
[parapet](https://github.com/moonrhythm/parapet) middleware framework. The page
you're reading is the **usage** contract — Ingresses, annotations, WAF, and
metrics. The full behavior contract lives in [`SPEC.md`](SPEC.md).

## Deploy

See deploy config at [deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/main/deploy)
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
env-var table, and per-request order are in [`SPEC.md`](SPEC.md); the plugins
live in [`plugin`](plugin).

## Configuration

Every component is configured entirely through environment variables. The tables
below list **all** of them, grouped by binary. The controller's set is also the
contract in [`SPEC.md`](SPEC.md); the edge components are designed in
[`EDGE.md`](EDGE.md). See the
[deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/main/deploy)
manifests for runnable examples.

### Controller (`cmd/parapet-ingress-controller`)

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `80` | HTTP (+ h2c) listener port |
| `HTTPS_PORT` | `443` | TLS port; **empty** = HTTP-only; unset = 443 |
| `INGRESS_CLASS` | `parapet` | `ingressClassName` to handle |
| `KUBERNETES_BACKEND` | cluster | Source of K8s objects: in-cluster watch (default), `fs` (one-shot load of static manifests, no watch — local dev/smoke tests), or `local` (kubectl proxy at `127.0.0.1:8001`) |
| `KUBERNETES_FS` | — | Directory of static manifests; **required** when `KUBERNETES_BACKEND=fs` |
| `WATCH_NAMESPACE` | `""` (all) | Restrict the watch to one namespace |
| `POD_NAMESPACE` | `""` | Controller's namespace (bounds the global WAF / rate-limit rulesets) |
| `LOAD_ALL_CERTS` | `false` | Index every TLS secret, not just `spec.tls`-referenced — lets a wildcard cert serve SNI without per-ingress wiring |
| `TRUST_PROXY` | `""` | `true` / `false` / comma-separated CIDRs (+ `cloudflare` / `google` / `bunny` shorthands). Whether to honor inbound `X-Forwarded-*` from a trusted front proxy vs. overwrite with the peer |
| `WAIT_BEFORE_SHUTDOWN` | `30s` | Drain delay on SIGTERM |
| `DISABLE_LOG` | `false` | Suppress the access log |
| `HTTP_SERVER_MAX_HEADER_BYTES` | `16384` | Max request header size |
| `HOST_CONCURRENT_CAPACITY` / `_SIZE` | `0` | Per-host in-flight cap / queue size (0 = off) |
| `HOST_COUNTRY_CONCURRENT_CAPACITY` / `_SIZE` | `0` | Per-host+country cap / queue size |
| `HOST_COUNTRY_HEADER` | `""` | Header(s) carrying the country code for the per-host+country limiter |
| `TR_MAX_CONNS_PER_HOST` | stdlib | Upstream max connections per host |
| `TR_MAX_IDLE_CONNS_PER_HOST` | stdlib / 128 | Upstream idle connection pool size |
| `UPSTREAM_AUTO_H2C` | `false` | Speculatively try h2c on plain-`http` upstreams, fall back to HTTP/1.1 when unsupported (verdict cached per-Service with a TTL) |
| `UPSTREAM_AUTO_H2C_TTL` | `10m` | How long a cached auto-h2c verdict is trusted before re-probing (only when `UPSTREAM_AUTO_H2C` is on) |
| `PROFILER` / `PROFILER_NAME` | `false` / — | Enable Cloud Profiler / its service name |
| `RATELIMIT_ENABLED` | `false` | Master switch for ConfigMap-driven rate limiting (see [RATELIMIT.md](RATELIMIT.md)) |
| `WAF_ENABLED` | `false` | Master switch for the WAF (see [WAF.md](WAF.md)) |
| `WAF_FAIL_MODE` | `open` | `open` (skip on rule error) / `closed` (500) |
| `WAF_EVAL_TIMEOUT` | `5ms` | Per-request ruleset deadline |
| `WAF_GEOIP_DB` | `/geoip/ip-to-country.mmdb` | IPLocate ip-to-country `.mmdb` → `request.country` + rate-limit `country` keys (loaded when WAF **or** ratelimit is on). Defaults to the baked-in DB; `""` disables |
| `WAF_ASN_DB` | `/geoip/ip-to-asn.mmdb` | IPLocate ip-to-asn `.mmdb` → `request.asn` + rate-limit `asn` keys. Defaults to the baked-in DB; `""` disables |
| `WAF_COST_LIMIT` | — | CEL cost cap per rule (see [WAF.md](WAF.md)) |
| `WAF_INSPECT_BODY` | — | Request-body bytes made available to rules |
| `WAF_DISABLE_MACROS` | — | CEL macro kill-switch |
| `WAF_VALIDATED_PROXY` | `""` | Skip the core's global+zone WAF for requests already validated at the edge. Comma list of `edge-mtls` (peer cert chains to the live edge CA; requires `EDGE_TRUST_CP_ENDPOINT`) and/or CIDRs/named groups (immediate TCP peer); also requires the `X-Parapet-Waf` claim. `true` is refused; a bad spec is fatal at startup |
| `EDGE_TRUST_CP_ENDPOINT` | `""` | Edge-trust CP endpoint — enables `edge-mtls` verification (peer client cert against the live edge CA bundle) |
| `EDGE_TRUST_CP_CA` | `""` | CA file to verify the edge-trust CP's TLS (else system roots) |
| `EDGE_TRUST_CP_CACHE_FILE` | `""` | Warm-start path for the fetched trust bundle (survives CP-down restarts) |
| `EDGE_TRUST_CP_MAX_STALE` | `3600` (s) | Max age the cached trust bundle is honored when the CP is unreachable |
| `EDGE_TRUST_CP_POLL_INTERVAL` | `300` (s) | How often to refresh the edge-trust bundle from the CP |
| `EDGE_TRUST_READY_WAIT` | `10s` | Startup wait for the first trust-bundle fetch before serving |

### Edge control plane (`cmd/edge-controlplane`)

In-cluster REST API that distributes cert+key, WAF rules, rate limits, and cache
purges to edges. See [EDGE.md](EDGE.md).

| Variable | Default | Description |
|---|---|---|
| `CP_LISTEN` | `:8443` | API listener address |
| `CP_METRICS_LISTEN` | `:9187` | Prometheus listener (separate, unauthenticated); `""` disables |
| `CP_TLS_CERT` / `CP_TLS_KEY` | `""` | Server cert + key → HTTPS. **Both empty** = plaintext HTTP (only on a trusted private network); one-of-two is a config error |
| `CP_TOKENS` | `""` | Per-edge bearer tokens as JSON: `{"<token>":["acme.com",…]}` or `{"<token>":{"id","domains","disabled"}}` |
| `CP_TOKENS_FILE` | `""` | Alternative to `CP_TOKENS`: path to that JSON file |
| `WATCH_NAMESPACE` | `""` (all) | Namespace to watch for cert secrets / WAF / ratelimit ConfigMaps |
| `POD_NAMESPACE` | `""` | CP's namespace (bounds the global WAF ruleset; holds the managed CA Secret) |
| `CP_WAF_ENABLED` | `false` | Serve WAF rules to edges (`GET /v1/waf`) |
| `CP_RATELIMIT_ENABLED` | `false` | Serve rate-limit sets to edges (`GET /v1/ratelimit`) |
| `CP_HOSTS_ENABLED` | `true` | Serve the known-hosts oracle to edges (`GET /v1/hosts`) — the edge per-host request metric's allow-list |
| `CP_EDGE_SIGN_CONCURRENCY` | `GOMAXPROCS` | Max concurrent edge-cert signings (overflow → 503 + Retry-After) |
| `CP_EDGE_SIGN_RETRY_AFTER` | `5` (s) | `Retry-After` returned when signing is shed |
| `CP_TRUST_WATCH_CONCURRENCY` | `1024` | Max blocked long-pollers on `GET /v1/trust-bundle?watch=1` (0 disables the cap) |
| `CP_TRUST_WATCH_RETRY_AFTER` | `5` (s) | `Retry-After` when the watch cap is hit |
| `CP_EVENTS_ENABLED` | `true` | Serve the `GET /v1/events` SSE change stream |
| `CP_EVENTS_PING_INTERVAL` | `20` (s) | SSE keep-alive ping interval |
| `CP_EVENTS_MAX_SUBSCRIBERS` | `1024` | Max concurrent SSE subscribers |
| `CP_EVENTS_MAX_PER_TOKEN` | `32` | Max SSE subscribers per token |
| `CP_EVENTS_RETRY_AFTER` | `30` (s) | `Retry-After` when the SSE cap is hit |
| `CP_PURGE_ENABLED` | `false` | Enable the cache-purge journal (`GET`/`POST /v1/purges`) |
| `CP_PURGE_ADMIN_TOKEN` | — | Stronger credential required to **issue** a purge (`POST /v1/purges`) |
| `CP_PURGE_MAX_ENTRIES` | `0` (unbounded) | Per-token purge-journal cap before a conservative fold |
| `CP_EDGE_METRICS_TTL` | `300` (s) | How long a pushed edge metrics snapshot is served before its series expire |
| `EDGE_CA_CERT` / `EDGE_CA_KEY` | `""` | Provided-mode edge CA cert + key → enable client-cert issuance + trust bundle |
| `EDGE_CA_SECRET` | `""` | Managed-mode edge CA Secret in `POD_NAMESPACE` (alternative to the provided files). Neither set ⇒ issuance off |
| `EDGE_CA_PROVIDED_GENERATION` | cert mtime | Provided-mode CA generation stamp (operator bumps on each rotation) |
| `EDGE_CA_TTL` | ~2 years | Lifetime for a self-generated/rotated CA |
| `EDGE_CLIENTCERT_TTL` | `168h` (7d) | Issued edge client-cert lifetime |
| `EDGE_CLIENTCERT_SKEW` | `10m` | Backdating skew on issued client certs |
| `EDGE_CA_ROTATION_DEADLINE` | `86400` (s) | When a stuck overlap rotation is flagged via metrics |
| `EDGE_CA_BOOTSTRAP` | `false` | Run-once Job: self-generate the CA into its Secret, then exit |
| `EDGE_CA_ROTATE` | `false` | Run-once Job: stage a NEW CA alongside OLD (overlap), then exit |
| `EDGE_CA_REVOKE` | `false` | Run-once Job: drop the OLD CA after convergence checks, then exit |
| `EDGE_CA_REVOKE_EDGE_ID` | — | Edge id being revoked (revoke mode) |
| `EDGE_CA_REVOKE_TIMEOUT` | `30m` | Overall deadline for the revoke convergence wait |
| `EDGE_CONVERGE_STATUS` | `false` | Run-once: print fleet convergence status, then exit |

The `EDGE_CONVERGE_*` knobs below tune the run-once convergence/revoke Jobs (they
scrape Prometheus to confirm the fleet has adopted a CA/authz generation before a
destructive step):

| Variable | Default | Description |
|---|---|---|
| `EDGE_CONVERGE_PROM_URL` | — | Prometheus URL to scrape edge/CP/core convergence series |
| `EDGE_CONVERGE_EXPECTED_CP` / `_CORE` / `_MIN_EDGES` | `0` | Expected reporter counts that must all be present |
| `EDGE_CONVERGE_EXPECTED_CA_ID` | — | CA id the fleet must report |
| `EDGE_CONVERGE_EXPECTED_SIGNER_FP` | — | Active-signer fingerprint the fleet must report |
| `EDGE_CONVERGE_EXPECTED_AUTHZ_GEN` | `0` | Authz generation the fleet must report |
| `EDGE_CONVERGE_REVOKED_EDGE_ID` | — | Edge id expected to be absent/revoked |
| `EDGE_CONVERGE_EXCLUDE` | — | Comma-separated ids to exclude from the convergence check |
| `EDGE_CONVERGE_STABLE_READS` | `2` | Consecutive matching scrapes required |
| `EDGE_CONVERGE_FRESHNESS` | `5m` | Max age of a scraped series to count |
| `EDGE_CONVERGE_POLL_INTERVAL` | `30s` | Between convergence evaluations |
| `EDGE_CONVERGE_SCRAPE_INTERVAL` | `15s` | Between Prometheus scrapes |
| `EDGE_REFRESH_INTERVAL` | `300s` | The edge poll cadence the Job assumes when computing its wait |
| `EDGE_CONVERGE_REVOKED_TOKEN` / `_CP_URL` / `_CP_CA` | — | Token + URL + CA to actively probe a revoked edge's access during revoke |

### Edge proxy (`cmd/edge-proxy`)

Out-of-cluster TLS-terminating proxy. See [EDGE.md](EDGE.md).

| Variable | Default | Description |
|---|---|---|
| `EDGE_HTTPS_LISTEN` | `0.0.0.0:443` | Public TLS listener |
| `EDGE_HTTP_LISTEN` | `0.0.0.0:80` | Public HTTP listener; `""` disables |
| `EDGE_METRICS_LISTEN` | `:9187` | Prometheus listener; `""` disables |
| `EDGE_CP_ENDPOINT` | `https://controlplane:8443` | Control-plane base URL (must be `https://` unless `EDGE_CP_ALLOW_PLAINTEXT=true`) |
| `EDGE_CP_ALLOW_PLAINTEXT` | `false` | Allow a non-`https` CP endpoint (trusted private network only) |
| `EDGE_CP_TOKEN` | — | **Required** per-edge bearer token |
| `EDGE_CP_CA` | `""` | CA file to verify the CP's TLS (else system roots) |
| `EDGE_ID` | hostname | Stable logical edge identity (required with `EDGE_DATAPLANE_MTLS`) |
| `EDGE_INSTANCE_ID` | `""` | Disambiguates replicas sharing one `EDGE_ID` in pushed metrics |
| `EDGE_DOMAINS` | `""` (serve-all) | Comma-separated domains to serve; empty = on-demand fetch any authorized SNI |
| `EDGE_REFRESH_INTERVAL` | `300` (s) | Cert/WAF/ratelimit refresh poll cadence |
| `EDGE_EVENTS_ENABLED` | `true` | Subscribe to the CP's `GET /v1/events` change stream (accelerator over polling) |
| `WAIT_BEFORE_SHUTDOWN` | `30` (s) | Drain delay on SIGTERM |
| `DISABLE_LOG` | `false` | Suppress the access log |
| `TRUST_PROXY` | `""` | Same spec as the controller — set when the edge sits behind another L7 proxy |
| `EDGE_UPSTREAM_ADDR` | `parapet:80` | Where to forward (the in-cluster parapet) |
| `EDGE_UPSTREAM_TLS` | `false` | Re-encrypt the upstream hop with TLS |
| `EDGE_UPSTREAM_SNI` | `""` | SNI/Host for the upstream TLS hop |
| `EDGE_DATAPLANE_MTLS` | `false` | Present a CP-issued client cert on the upstream hop (requires `EDGE_UPSTREAM_TLS=true` + `EDGE_ID`) |
| `EDGE_WAF_ENABLED` | `false` | Run the global+zone WAF at the edge |
| `EDGE_RATELIMIT_ENABLED` | `false` | Enforce the CP-distributed rate limits at the edge (requires `CP_RATELIMIT_ENABLED`) |
| `WAF_GEOIP_DB` | `/geoip/ip-to-country.mmdb` | Same as the controller — `request.country`; `""` disables |
| `WAF_ASN_DB` | `/geoip/ip-to-asn.mmdb` | Same as the controller — `request.asn`; `""` disables |
| `EDGE_ONDEMAND_NEG_TTL` | `30` (s) | Serve-all mode: negative-cache TTL for an unauthorized/unknown SNI |
| `EDGE_ONDEMAND_MAX_INFLIGHT` | `32` | Serve-all mode: max concurrent on-demand cert fetches |
| `EDGE_METRICS_PUSH_INTERVAL` | `0` (off) | Push the edge's metrics to the CP every N seconds (0 = disabled) |
| `EDGE_CACHE_ENABLED` | `false` | Enable the HTTP response cache |
| `EDGE_CACHE_BACKEND` | `disk` | `disk` or `memory` |
| `EDGE_CACHE_DIR` | `/var/cache/parapet-edge` | Cache root (disk backend only) |
| `EDGE_CACHE_MAX_SIZE` | `1073741824` (1 GiB) | Total bytes cap, LRU-evicted |
| `EDGE_CACHE_MAX_FILE_SIZE` | `8388608` (8 MiB) | Per-object bytes cap |
| `EDGE_CACHE_CHUNKED` | `true` | Cache GET responses with no `Content-Length` (chunked / on-the-fly-compressed bodies — gzip/br/zstd) by buffering to derive a length; the cap is still enforced mid-stream, SSE is never buffered, and a truncated upstream is never committed. `false` caches only `Content-Length`'d responses |
| `EDGE_CACHE_PURGE_ENABLED` | `true` | Poll for + apply cache purges (needs `CP_PURGE_ENABLED`) |
| `EDGE_CACHE_PURGE_POLL_INTERVAL` | `10` (s) | Poll `GET /v1/purges` cadence |
| `EDGE_CACHE_PURGE_MAX_RECORDS` | `65536` | Per-map invalidation-record cap before a conservative fold-to-global |
| `EDGE_CACHE_PURGE_SWEEP_INTERVAL` | `300` (s) | Background reaper cadence (reclaim invalidated entries off the serving path) |
| `EDGE_CLIENTCERT_RENEW_REMAINING_FRACTION` | `0.66` | Re-mint the mTLS client cert once this fraction of its life remains |
| `EDGE_CLIENTCERT_REMINT_JITTER` | `60` (s) | Jitter on proactive re-mints |
| `EDGE_CLIENTCERT_REMINT_BACKOFF_BASE` | `2` (s) | Base backoff between failed re-mints |
| `EDGE_CLIENTCERT_REMINT_COOLDOWN` | `5 × refresh` (s) | Min interval between re-mint attempts |
| `EDGE_CLIENTCERT_REMINT_BREAKER_K` | `3` | Failures before the re-mint breaker trips |
| `EDGE_CLIENTCERT_REMINT_PROACTIVE_J` | `5` | Proactive re-mint jitter buckets |

## Web Application Firewall (WAF)

An opt-in CEL-rule firewall with a platform-wide **global** ruleset plus
per-tenant **zones** that an ingress binds by reference. Rules live in ConfigMaps
and hot-reload without restarting the controller or rebuilding routes. Full
design and the complete CEL reference: [WAF.md](WAF.md).

### Enable it

Set `WAF_ENABLED=true` on the controller (off by default; when off the WAF does no
work). The controller's ServiceAccount needs `list`/`watch` on `configmaps` —
already in the [deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/main/deploy)
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
key. The resolved country is also forwarded **upstream** as `X-Forwarded-Country`
(overwriting any client value), so backends can read it without their own lookup.
The bundled data is from [IPLocate.io](https://www.iplocate.io) under CC BY-SA 4.0
(keep the attribution); see [WAF.md](WAF.md) to swap or update it.

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
placed (so `request.asn == 0` is a usable "unknown AS" predicate). It is also
forwarded **upstream** as `X-Forwarded-ASN`. The ip-to-asn DB is large (~74 MB), so
pass `--build-arg ASN_DB_URL=` (empty) to skip baking it, or set `WAF_ASN_DB=""` to
disable the lookup. See [WAF.md](WAF.md).

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
- parapet_host_active_requests{host, kind}
- parapet_ratelimit_total{name, result}
- parapet_rejected_requests{reason}
- parapet_waf_matches{rule_id, action, scope}
- parapet_waf_eval_duration_seconds{outcome, scope}

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
