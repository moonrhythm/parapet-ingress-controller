# Edge control plane (cert+key distribution + WAF distribution)

An **out-of-cluster edge reverse proxy** that terminates public TLS locally and
runs the WAF, fronting the in-cluster parapet ingress controller. A small
in-cluster **control plane** distributes, per edge, only the certificates (and
private keys) and WAF rules for the domains that edge serves.

> Status: **Phases 1–5 implemented** (cert distribution, WAF distribution + edge
> global eval, zones at edge, disk response cache, cache purge / invalidation).
> Both the control plane (`cmd/edge-controlplane`, reusing `cert`, `k8s`,
> `wafrule`) and the **edge** (`cmd/edge-proxy` + `edge`, on the parapet
> framework) are **Go**. They share **only a language-neutral HTTP/JSON contract**
> (below) on the wire. Per [`CLAUDE.md`](CLAUDE.md) the contract changes here first.

> **Both Go.** The control plane and edge share only the wire contract — no
> shared in-process state — but, both being Go, they draw on the same libraries
> (the controller's `cert`/`wafrule`/`geoip` packages and `parapet/pkg/waf`).
> (The edge was originally a separate Rust/Pingora implementation that shared
> *nothing* in code; see [Implementation history](#implementation-history).)

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
   (Default. `WAF_VALIDATED_PROXY` on the core is the explicit opt-out for
   strongly-identified edge hops — see
   [the backstop section](#parapet-stays-authoritative-the-backstop).)
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
                  │ optional global + zone rate limits (per-edge)         │
                  │ optional disk response cache                          │
                  │                                                       │
                  ├── HTTPS GET (bearer token) ─► controlplane :8443      │
                  │     GET /v1/certs?sni=… → cert+key+ETag (allowed SNI) │
                  │     GET /v1/waf         → rules for edge domains      │
                  │     GET /v1/ratelimit   → limits for edge domains     │
                  │   authz: bearer token → allowed domains/zones         │
                  │   reads: TLS Secrets, WAF + ratelimit ConfigMaps,     │
                  │          Ingresses                                    │
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
  (`wafrule`), and route/zone logic. Serves `GET /v1/certs?sni=…` (cert+key),
  `GET /v1/waf` (rules), and `GET /v1/ratelimit` (limits). Not on the request
  path.
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
- `GET /v1/ratelimit` → same scoping (zones, host-map, known hosts) per token.

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
  200 {"generation": N, "global_rules":"…", "zones":{…}, "route_zone_map":{…},
       "host_zone_map":{…}}
       global_rules   : the platform baseline YAML (identical for every edge)
       zones          : zoneKey ("<ns>/<name>") → rules YAML, scoped to the edge's hosts
       route_zone_map : route pattern → zoneKey — PATH-AWARE binding. Patterns are
                        byte-identical to the controller's route keys (Prefix →
                        "host/path" + "host/path/", Exact → trailing slash stripped,
                        ImplementationSpecific → as-is); the edge loads them into a
                        real http.ServeMux, so zone resolution matches the core
                        exactly (incl. two ingresses sharing a host with different
                        paths and different zones). Scoped to the edge's hosts.
       host_zone_map  : host → zoneKey — LEGACY host-level binding, kept for
                        pre-path-aware edges; a current edge uses it only when
                        route_zone_map is absent (older CP), as whole-host patterns.
       (ETag is over the *scoped* payload, so 304 revalidation is per-edge-correct)

GET /v1/ratelimit     Authorization: Bearer <token>   [If-None-Match: "<etag>"]
  200 {"generation": N, "global_limits":["…"], "zones":{"<ns>/<name>":["…"]},
       "route_zone_map":{…}, "host_zone_map":{…}, "hosts":["…"]}
       global_limits  : the platform baseline limit DOCUMENTS (identical for every edge)
       zones          : zoneKey → limit documents, scoped to the edge's hosts
       route_zone_map : route pattern → zoneKey (`ratelimit-zone`, same-namespace
                        only) — same path-aware model as /v1/waf
       host_zone_map  : host → zoneKey (legacy, as in /v1/waf), scoped
       hosts          : every Ingress-declared host the edge may serve — wired as the
                        Limiter's KnownHost so host-keyed buckets for undeclared hosts
                        collapse into one (cardinality bound under a random-Host flood)
       (documents are ARRAYS of YAML strings, one per ConfigMap data value —
        ratelimitrule.Parse takes one document per string and does not split "---",
        so the WAF's concatenated format would silently drop trailing documents;
        ETag over the scoped payload, like /v1/waf)
  401 (no/invalid token)   404 (ratelimit distribution disabled)

GET /v1/purges?since=<seq>   Authorization: Bearer <token>
  200 {"entries":[{"seq":N,"scope":"url|host|prefix|tag|flush-all","host":"…","uri":"…","tag":"…"}],
       "max_seq": N, "flush_required": false}
       entries        : journal entries with seq > since, SCOPED to the token's hosts
                        (flush-all and tag reach every edge; host/url/prefix only its
                        allowed hosts; scope=prefix uri is the path prefix; scope=tag
                        carries a surrogate key in tag, no host)
       flush_required : true when the edge's next-needed seq (since+1) was trimmed
                        (it fell behind the retained window), OR when since > max_seq
                        (its cursor is ahead of the CP's journal — a CP restart / fresh
                        replica reset the in-memory journal). The edge does a lazy
                        flush-all and realigns its cursor to max_seq. Conservative:
                        never under-invalidates.
  401 (no/invalid token)   404 (purge distribution disabled)

POST /v1/purges       Authorization: Bearer <ADMIN token>   ← stronger cred than the read token
  {"scope":"url|host|prefix|tag|flush-all", "host":"…", "uri":"…", "tag":"…"}  → appends, returns {"seq":N}
       (scope=prefix: uri is the path prefix, e.g. "/blog"; path-only, boundary-aware.
        url+prefix: uri MUST be a rooted "/..." path in the SAME percent-encoded form the
        request carries — the cache keys on the raw request-uri, so "/café" must be sent
        as "/caf%C3%A9". A non-"/" uri is rejected 400.
        scope=tag: tag is a surrogate key from the origin's Cache-Tag response header,
        host-independent — distributed to every edge, which invalidates any entry whose
        stored Cache-Tag set contains it. tag is required. NOTE: tag names are
        broadcast fleet-wide (not host-gated like url/host/prefix), so they are a
        shared cross-tenant namespace — do not encode secrets in Cache-Tag values.)
       (the admin token is NOT host-scoped — it may purge any host; per-host scoping is
        applied on the read side, not at issue time)
  401 (no/invalid admin token)  400 (invalid scope/host/uri)  404 (purge distribution disabled)

POST /v1/metrics      Authorization: Bearer <token>   X-Edge-Instance: <instance>
  body: the edge's FULL Prometheus registry in text exposition format
  204 (snapshot stored; served merged into the CP's /metrics listener)
  401 (no/invalid token)
  403 (token has no id grant — the edge_id label is the token's identity, so an
       id-less token cannot push)
  400 (missing/oversized X-Edge-Instance, or unparseable body)  413 (body > 8 MiB)
  404 (CP_METRICS_LISTEN="" — ingestion disabled with the listener)
       (the CP OVERRIDES any edge_id label in the body with the token's id and adds
        edge_instance from the header — a pushed body can never impersonate another
        edge. EDGE_ID should match the token's id; the label is always the latter.)

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

The on-demand fetch blocks the handshake on a synchronous CP round trip, so three
guards bound its blast radius (all serve-all only): concurrent handshakes for the
**same** SNI collapse into one fetch via single-flight; a missing/denied SNI is
**negative-cached** for `EDGE_ONDEMAND_NEG_TTL` (default 30s) so it isn't re-fetched
on every handshake; and a **global cap** `EDGE_ONDEMAND_MAX_INFLIGHT` (default 32)
limits concurrent fetches across distinct SNIs — over the cap a handshake self-signs
immediately instead of queueing, so a flood of unknown SNIs can't exhaust handshake
goroutines or hammer the CP. `parapet_edge_ondemand_cert_total{result}` counts the
outcomes (`hit|miss|shed|suppressed`); a rising `shed`/`suppressed` rate signals a
flood or a too-tight cap/TTL.

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
   XX` for an unplaceable IP when the DB is loaded.
   With no DB loaded, `country` is `""` and `asn` is `0` and neither header is
   forwarded (the field is always present in the rule map, so a rule never errors)
   — such a rule simply won't early-drop at the edge, but parapet still re-runs it
   authoritatively (unless the core skips the re-run via `WAF_VALIDATED_PROXY`,
   which is why that opt-in requires GeoIP/ASN-DB parity — see its section below).
2. **Global WAF** (always) → block early on match.
3. Resolve the zone from the `route_zone_map` (host+path, the controller's own
   ServeMux semantics; falls back to the legacy `host_zone_map` against an older
   CP) → **zone WAF** → block on match.
4. If not blocked, forward to parapet with `X-Forwarded-For/-Proto/-Country/-ASN`.

Rule snapshots apply with the same **all-or-nothing compile + atomic swap +
keep-last-good** semantics as parapet's `SetRules`; on a fetch failure the edge
**fails static** (keeps last-good) — never fail-open to "no WAF".

Both layers record per-request rule-eval latency on `:9187` as
`parapet_waf_eval_duration_seconds{outcome,scope}` (`outcome` =
`pass|allow|block|error`, `scope` = `global|zone`), same metric as the
controller; an empty ruleset (before the first snapshot lands) takes the
no-rules fast path and records nothing. Edge rule *matches* are debug-logged
but not yet a counter (the controller's `parapet_waf_matches` is
controller-only).

### parapet stays authoritative (the backstop)

The control plane derives `host[/path] → zoneKey` from the Ingress objects
(reusing `controller`'s normalization + path matching) and ships it scoped to the
edge's domains. If the edge's resolution ever disagrees with parapet's router, it
is **non-fatal**: parapet re-runs global + zone WAF authoritatively and resolves
the zone from its own router. So:

- Edge WAF = early-drop optimization + DDoS shield (lower trust tier).
- parapet WAF = authority. **By default parapet re-runs the WAF for edge
  traffic** — keep it that way unless you've read the opt-out below.

Because the edge sets `X-Forwarded-For` and parapet trusts it
(`TRUST_PROXY=<edge CIDR>`), both evaluate against the same client IP.

#### Skipping the core re-run (`WAF_VALIDATED_PROXY`, opt-in)

When every edge runs the WAF and the edge→core hop is strongly identified, the
double evaluation can be turned off on the core: set `WAF_VALIDATED_PROXY` to a
comma-separated list of

- `edge-mtls` — the request's TLS client cert chains to the live edge CA.
  Cryptographic; requires edge auto-trust on the core (`EDGE_TRUST_CP_ENDPOINT`)
  and the re-encrypt data plane on the edge (`EDGE_UPSTREAM_TLS=true` +
  `EDGE_DATAPLANE_MTLS`), since the plaintext hop carries no client cert.
- CIDRs / named groups — the immediate TCP peer is in the listed ranges (the
  `TRUST_PROXY` spec language). The option for the plaintext `:80` hop; only as
  strong as network reachability into those ranges (anything that can source
  from them — e.g. any pod in a flat cluster network — bypasses the core WAF).

Peer trust alone is not enough: the core also requires the per-request
**`X-Parapet-Waf` claim** the edge stamps after its WAF layer evaluated the
request (`EdgeWAF.ClaimStamp`, mounted after the global+zone rulesets; value =
the live snapshot's generation, checked by presence). The claim is stamped only
once a CP snapshot has landed, and the edge strips any client-supplied claim
unconditionally — even with `EDGE_WAF_ENABLED=false` (`edge.StripWAFClaim`,
mounted before the WAF so CEL rules never see a spoofed value either). On the
core side, the claim is deleted from every request that is *not* skipped, so an
unvalidated claim never reaches CEL rules, the zone WAF, or the backend; a
skipped request's claim flows upstream, core-vouched. The claim is what lets
the core tell edges apart **per request**: a WAF-disabled edge, or one still on
its empty boot ruleset (booted while the CP was unreachable), forwards
claimless requests — which simply get the full core WAF.

Matching requests skip the core's global **and** zone WAF, counted as
`parapet_waf_skips{scope}`; rate limits, auth, routing, and geo headers are
unchanged, and non-matching traffic (direct, LB, another front proxy) still
gets the full core WAF. `WAF_VALIDATED_PROXY` is deliberately separate from
`TRUST_PROXY`: a front proxy you trust for `X-Forwarded-*` (e.g. Cloudflare)
did **not** run your WAF.

This makes the edge's WAF — and its `route_zone_map` zone resolution —
authoritative for matching traffic. The trade-offs you accept:

- the claim is the edge's **self-report**, made trustworthy by the verified
  peer identity — so it requires every edge image to be at least the version
  that stamps *and strips* the claim. An older binary never stamps (its
  traffic is simply evaluated at the core — safe), but it does not strip
  either, so a client could smuggle a claim through an old edge; keep the
  fleet current before opting in;
- zone-resolution drift is no longer corrected by the core for that traffic;
- the claim reflects **fail-static last-good** state: once a first snapshot
  has applied cleanly, an edge keeps claiming on its last-good rules through
  later fetch failures or a bad ruleset edit — mirroring the core's own
  keep-last-good posture. A snapshot that fails to compile never advances the
  claim generation or the etag, so a bad FIRST snapshot keeps the edge
  claimless (its traffic gets the full core WAF) and the input is re-fetched
  and retried every poll rather than 304ing forever;
- keep `WAF_INSPECT_BODY` / fail-mode parity between edge and core, or the
  edge's verdict is weaker than the one it replaces — and GeoIP/ASN-DB parity
  too: on a DB-less edge `request.country`/`request.asn` rules never match, and
  with the skip on nobody re-runs them;
- **upgrade the control plane before (or with) the edges.** A path-aware edge
  against an older CP (no `route_zone_map`) silently runs the legacy
  host-level fallback bindings — and **still stamps the claim** (the claim
  asserts "this edge's WAF evaluated the request", not which binding model it
  used). For a host shared by ingresses with different paths and different
  zones, that fallback resolves one zone for the whole host, and the skip
  means the core never corrects it. The path-aware soundness of the skip only
  holds once the CP serves `route_zone_map`.

Fail-fast guards: `WAF_VALIDATED_PROXY=true` is refused (that's
`WAF_ENABLED=false` with extra steps), `edge-mtls` without auto-trust and
malformed CIDRs abort startup.

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

## Rate limiting at the edge

Opt-in (`EDGE_RATELIMIT_ENABLED=true` on the edge, `CP_RATELIMIT_ENABLED=true`
on the control plane): the edge enforces the same ConfigMap-driven global +
zone rate limits the controller does (see [RATELIMIT.md](RATELIMIT.md)),
reusing `ratelimitrule` — the controller's own runtime — so a limit shapes
traffic identically by construction (fixed/sliding strategies, shadow mode,
exclude CIDRs, the ACME-challenge exemption, all-or-nothing `SetLimits` with
per-limit counter carry-over).

Distribution mirrors the WAF exactly: the CP watches the
`parapet.moonrhythm.io/ratelimit` ConfigMaps (global honored only from
`POD_NAMESPACE`; a ConfigMap also carrying the WAF label is refused — one
ConfigMap per feature, like the controller) and derives `host → zoneKey` from
the `ratelimit-zone` annotation on Ingresses — **same-namespace only**,
mirroring `plugin.RateLimitZone` (zones carry shared counter state; a
cross-namespace bind would be a cross-tenant DoS channel). Both features share
one Ingress watch. The edge polls `GET /v1/ratelimit` on
`EDGE_REFRESH_INTERVAL`, fail-static.

Per-request order: **after the edge WAF** (WAF-blocked traffic never burns
rate budget, the controller's own order) and **before the response cache** —
edge-enforced limits apply to cache hits too (the core's per-pod counters
still never see a cache hit, since hits never reach it).

What to know before enabling:

- **Counters are per edge**, exactly as the controller's are per pod: N edges
  + M controller replicas admit up to (N+M)× `rate` fleet-wide. The edge
  enforcing a limit does not relieve the core's own enforcement — each layer
  counts the traffic it sees.
- **Zone resolution is path-aware** (`route_zone_map`), like the edge WAF: the
  controller's own route keys on a real `http.ServeMux`, so a host shared by
  two ingresses with different paths and different zones burns each zone's
  budget on its own paths only. parapet's per-ingress binding stays
  authoritative behind it.
- **GeoIP parity**: `country`/`asn`-keyed limits need the IPLocate `.mmdb`s on
  the edge (same `WAF_GEOIP_DB`/`WAF_ASN_DB` contract; the resolvers load when
  the WAF **or** rate limiting is enabled). Without the DB, `SetLimits`
  rejects the whole set (all-or-nothing) rather than silently bucketing
  everyone together — the edge then keeps last-good (possibly empty) limits.
- **Host-key cardinality**: the payload's `hosts` list (every Ingress-declared
  host, scoped per edge) is wired as the Limiter's `KnownHost`, so host-keyed
  buckets for undeclared hosts collapse into one — a random-Host flood can't
  mint unbounded keys, mirroring the controller's `IsKnownHost`.
- Decisions count in `parapet_ratelimit_total{name,result}` on the edge's
  `:9187`, same names as the controller (`global:<id>` / `zone:<ns>/<name>:<id>`)
  on a different scrape target.

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
- **Observability.** Sets `X-Cache: HIT|MISS|STALE` (HIT = served from the edge
  cache, MISS = fetched from parapet, STALE = served stale under RFC 5861).
  Cache outcomes are counted on the `:9187` metrics
  endpoint (`EDGE_METRICS_LISTEN`, set `""` to disable) as
  `parapet_cache_total{result}` (`HIT|MISS|STALE|STALE_ERROR|BYPASS` — BYPASS is
  the ineligible-request path that sends no `X-Cache` header) plus
  `parapet_cache_fill_duration_seconds` (origin-fill latency, observed only when
  parapet was contacted on the serving path). Deliberately **no `host` label** —
  the edge serves any Host the client sends, so a host label would be unbounded
  series under a flood. Unless `DISABLE_LOG` is set, each access-log line also
  carries the outcome as a `cacheStatus` field.

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
EDGE_CACHE_PURGE_ENABLED         poll for + apply cache purges (default true; needs
                                 CP_PURGE_ENABLED on the control plane)
EDGE_CACHE_PURGE_POLL_INTERVAL   poll GET /v1/purges (default 10s; lower than the
                                 cert/WAF refresh — invalidation latency matters more)
EDGE_CACHE_PURGE_MAX_RECORDS     per-map cap before a conservative fold-to-global
                                 (default 65536)
EDGE_CACHE_PURGE_SWEEP_INTERVAL  reaper cadence: physically reclaim invalidated
                                 entries off the serving path (default 300s)
```

The purge feature is **implemented** (see "Purge / invalidation" below). A
background reaper (`EDGE_CACHE_PURGE_SWEEP_INTERVAL`) physically reclaims
invalidated entries off the serving path; the in-memory record table is bounded by
the count-cap fold, and disk by the cache's LRU byte cap.

A fetch/IO error on the read path **fails static** (degrades to a cache miss →
serve from origin), never erroring the client request. RFC 5861
stale-while-revalidate / stale-if-error are honored when the origin opts in via
`Cache-Control` (part of `parapet/pkg/cache`). **Not yet:** Range/partial
caching, per-route policy via Ingress annotations, and chunked-GET caching (a
GET needs a `Content-Length`).

### Purge / invalidation

> **Status: implemented** (edge `edge/purge.go` + `edge/purgerefresh.go` +
> `edge/purgereaper.go`; control plane `edgecp/purgestore.go` + `GET`/`POST
> /v1/purges`). The lookup gate is the `parapet/pkg/cache`
> `Options.InvalidatedAfter` hook (parapet **v0.17.0**); the reaper uses
> `Storage.Range` + the raw host/uri in `Meta` (parapet **v0.17.1**); tag scope
> uses the surrogate keys in `Meta.Tags` (parapet **v0.17.2**).

Invalidation is **pulled from the control plane**, exactly like cert and WAF
distribution: an operator publishes a purge once at the control plane and every
sharded edge converges on its own timer. There is **no inbound purge port on the
edge** (edges are out-of-cluster, often NAT'd), and the per-token host scoping is
the same boundary that gates `/v1/certs` and `/v1/waf`. Five scopes are supported:
**exact URL** (all `Vary` variants, both schemes, GET+HEAD), **path prefix**
(every URL under a path on a host — path-only, boundary-aware: `/blog` covers
`/blog` and `/blog/x` but not `/blogger`), **whole host**, **tag** (every cached
response carrying a surrogate key from the origin's `Cache-Tag` header — content
identity, host-independent), and **flush-all**. Host/url/prefix are host-scoped
(an edge gets only purges for hosts it serves); tag and flush-all reach every edge,
which then matches each entry's own tags / created-time.

**Why lazy epochs, not eager file deletion.** The cache stores each entry under
`variantHash = hash(primaryHash ⊕ Vary-values)`, where `primaryHash =
hash(host+method+scheme+uri)`. So from a URL alone you **cannot enumerate its
variants' storage keys** — there's no index, and the hash mixes everything. But
the cache's `InvalidatedAfter(r, Meta)` hook runs *at lookup* with the live
request (host, uri) **and** the stored `Meta` (which carries `Created`, unix
nanos). So the edge can match a request against a coarse predicate at lookup time
regardless of variance, without ever naming the key. That asymmetry is why purge
is **lazy epoch invalidation**, not synchronous deletes: a hit whose
`Meta.Created <= invalidAfter` is reaped and served as a miss, exactly like a
passed `FreshUntil`.

**The invalidation table** (`edge.PurgeTable`, in-memory, persisted to
`<EDGE_CACHE_DIR>/purge-state` with the same temp+fsync+rename as the disk cache;
the in-memory backend keeps no state):

```
global:  int64                       // flush-all epoch (unix nanos); 0 = never
host:    host                → int64 // normalized host (lowercase, port-stripped)
url:     hash(host ⊕ uri)    → int64 // uri = path+query; method/scheme-agnostic
cursor:  uint64                      // last journal seq applied — persisted in the SAME atomic write as the maps
```

**Lookup gate** — `PurgeTable.InvalidatedAfter`, wired into `cache.Options`:

```
invalidAfter = max(global, host[normHost(r.Host)], url[hash(normHost ⊕ r.URL.RequestURI())])  // absent ⇒ 0
// the cache then reaps + misses any hit with Meta.Created <= invalidAfter
```

Host normalization mirrors `cache.primaryHash` exactly (lowercase + strip port)
so a purge key matches the stored key. Keying the `url` map on `host ⊕ uri` (not
the full primary) is deliberate: one URL purge covers **all methods, both
schemes, and every `Vary` variant** — the operator's mental model of "purge
`/a`". Issue cost is **O(1)**; the hot-path cost is one `RLock` + ≤3 map lookups +
a timestamp compare, and only on cache hits (so zero when caching is disabled, and
nil-checked away entirely when purge is off).

**Edge-clock epochs — no trusted CP timestamp.** An epoch is *"invalidate
everything cached before this edge learned of the purge"* = the edge's own wall
clock at apply. This removes any CP↔edge clock-skew dependency; the control plane
only has to **deliver** the directive. Idempotency comes from the cursor, not the
timestamp: the edge applies a journal `seq` only if `seq > cursor`, so an entry is
applied exactly once and "now-at-apply" is never replayed. The one inherent gap —
an in-flight miss whose origin fetch began before apply but commits just after —
is the same race every CDN purge has; the next TTL expiry or purge covers it.
Epochs are clamped **monotonic non-decreasing** (a new stamp is `>= highWater`, the
largest epoch ever stamped, reloaded from disk on restart) so an NTP step back
can't un-purge.

**Reaping (entries).** The lazy gate alone reaps an entry only when it is next
looked up, so after a broad purge with little traffic the dead bytes would linger
until LRU pressure evicts them. A **background reaper** (`ReapOnce` / `RunReaper`,
`EDGE_CACHE_PURGE_SWEEP_INTERVAL`, default 300s, jittered) closes that: it
`Storage.Range`s over the cache and `Delete`s every entry whose `Meta.Created <=
epochFor(Meta.Host, Meta.URI, Meta.Tags)` — using the host/uri/tags parapet stamps
into `Meta` so every scope matches off the serving path (an old entry with an empty
`Host` matches the global scope only). Correctness never depends on the reaper —
the gate already guarantees a purged entry is never served — so it deletes only in
the **safe direction**: over-deleting a still-valid entry (e.g. a `Created` stamped
low by a wall-clock step) merely costs a re-fetch, never a stale serve.

**The reaper deliberately does NOT retire records.** Dropping a record is the one
*under-invalidating* direction, and it can't be made safe against a backward
wall-clock step: both `Meta.Created` (stamped by parapet at fill-commit) and any
sweep marker are unclamped wall clocks, so a fill that commits with a regressed
`Created` after the sweep walk could match a record the sweep then retired —
leaving a purged entry servable. Since retirement is only an optimization over an
already-safe bound, the table is bounded purely by the **count-cap fold** instead.

The **count-cap fold** bounds the `host`/`url` maps unconditionally and safely: if
a map exceeds `EDGE_CACHE_PURGE_MAX_RECORDS` it is folded into the `global` epoch
(which `≥` every record it held, via the `highWater` monotonic clamp) and cleared —
**over-invalidates (a coarser flush) but never under-invalidates**. Because purges
are operator-issued (not per request), the maps stay small and the fold is
essentially never hit in practice. Disk is additionally bounded by the cache's LRU
byte cap regardless.

**Distribution loop.** The control plane keeps a bounded append-only journal
(`{seq, scope, host?, uri?}`, monotonic `seq`, `min_seq` = oldest retained,
`CP_PURGE_MAX_ENTRIES`). The edge polls `GET /v1/purges?since=<cursor>` on
`EDGE_CACHE_PURGE_POLL_INTERVAL`; on `flush_required` it bumps the `global` epoch
and realigns `cursor = max_seq`, else it applies each new entry once and (only on a
real change) atomically persists `{maps, cursor}`. The CP returns `flush_required`
both when the cursor fell behind the retained window (`since+1 < min_seq`) **and**
when the cursor is *ahead* of the journal (`since > max_seq` — a CP restart or fresh
replica reset the in-memory journal); the latter is the case where `cursor =
max_seq` is a deliberate realign **down**, so a reset can't wedge the edge into
flushing every poll. The CP scopes each edge's response by its token (flush-all
reaches every edge; host/url entries only edges that may serve that host). Purges
are issued by an admin
`POST /v1/purges` gated by `CP_PURGE_ADMIN_TOKEN` (a **stronger** credential than
the per-edge read token); auto-sourcing a `host` purge on cert rotation or Ingress
change is a natural later addition.

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
               :9187  metrics (CP_METRICS_LISTEN) — the CP's own convergence
                      metrics MERGED with every pushed edge snapshot (below)
```

### Edge metrics push (scrape the CP, not the fleet)

The edge fleet is out-of-cluster, so an in-cluster Prometheus often can't reach
each edge's `EDGE_METRICS_LISTEN`. Opt-in alternative: the edge pushes its **full
registry** (request/host/backend series + the `edge_*` convergence gauges +
`go_*`/`process_*`) to `POST /v1/metrics` on its existing authenticated CP
channel, and the CP serves every live snapshot merged into its own `/metrics` on
`CP_METRICS_LISTEN` — **one scrape target** for the CP plus the whole fleet.
`EDGE_METRICS_LISTEN` is untouched (useful for local debugging; set `""` to
close the port when pushing).

```
EDGE_METRICS_PUSH_INTERVAL   seconds between pushes; 0 (default) = disabled.
                             First tick jittered to decorrelate the fleet.
EDGE_INSTANCE_ID             per-PROCESS discriminator (default: hostname), sent as
                             X-Edge-Instance. Replicas may share one EDGE_ID/token
                             identity, so edge_id alone cannot key snapshots — the
                             CP stores and labels by (edge_id, edge_instance).
CP_EDGE_METRICS_TTL          seconds a snapshot stays served after its last push
                             (default 300; keep >= 3x the fleet push interval). A
                             dead instance's series disappear at TTL instead of
                             being served stale forever; instance-id churn stays
                             bounded the same way.
```

The CP labels every pushed series with the **token-derived** `edge_id`
(overriding any self-reported value — `EDGE_ID` should match the token's id) plus
`edge_instance`, so per-family `# HELP`/`# TYPE` blocks merge cleanly: one block,
one label set per CP/instance (the CP's own HELP/TYPE wins; a TYPE-conflicting
edge family is dropped and counted in
`parapet_edge_metrics_family_dropped_total`). Stored samples carry **no
timestamps** — Prometheus stamps at scrape time — so staleness is bounded by the
TTL plus the per-instance freshness gauge
`parapet_edge_metrics_last_push_seconds{edge_id,edge_instance}` (deleted on
eviction, so its presence implies the snapshot is still served). Push outcomes
count in `parapet_edge_metrics_push_total{status}` (CP side) and
`parapet_edge_metrics_client_push_total{result,edge_id}` (edge side). Note the
per-instance `go_*`/`process_*` series land on the one scrape target — fleet
cardinality is bounded by live instances via the TTL.

The instance id is self-reported, so the CP also caps DISTINCT instances per
edge_id (128): at the cap a new instance evicts that identity's stalest snapshot
(`parapet_edge_metrics_instance_evicted_total`), bounding memory at
tokens × cap × snapshot even if a compromised edge mints instance ids. Bodies are
capped at 8 MiB (413).

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
| `GET /v1/ratelimit` unreachable | Edge keeps last-good limits (**fail static**). Never "no limits". |
| Bad rule snapshot | All-or-nothing compile rejects the batch; previous good ruleset stays live. |
| Bad limit snapshot | All-or-nothing per set (SetLimits); previous good set — and its live counters — stays live. The etag is withheld, so the input is re-fetched, retried, and re-warned every poll rather than 304ing silently. |
| Edge compromised | Leaks its allowlisted domains' keys → **reissue/revoke those certs**; revoke the edge's token. Other edges/domains unaffected. |
| Cert rotation gap | Overlapping refresh + fail-static avoid a window where the edge has no usable cert. |
| Cache read IO error | Degrades to a cache miss (**fail static**) → served from parapet. Never errors the client request. |
| Cache dir unwritable | Cache init fails → caching disabled for the process (logged); the edge still proxies normally. |
| `GET /v1/purges` unreachable | Edge keeps its applied epochs + cursor (**fail static**); retries with backoff. Pending purges are *delayed, not lost* — the journal+cursor catch up. Stale-serving window bounded by object TTL. |
| Purge cursor gap (`since+1 < min_seq`, journal trimmed) | CP returns `flush_required` → edge bumps the global epoch (lazy flush-all) and realigns to `max_seq`. Conservative; never under-invalidates. |
| CP restart / fresh replica (in-memory journal seq resets below the edge cursor, `since > max_seq`) | CP returns `flush_required` (the cursor-ahead-of-journal check) → edge flushes and realigns its cursor **down** to `max_seq`. The edge also independently flushes on `max_seq < cursor` as defense-in-depth against an older CP. Never silently under-invalidates. |
| `purge-state` lost/corrupt | Cursor resets to 0 → next poll re-syncs (a trim gap or cursor-ahead → flush-all). Cursor + maps share **one atomic write** so they can't desync. |
| `POST /v1/metrics` unreachable | Edge keeps serving traffic (**fail static** — push is pure observability); the CP serves the last snapshot until `CP_EDGE_METRICS_TTL`, then the instance's series disappear (its `last_push_seconds` series with them). The next successful push restores everything — counters are cumulative, nothing is lost. |

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

The edge was originally **Rust/Pingora**; it was rewritten in **Go** on the
parapet framework after recurring memory bugs in pingora 0.8 (notably
cloudflare/pingora#748), letting it reuse the controller's Go libraries (`cert`,
`wafrule`, `geoip`, `parapet/pkg/waf`) and get HTTP/2 `Cookie` reassembly for
free from `net/http`. The Rust implementation has since been removed from the
repo entirely; it is recoverable from git history.

## Phasing

1. **Cert+key distribution** — controlplane `/v1/certs` (bearer authz) + edge
   in-memory cert store, timer refresh, local TLS termination, forwarding.
   **(done)**
2. **WAF distribution + edge global eval** — `/v1/waf` (global ruleset,
   `generation`), edge consumes + evaluates global, fails static. **(done)**
3. **Zones at edge** — zone-binding derivation + per-edge zone scoping + edge
   zone evaluation, with the parapet-authoritative backstop. **(done)** Zone
   resolution at the edge is **path-aware** (`route_zone_map`): the control
   plane derives the controller's own route keys from Ingress objects (host +
   path per PathType) and ships them scoped to the edge's allowed hosts,
   alongside the zone rulesets; the edge matches them on a real
   `http.ServeMux`, so resolution behaves exactly like the core — including a
   host shared by two ingresses with different paths bound to different zones
   (which the earlier host-level `host_zone_map`, still shipped for old edges,
   could not represent: one zone silently won the whole host). parapet still
   re-runs zone resolution authoritatively on its per-ingress binding (not for
   traffic the core skips via `WAF_VALIDATED_PROXY`, which accepts the edge's
   resolution — path-awareness is what makes that acceptance sound, and only
   once the CP actually serves `route_zone_map`: see the upgrade-ordering
   trade-off in the `WAF_VALIDATED_PROXY` section).
4. **Response cache** — optional disk-backed HTTP cache (`EDGE_CACHE_*`),
   honor-origin policy, LRU-bounded, restart-persistent, fail-static. **(done)**
   See [Response cache at the edge](#response-cache-at-the-edge). Edge-only (no
   parapet-core equivalent).
5. **Cache purge / invalidation** — CP purge journal + `GET`/`POST /v1/purges`,
   edge poll loop with a persisted cursor, lazy epoch invalidation (global / host /
   url / path-prefix / tag) checked at lookup via the `parapet/pkg/cache`
   `InvalidatedAfter` hook. A background reaper (`Storage.Range`) physically
   reclaims invalidated entries off the serving path; the count-cap fold + LRU byte
   cap bound the rest. Scopes: exact-URL (all variants), path-prefix (boundary-aware,
   path-only), whole-host, tag (surrogate keys from the origin's `Cache-Tag` header,
   via parapet `Meta.Tags`, host-independent), flush-all. **(done)** See
   [Purge / invalidation](#purge--invalidation). Edge-only.
6. **Rate limits at edge** — `/v1/ratelimit` (global + zone limit documents,
   `route_zone_map` from `ratelimit-zone` same-namespace bindings (path-aware,
   as in phase 3; legacy `host_zone_map` still shipped), known-hosts
   list), edge enforcement via the controller's own `ratelimitrule` runtime
   (per-edge counters, after the WAF, before the cache), fails static.
   **(done)** See [Rate limiting at the edge](#rate-limiting-at-the-edge).
