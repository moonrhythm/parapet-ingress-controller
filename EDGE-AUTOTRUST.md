# Auto-trust edge proxy (data-plane trust without a restart)

> **Status: DRAFT / design-only — not implemented.** This proposes how the
> in-cluster **core** proxy (`cmd/parapet-ingress-controller`, "parapet") comes to
> trust a newly-deployed **edge** proxy (`cmd/edge-proxy` + [`edge/`](edge/))
> automatically — without an operator editing `TRUST_PROXY` and restarting the
> core. It builds on the edge architecture in [`EDGE.md`](EDGE.md). Per
> [`CLAUDE.md`](CLAUDE.md), the behavior contract changes in [`SPEC.md`](SPEC.md)
> first; on acceptance, the contract bits (the trust predicate, the new env vars,
> the `POST /v1/edge-cert` + tokenless `GET /v1/trust-bundle` endpoints, the
> per-request order) fold into `SPEC.md` and the architecture into `EDGE.md`.
> **No cert-manager dependency:** a run-once bootstrap Job self-manages the edge CA.
> **The core no longer watches a k8s Secret for trust material; it pulls a CP-issued
> trust bundle over verified server-TLS.** The CP is the single authority for the
> SAN allow-set — there is no shared SAN-derivation package imported by both
> binaries. **The serving control plane is stateless across N identical replicas
> behind its Service (no leader election).**

## The problem

The edge sits in front of the core and sets `X-Forwarded-For` / `X-Forwarded-Proto`
(and, with a GeoIP DB, `X-Forwarded-Country` / `X-Forwarded-ASN`) so the core's WAF,
per-IP rate limits, GeoIP, and access logs see the **real client**, not the edge.
For the core to honor those headers, the edge's source must be in the core's
**trust list** — today the `TRUST_PROXY` env var (a CIDR list, or the literal
`cloudflare`).

`TRUST_PROXY` is read **once at startup**
(`cmd/parapet-ingress-controller/main.go:214-237`), compiled into a
`parapet.Conditional`, and frozen for the life of the process. So adding or
replacing an edge means:

1. Edit `TRUST_PROXY` to add the new edge's source CIDR, **and**
2. **restart the core pod** to pick it up.

Two problems, not one. The restart is operationally painful (it's the cluster's
ingress front door). And the CIDR model is brittle for the edge's actual topology:
edges run *outside* the cluster, reaching it over a tunnel / peered VPC, often
**NAT'd or autoscaling**, so the source IP the core sees is unstable and is not a
good identity.

> **Why trust is security-critical (not just plumbing).** parapet's inbound proxy
> layer calls `TrustProxy(r)` **per request** (parapet `proxy.go`). Trusted →
> honor the incoming `X-Forwarded-*`. Untrusted → overwrite them with the
> immediate peer IP. So "trust everyone" is not an option: any source the core
> trusts can **spoof `X-Forwarded-For`** to bypass IP-based WAF rules and per-IP
> rate limits, and poison GeoIP/logs. Auto-trust must therefore mean *trust
> exactly the sanctioned edges*, and that set must be **hot-reloadable**.

## The key enabler

`parapet.Conditional` is `func(r *http.Request) bool`, evaluated **per request**
(parapet `proxy.go` `ServeHTTP` → `m.Trust(r)` → `trust`/`distrust`). A closure
installed **once** at startup can read an `atomic.Pointer` to a live trust policy
that is **hot-swapped** from the trust bundle the core pulls from the control plane
(`GET /v1/trust-bundle`), via the same validate-then-swap discipline the edge's
`CpClient` fetch loop uses (`edge/cp.go`, `edge/refresh.go`) — fail-static,
all-or-nothing, never rebuilding the route mux. **No restart.** The question is only
*what credential the edge presents* and *how the core learns the live trust policy*
— and the answer to the latter is now a tokenless CP pull, not a Secret watch.

## Recommended design: edge mTLS (client-cert-as-trust)

Authenticate the **edge → core hop with mutual TLS**. Trust follows a private key,
not a source IP.

1. **A dedicated, single-purpose edge CA.** Created once and reused forever; it
   signs **nothing else**, so "chains to this CA" means exactly "is a sanctioned-edge
   credential." By default (**managed** mode) a **run-once bootstrap Job generates
   the CA once and persists it**; the serving CP only **reads** it and signs — no
   cert-manager, no out-of-band openssl. For orgs with an existing PKI, **provided**
   mode lets the operator mount their own CA (`EDGE_CA_CERT`/`EDGE_CA_KEY`) and the
   CP uses it without generating. Either way the key never reaches an edge — only
   leaf certs do. See [Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert).

2. **Each edge gets a short-lived client cert with a stable URI SAN
   `spiffe://parapet.moonrhythm.io/edge/<id>`.** The **control plane issues it** over
   the edge's existing bearer-authenticated HTTPS channel — the edge sends a CSR to
   `POST /v1/edge-cert`, the CP signs it with the edge CA and returns only the cert
   chain; the **private key never leaves the edge**, and the **CP decides the SAN
   from the token identity** (ignoring any SAN in the CSR), so a compromised edge
   cannot request a SAN it isn't entitled to. Renewal is generous (renew at ~⅓
   lifetime *remaining*) so it never races expiry — see [Edge wiring](#edge-wiring).

3. **The edge presents it** on the re-encrypt hop. `edge/forward.go`'s
   `EDGE_UPSTREAM_TLS=true` path gets the client cert via
   `tls.Config.GetClientCertificate` — a **live callback** reading the in-memory
   cert, so a renewal is picked up with **no edge restart**. A client cert can only
   ride TLS, so edge trust is conferred **only on the core's `:443` listener**; the
   plaintext `:80` listener can present none and is never mTLS-trusted.

4. **The core verifies it.** The `:443` `tls.Config` gets
   `ClientAuth = tls.VerifyClientCertIfGiven` (the cert is **optional** —
   Cloudflare-direct and browser traffic present none and complete the handshake
   unchanged) and a `ClientCAs` pool sourced from the trust bundle the core pulls
   from the CP's `GET /v1/trust-bundle` (no longer a watched Secret — see
   [Core wiring](#core-wiring)). The standard library cryptographically verifies any
   presented client cert (with `ExtKeyUsageClientAuth`) against `ClientCAs` during
   the handshake and, on success, populates `r.TLS.VerifiedChains`. A
   presented-but-unverifiable cert **aborts the handshake**.

5. **The per-request trust predicate** (installed once; see [Core wiring](#core-wiring)):

   ```
   trust(r) :=  cidrTrust(r)                                  // existing TRUST_PROXY (e.g. cloudflare)
            OR ( len(r.TLS.VerifiedChains) > 0                // a chain verified to the edge CA, AND
                 AND leafURISAN(r) ∈ liveAllowSet )           // its SAN is in the live allow-set
   ```

   The SAN check is re-evaluated **per request** against an `atomic.Pointer`-held
   allow-set fed by the CP long-poll, so **dropping a registry entry distrusts that
   edge within one debounce of the CP recompute** (sub-second normally; bounded by
   `EDGE_TRUST_CP_POLL_INTERVAL` worst-case if a long-poll wake is missed — see
   [Freshness](#freshness-long-poll-not-bare-poll)). The predicate itself is
   unchanged; only the *feed* moves.

### Single source of truth (onboard in one place)

Onboarding/offboarding touches one registry, `edge-controlplane-tokens`, whose shape
becomes `{ "<token>": { "id": "<edge-id>", "domains": [...] } }`, where `id` is an
**explicit, separate opt-in grant** of a data-plane identity. Adding an entry with an
`id` → the CP issues that edge's cert (stamping its SAN) **and** publishes the same
SAN in the allow-set; **deleting an entry = data-plane revoke** within the
convergence bound below.

The SAN allow-set is now computed in **exactly one place — the control plane**, by
the same `identityFor(id) -> spiffe://parapet.moonrhythm.io/edge/<id>` derivation
`Signer.Sign` uses to stamp the URI SAN into every issued leaf. The core no longer
derives anything: it *receives* the live `allowed_sans` already computed, over `GET
/v1/trust-bundle`. So CP-stamped-SAN == broadcast-allow-set-entry holds **by
construction within one process**, not across a cross-binary boundary — the prior
shared-package-imported-by-both-binaries hack and its split-brain risk are **gone**,
not papered over with a conformance test. Canonical form is unchanged: `<id>`
**lowercased, trimmed, NFC-normalized, validated as a SPIFFE path segment** (no `/`,
no whitespace, bounded length), **rejected fail-closed at load time** if invalid. A
serve-all (`"*"`) token gets **no** identity by default; an existing registry
migrates to no identity for every token (feature off ⇒ identical to today).

**This single-sourcing also removes the only independent cross-check**, so the CP's
allow-set correctness is now wholly load-bearing for the trust boundary: an
over-broad allow-set is a silent fleet-wide trust-widening with no second opinion.
Two guards replace the deleted cross-binary check (see [Conformance](#conformance--contract)):
(a) an **intra-process** test asserting `identityFor()` output == the SAN
`Signer.Sign` stamps for a fixed fixture; (b) a **revocation** test asserting a
known-dropped id is **absent** from a freshly-computed `allowed_sans`. `allowed_sans`
MUST be recomputed from the **same registry snapshot** that authorizes
`/v1/edge-cert` at that generation, and the generation is bumped only **after** the
new allow-set is computed. The core logs/metrics the **size + hash** of every
accepted allow-set (`parapet_trust_allowed_sans_count`, `parapet_trust_bundle_hash`)
so an unexpected widening is alertable.

## Deployment models: k8s edge vs Docker edge

There are two edge deployment shapes, and the data-plane client cert must work for
**both** with the same onboarding gesture ("provision one token"). The cert always
arrives the same way — the CP issues it via `POST /v1/edge-cert`; only how the edge
is packaged differs:

**k8s edge.** The edge runs as a Deployment in some cluster (its own or the core's).
The data-plane client cert rides `POST /v1/edge-cert` exactly as for Docker. An
operator who already runs cert-manager and wants to *mount* a client cert can still
do so via the legacy `EDGE_UPSTREAM_CLIENT_CERT`/`_KEY` file path — a mount detail on
the edge, **not a CA mode on the CP**. cert-manager is no longer part of this design.

**Docker edge (the motivating case).** The edge is a bare `docker run` on a VM / box
near clients (`deploy/edge/run-edge-docker.sh`). Its **only required input is
`EDGE_CP_TOKEN`** — no cert-manager, no CRDs, no file mounts, no manual renewal. It
already pulls its public cert+key (`GET /v1/certs`) and WAF rules (`GET /v1/waf`)
from the control plane on `EDGE_REFRESH_INTERVAL`, fail-static, keys in memory only.
The data-plane identity rides the **same channel and loop**: `POST /v1/edge-cert`,
CSR in, signed chain out, key in memory only.

| | k8s edge | Docker edge |
|---|---|---|
| Public cert+key | `GET /v1/certs` (token-pull) | `GET /v1/certs` (token-pull) |
| WAF rules | `GET /v1/waf` (token-pull) | `GET /v1/waf` (token-pull) |
| **Data-plane client cert** | `POST /v1/edge-cert` (mounted-cert file path optional) | **`POST /v1/edge-cert`** |
| Required edge input | token (+ optional mounted cert Secret) | **`EDGE_CP_TOKEN`, and nothing else** |
| Renewal | CP loop (`EDGE_REFRESH_INTERVAL`) | CP loop (`EDGE_REFRESH_INTERVAL`) |

## Core wiring

In `cmd/parapet-ingress-controller/main.go`, replace the one-shot `trustProxy`
block (`:214-237`) — but keep the existing static parse **verbatim** into a fixed
local `cidrTrust` (`"true"` → `parapet.Trusted()`; `"false"`/`""` → nil; else
`parapet.TrustCIDRs(list)` with the `predefinedCIDRs["cloudflare"]` expansion). Add a
trust-policy holder owned by the controller:

```go
type trustPolicy struct{ allowedSANs map[string]struct{} }
var trustPol   atomic.Pointer[trustPolicy]
var clientCAs  atomic.Pointer[x509.CertPool]
```

Install **one** closure, assigned to **both** servers' `TrustProxy` field:

```go
trustProxy = func(r *http.Request) bool {
    if cidrTrust != nil && cidrTrust(r) { return true }       // metric: cidr
    if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 { return false } // metric: none
    p := trustPol.Load(); if p == nil { return false }
    if requireSAN { return sanAllowed(r.TLS.PeerCertificates[0], p.allowedSANs) }
    return true // CA-only mode (EDGE_TRUST_REQUIRE_SAN=false) — forbidden with CP-issuance
}
```

`sanAllowed` matches the leaf's URI SANs *exactly* against the allow-set. The `:80`
server's `r.TLS == nil` short-circuits the mTLS branch, leaving CIDR-only.
**Only the *feed* into `trustPol`/`clientCAs` changes — from a k8s Secret watch to a
CP long-poll (next section). The per-request closure, the two atomics, `sanAllowed`,
and the `GetConfigForClient` hot-swap + self-test below are all identical to the
Secret-watch design.**

**Hot-swap `:443` `ClientCAs` without clobbering the SNI cert table** (unchanged).
Set, once, before `Serve()`:

```go
base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
    c := base.Clone()
    c.ClientCAs = clientCAs.Load()   // fresh per handshake; never nil
    return c, nil                    // carries GetCertificate = ctrl.GetCertificate (live), ClientAuth, fallback
}
```

`GetConfigForClient` must be non-nil before `Serve()` and never return nil (last-good
on error). A startup **self-test** asserts the served config carries `GetCertificate`
+ `ClientCAs` + `ClientAuth == VerifyClientCertIfGiven`. The bytes into `clientCAs`
just arrive from the CP now.

### The trust pull (tokenless CP client)

Gated by `EDGE_TRUST_CP_ENDPOINT != ""` (default off ⇒ identical to today). There is
**no 6th k8s watcher** — `controller_trust.go` and the `watchResource[*v1.Secret]`
trust invocation are gone. Instead a new tokenless `TrustCpClient` (a new small file,
e.g. `trust/client.go`) mirrors `edge/cp.go`'s `CpClient` minus the `Authorization`
header: `http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}` whose
`tlsConfig.RootCAs` is built from `EDGE_TRUST_CP_CA` via
`x509.NewCertPool().AppendCertsFromPEM`. `FetchTrustBundle(sinceGen, etag)` builds
`base + "/v1/trust-bundle?watch=1&since=<sinceGen>"`, sets `If-None-Match`,
body-capped `json.Decode` into `{generation, ca_pem, allowed_sans}`, returns
`Unchanged` on 304 and an error on any non-200/304 (caller fail-statics).

**Deliberate inversion of `edge/cp.go`:** that client silently ignores an unparseable
CA and falls back to system roots (`edge/cp.go:42-47`); for the trust channel that is
**forbidden**. A missing / empty / unreadable / unparseable `EDGE_TRUST_CP_CA`, or an
`AppendCertsFromPEM` that adds **zero** certs, is a **FATAL startup error** when
`EDGE_TRUST_CP_ENDPOINT` is set. `InsecureSkipVerify` is **never** set; a startup
self-test asserts `tlsConfig.RootCAs != nil && !tlsConfig.InsecureSkipVerify` (carry a
code comment naming this inversion so a future client-unification refactor cannot
re-introduce the fallback). A non-`https://` endpoint is rejected fatally — **no
plaintext analog, ever** (contrast the edge data plane's `EDGE_CP_ALLOW_PLAINTEXT`).
Server-cert **identity**, not merely chain-to-CA, is the boundary: `EDGE_TRUST_CP_CA`
SHOULD be a **dedicated single-purpose CA that signs only the CP server cert**; the
client verifies the CP cert hostname against the endpoint host (Go's default
`ServerName`-from-dial-host, never loosened); a shared org CA is loud-warned.

A single **long-poll refresh goroutine** (mirroring `RunCertRefresh` but blocking, not
ticking) calls `FetchTrustBundle`. On a good 200 it does the **same validate-then-swap,
all-or-nothing** the old Secret watch did: parse `ca_pem` into an `x509.CertPool`
(**reject a non-empty-input-that-yields-zero-certs bundle**, keep last-good, bump
`parapet_trust_reload_rejected_total`), build the `allowedSANs` set, **reject any
bundle whose `generation` <= the one currently held** (forward-only, bump
`parapet_trust_rollback_rejected_total`), then atomically `Store` **both** `clientCAs`
and `trustPol` together. On 304/timeout it re-issues with the unchanged `since`; on
connection drop/error it fail-statics (keep last-good), short jittered backoff,
re-issues. **NEVER nil the live pool from a bad/empty/forged fetched bundle** — only
feature-off does. An empty `allowed_sans` with a valid `ca_pem` is accepted as an
operator-driven shrink **only when the generation strictly advances**, so a
truncated/forged body cannot masquerade as an empty set.

### Freshness: long-poll, not bare poll

A bare poll would make revocation as slow as the poll interval; the old k8s watch gave
~300 ms. To keep that, `GET /v1/trust-bundle` supports a **long-poll**:
`?watch=1&since=<generation>` **blocks** server-side until the generation advances past
`<since>` (a registry edit → recompute → bump → broadcast, or a CA rotation step) or a
server-side ceiling (`EDGE_TRUST_CP_WATCH_TIMEOUT`, default ~30 s) elapses → `304`. CP
side: a `generation` (see [Generation](#generation-content-derived-replica-identical--monotonic))
bumped on every **observed content change**, with a `sync.Cond` broadcast to wake
blocked waiters. The SAN set is serialized **deterministically** (sorted,
NFC-normalized) before the gen/etag hash, so non-deterministic map iteration cannot
compute a spuriously-unchanged etag and stall the bump (the `WafStore.recompute`
early-return on equal etag is correct only because its `fingerprint` is sorted —
`wafstore.go:86-94`; the trust bundle MUST do the same).

The core: on **200** → validate-then-swap, advance `since` to the returned (strictly
greater) generation, re-issue `watch=1&since=<new>`; on **304/timeout** → re-issue
unchanged; on error → fail-static + jittered backoff + re-issue. **Liveness:** the
watch call MUST NOT use a whole-request `http.Client.Timeout` (it would guillotine a
legitimately-blocking long-poll); use Transport-level `ResponseHeaderTimeout`/
`IdleConnTimeout` + a per-attempt context deadline of `watch-timeout + slack` (~45 s
for a 30 s block) + TCP keep-alive, so a half-open connection is detected and the
single watch goroutine never wedges. The CP `http.Server` `WriteTimeout`/`IdleTimeout`
MUST be **>= the watch ceiling** (today only `ReadHeaderTimeout` is set,
`cmd/edge-controlplane/main.go:103`). **The safety-net plain-GET poll
(`EDGE_TRUST_CP_POLL_INTERVAL`, default 5 m) runs unconditionally alongside the
long-poll** as a correctness backstop. Honest SLA: **sub-second normally, ≤ one poll
interval worst-case** — never present sub-second as guaranteed.

### Generation (content-derived, replica-identical + monotonic)

The revocation guarantee rests on the generation being **strictly monotonic and
tamper-evident over the verified TLS channel**, *and* (for a stateless multi-replica
CP) **identical on every replica**. Both are satisfied by deriving generation from the
**apiserver `resourceVersion`** of the source objects — `generation = max(resourceVersion)`
across the source Secrets/ConfigMaps (the `edge-controlplane-tokens` registry and the
`parapet-edge-ca` Secret). resourceVersion is the etcd revision at last write; etcd is a
**single global monotonic counter**, so this value is server-assigned (identical on
every replica reading the same objects), monotonic, and **persisted across CP restarts
by construction** — it lives in etcd, not a CP process. This **dissolves the apparent
conflict** between "content-derived/stateless" and "monotonic/persisted": one source
satisfies both. Do **not** use a per-process `atomic.Uint64` counter (replica-divergent)
nor leading bytes of a content hash (non-monotonic; truncation collisions).

Three rules: (1) **Forward-only swap** — the core rejects any bundle whose
`generation <=` the one it holds (`parapet_trust_rollback_rejected_total`), so a MITM
on any TLS gap can't replay a captured **older** 200 to un-revoke a dropped SAN. (2)
**No reset** — because generation is an etcd revision, a CP restart never lowers it, so
a core holding `since=N` is never stranded. (3) **Equality/identity token** — anti-rollback
rests on server-TLS + forward-only, not on the value being a dense counter.

> **Pre-existing bug fixed here:** `edgecp/wafstore.go:32` `gen atomic.Uint64`, bumped
> at `:80`, returned at `:124` into `wafResponse.Generation` — under `replicas: 2` two
> replicas ingesting identical ConfigMaps return *different* generation integers, so an
> edge round-robining the Service sees the counter flap (e.g. 7,4,8,4). The fix applies
> the **same** resourceVersion-derived generation to `/v1/waf`; the sha256 fingerprint
> at `wafstore.go:86` stays for the ETag (already content-derived + replica-safe).

### Warm-start cache (fail-closed for revocation)

A core restart during a CP outage loses its in-memory `clientCAs`/`trustPol` and would
otherwise degrade to CIDR-only until the CP returns. To shrink that window the core
**persists the last-good bundle to `EDGE_TRUST_CP_CACHE_FILE`** (write-on-successful-swap;
the bundle is public — `ca_pem` + opaque SAN ids — so **no new secret-at-rest concern**).
**But the disk copy confers NO trust until revalidated against the live CP.** A restarted
core with the CP down reads the file as a **warm-start hint only**, stays **CIDR-only**,
and flips to mTLS-trust **only after the first successful live fetch supersedes it**.
This is deliberate and fail-closed: persisting-**and-trusting** the file would resurrect
a revoked SAN (revoke X → CP down → core restarts → reads a disk bundle still containing
X → X trusted across the whole outage). `EDGE_TRUST_CP_MAX_STALE` (default ~1 h) caps the
hint's age; an older file is ignored. Emit `parapet_trust_source{file}` (vs
`{mtls}`/`{cidr}`/`{none}`) and `parapet_trust_bundle_age_seconds` so a stale/pre-bundle
core is alertable. **No-trust-until-revalidated is the default and is non-negotiable.**

**Header hardening (a real gap today):** mount a middleware **first** in `main.go`'s `m`
chain that **unconditionally deletes** client-supplied `X-Forwarded-Country` /
`X-Forwarded-ASN` at ingress (`forwardGeoHeaders`, `main.go:329`, only *overwrites* them
when a DB is loaded → a no-DB core passes a client-forged value upstream). Treat both as
edge-set-only.

## Edge wiring

The default data-plane identity is **CP-issued**. `EDGE_DATAPLANE_MTLS` (bool, default
false — off ⇒ anonymous re-encrypt, identical to today) turns it on; `EDGE_UPSTREAM_TLS=true`
is a prerequisite (loud startup error otherwise).

- **`edge/clientcert.go` (new)** — an in-memory `ClientCertStore`
  (`atomic.Pointer[tls.Certificate]`), `GetClientCertificate` returns the live
  (complete key+chain) cert, and an **all-or-nothing** `Update(chainPEM, heldKey)`
  that `tls.X509KeyPair`-validates and atomically swaps — **if validation fails, the
  prior pair is kept** (never a half-rotated state). A never-loaded empty return is
  loud and gates readiness.
- **`edge/refresh.go`** — `RefreshEdgeCertOnce`: generate an ephemeral key **into a
  local var**, build the CSR, `cp.FetchEdgeCert(...)`, on success `Update` as one
  atomic unit, on error fail-static. `RunEdgeCertRefresh` renews on
  remaining-life/renew-before with backoff + **jitter**, honoring `Retry-After`.
- **`edge/forward.go` `NewForwarder`** gains a `*ClientCertStore` param (nil ⇒
  anonymous re-encrypt); on `useTLS` it sets
  `tlsConfig.GetClientCertificate = ccStore.GetClientCertificate`. `InsecureSkipVerify`
  stays for now (the edge doesn't yet verify the core's server cert — see open
  questions). **This is the deliberate mirror image of the trust channel:** the edge
  data-plane hop is authenticated by the edge's *client* cert and still skip-verifies
  the server; the core→CP trust channel is authenticated by the CP's *server* cert with
  no client cert and **never** skip-verifies. Same binary pair, opposite posture, by
  design.
- **Readiness is fail-closed.** When `EDGE_DATAPLANE_MTLS=true`, readiness
  (`cmd/edge-proxy/main.go:197`) becomes `(serveAll || store.Loaded()) && clientCert.Loaded()`
  — serve-all does NOT bypass it. First-boot issuance failure keeps the edge not-ready
  (503). **But CP-readiness ≠ system-readiness:** the edge can't self-detect "the core
  doesn't trust my CA," so it can go ready and still 502 in the convergence window — see
  the system-readiness fail mode.

The edge remains the first hop and sets **no** `TrustProxy`, so it overwrites incoming
`X-Forwarded-*` with the true client peer before forwarding — the **transitive-trust
invariant** the core relies on.

## Control-plane wiring: CP issues the client cert

### Stateless serving control plane (HA via replicas + Service)

The serving CP holds **no control-plane-owned state**: every input (the edge-CA keypair
from `parapet-edge-ca`, the `edge-controlplane-tokens` registry, tenant TLS via the
`Reloader`, WAF via `WafReloader`/`IngressReloader`) is read from the apiserver into a
derived, reconstructible cache, so replicas are **byte-identical and interchangeable**.
HA is the existing ClusterIP Service over N pods with the `/healthz?ready=1` gate; the CP
is **off the request path** (edges/core pull on timers/long-poll, fail-static), so losing
a replica only delays a pull, never drops live traffic. **No leader election, no lease, no
in-serving CAS, no write RBAC.** Signing is deterministic and stateless per request:
zero-value leaf template + fresh 128-bit CSPRNG serial + clock-derived validity +
registry-derived SAN, so two replicas signing the same CSR produce equally-valid,
differently-serialed certs. Multiple concurrently-valid serials per SAN (one per replica
that served a renewal) are **expected**, because revocation is SAN-drop in the core, not
serial/CRL. This subsection replaces the in-serving create-once/CAS/anti-regen machinery
that previously lived here — that machinery moves into the bootstrap Job below.

### `GET /v1/trust-bundle` — the tokenless trust endpoint

New handler on `edgecp.Server.Handler()` (`edgecp/server.go:30-36`), mounted **alongside**
the token-gated `GET /v1/certs`/`GET /v1/waf` but a sibling of the **no-auth**
`GET /healthz` — it **never inspects `Authorization`**:

```
GET /v1/trust-bundle    (NO Authorization header)   [If-None-Match: "<etag>"]   [?watch=1&since=<generation>]
  200 {"generation": N, "ca_pem": "<edge-CA PUBLIC cert bundle, PEM>", "allowed_sans": ["spiffe://parapet.moonrhythm.io/edge/<id>", …]}
       generation   : resourceVersion-derived, replica-identical + monotonic; bumped whenever ca_pem OR allowed_sans changes
       ca_pem       : the edge CA PUBLIC cert(s) ONLY (overlap bundle old++new during rotation). NEVER a private key.
       allowed_sans : the live allow-set, CP-computed from edge-controlplane-tokens via the single canonical identityFor derivation
       ETag: "<strong validator over generation || ca_pem || sorted(allowed_sans)>"   Content-Type: application/json   Cache-Control: no-cache
  304 (If-None-Match matched OR a ?watch long-poll elapsed with no generation change)
  503 (signer/CA not yet initialized — bootstrap Job hasn't populated the CA; core fail-statics and retries)
```

New `edgecp/trust.go` + `mux.HandleFunc("GET /v1/trust-bundle", s.handleTrustBundle)`. The
handler: (1) **no `bearer(r)` call**; (2) computes `allowed_sans` from the **same
`edge-controlplane-tokens` registry** the CP authorizes against, via the canonical
`identityFor` (the **same** code path `Signer.Sign` stamps with — byte-identical by
construction); (3) assembles `ca_pem` as the **public** cert(s) only from the live
`Signer`; (4) reads the resourceVersion-derived generation + a `sync.Cond` for the
long-poll, `ETag = etagOfString(...)` (`server.go:130`). Wired like `WithWAF`: a
`WithTrust(...)`, so **absent signer ⇒ 503** (the endpoint *exists* but is not-yet-ready
— 503, not 404, so the core retries rather than treating it as permanent). No new CP
watch — the trust bundle is a new **view** over state the CP already maintains. There is
**no 401/403 path**.

### Bounding the unauthenticated long-poll

Because `/v1/trust-bundle?watch=1` is **unauthenticated** and **blocks a goroutine +
connection** for up to the watch ceiling, the CP **cannot bound concurrency by caller**.
Any NetworkPolicy-permitted source could otherwise open thousands of concurrent watches
and exhaust the goroutine/FD budget, **starving the token-gated `/v1/certs`/`/v1/waf`/
`/v1/edge-cert` the data plane needs**. So the CP MUST add **auth-independent** limits: a
**bounded semaphore** on concurrent in-flight watch handlers (over-limit ⇒ `503` +
`Retry-After`, or short-block then `304`); a **hard server-side deadline** via `context`
(≤ the watch ceiling); a **per-source-IP concurrent-connection cap**; a response **body
cap**; and a cheap reject of `?watch` with an absurd/missing `since`. **The
edge-sources-only NetworkPolicy is now availability-load-bearing** (the only caller bound
on this endpoint) — a hard prerequisite — and the CP `http.Server` MUST set
`WriteTimeout`/`IdleTimeout` ≥ the watch ceiling.

### CP-side TLS guard (no plaintext trust channel, either end)

The no-token decision is safe **only because server-TLS is the integrity boundary** — so
it MUST be non-optional on the CP **server** side too. The CP today serves plaintext when
`CP_TLS_CERT`/`CP_TLS_KEY` are both empty (`cmd/edge-controlplane/main.go:40-51`). **When
the CP is a trust source (the trust bundle is wired), `CP_TLS_CERT`/`CP_TLS_KEY` MUST be
set — plaintext + trust-bundle is a FATAL CP startup error**, mirroring the existing
`CP_TLS` pairing guard. The edge **data-plane** plaintext exception (`EDGE_CP_ALLOW_PLAINTEXT`)
does **NOT** extend to the trust channel on **either** end: an on-path attacker on a
"trusted" private network who injects a forged `ca_pem` over plaintext mints leaves the
core trusts = fleet-wide XFF-spoof = trust-boundary takeover.

### The issuance endpoint (`POST /v1/edge-cert`)

CSR-based, so the private key **never leaves the edge**:

```
POST /v1/edge-cert    Authorization: Bearer <token>
  request body: {"csr_pem": "<PKCS#10 CSR, PEM>"}
  200 {"chain_pem":"…", "not_after":"<RFC3339>", "serial":"<hex>"}   (NO key on the wire; Cache-Control: no-store, Pragma: no-cache; no ETag/304)
  400 (malformed/oversized CSR, bad PEM, sig fails verify, unsupported/over-large key type)
  401 (no/invalid token)  403 (token has no edge identity grant)  405 (not POST)  413 (CSR > 16 KiB)  429 (rate limit / signer saturation — Retry-After)
```

The edge generates an ephemeral key in memory, sends the CSR; the CP **whitelists the key
type/curve BEFORE `CheckSignature`** (ECDSA P-256/P-384 or Ed25519 only; reject RSA → 400),
verifies proof-of-possession, then `Signer.Sign(csr.PublicKey, authorizedSAN)`. Absent
signer ⇒ 404 (back-compat).

### Signing: template, custody, rate-limiting

**`edgecp/signer.go` (new).** `Signer` holds the parsed edge CA cert + key (behind an
interface — the **HSM/KMS seam**); `Sign` builds the leaf template **from a zero value —
never from the parsed CSR** — setting ONLY `SerialNumber` (128-bit CSPRNG), `NotBefore =
now - EDGE_CLIENTCERT_SKEW`, `NotAfter = now + EDGE_CLIENTCERT_TTL`, `KeyUsage =
DigitalSignature`, `ExtKeyUsage = [ClientAuth]`, `URIs = [authorizedSAN]`,
`BasicConstraintsValid = true, IsCA = false`. The CSR contributes **only `csr.PublicKey`**.
**Post-sign self-check (mandatory in BOTH modes):** re-parse the leaf and assert
`IsCA==false`, `KeyUsage`, `ExtKeyUsage==[ClientAuth]`, `URIs==[authorizedSAN]`, no
DNS/IP; refuse to return otherwise.

**`edgecp/authz.go` — per-edge identity (explicit opt-in).** `Identity(token) (string,
bool)`; returns `("",false)` (→ 403) unless the operator set an `id`. Serve-all gets none.

**CA custody — managed (default) vs provided.** Two modes, decided at boot by the
**presence** of `EDGE_CA_CERT`/`EDGE_CA_KEY` (no `EDGE_CA_MODE` knob):

- **`managed` (default — zero PKI, zero cert-manager).** A **run-once bootstrap Job**
  generates the CA once and persists it to `parapet-edge-ca`; the serving CP **reads** it
  and hot-reloads it, **never generates or writes**. The generated CA template (from a
  zero value): key **ECDSA P-384** (`EDGE_CA_KEY_TYPE=ed25519` alt), PKCS#8; `SerialNumber`
  128-bit CSPRNG; `Subject` CN `parapet-edge-ca`; `NotBefore = now-10m`, `NotAfter = now +
  EDGE_CA_TTL`; `KeyUsage = CertSign | CRLSign` ONLY; `ExtKeyUsage = [ClientAuth]` ONLY;
  `BasicConstraintsValid=true, IsCA=true, MaxPathLenZero=true`;
  `NameConstraints.PermittedURIDomains = ["parapet.moonrhythm.io"]`. **Honest scope:** this
  pins the SAN **host** only — path scoping to `/edge/*` is *not* expressible as a URI
  NameConstraint (the issuance template's `URIs=[authorizedSAN]` + post-sign self-check pin
  the path); the constraint stops cross-domain/serverAuth abuse, NOT edge-fleet
  impersonation. A conformance test must prove `x509.Verify` rejects
  `spiffe://evil.example/edge/x` and accepts the legit form. The **Job** logs it
  GENERATED/ADOPTED a fleet-minting CA; the **serving** CP logs it HOLDS a loaded signer
  (read-only).
- **`provided` (escape hatch — operator's own PKI).** Both `EDGE_CA_CERT`/`EDGE_CA_KEY`
  point at mounted PEM files; the CP **uses** them, never generates/writes, needs no
  get/update RBAC; hot-reload the files. **Validation (mandatory):** `IsCA` + EKU
  `clientAuth` (reject pure serverAuth/anyEKU); **warn loudly (or refuse) if no
  `NameConstraints.PermittedURIDomains`**. Dedicated single-purpose CA, never a shared org
  intermediate. cert-manager may *populate* the mounted Secret, but the CP sees opaque
  files — no CRD, no `CertificateRequest`.

**`cmd/edge-controlplane/main.go`.** Branch **FIRST** on `EDGE_CA_BOOTSTRAP` /
`--bootstrap-ca`: if set, run `EnsureCA` against `parapet-edge-ca` in `POD_NAMESPACE` then
`os.Exit(0 success / non-zero failure)` — **never start the server**. Else serving mode:
managed = `GetSecret`+parse to a `*Signer` and start the CA-Secret **read-watch**; provided
= mounted files; neither = nil signer = 404. Both-or-neither `EDGE_CA_CERT`/`EDGE_CA_KEY`
guard. Empty `POD_NAMESPACE` is **fatal** in bootstrap mode and serving-managed mode.
**Serving no longer calls `EnsureCA`/`UpdateSecret`.**

**Rate-limiting + DoS.** The per-token bucket (`EDGE_CLIENTCERT_RATE`) and the global
signing concurrency cap are **PER-REPLICA** — with N replicas behind the Service the
effective fleet ceiling is **N× nominal**, and it scales **silently** as replicas rise for
HA. Document this; a truly hard global cap needs externalized rate-limit state (out of
scope, same exception class as the purge journal). authz-reject + the key-type whitelist
run **before** any signing, so unauthorized/oversized floods cost zero CA work; keep
per-edge refresh jitter.

### CA generation: the run-once bootstrap Job (single intentional writer)

CA generation runs in the same `edge-controlplane` binary in one-shot mode
(`--bootstrap-ca` / `EDGE_CA_BOOTSTRAP=true`) running `edgecp.EnsureCA`, then exit 0
(success/adopt) or non-zero (Job retries). Pure-Go x509, no cert-manager. Operator
pre-creates an **empty** `parapet-edge-ca` stub (RBAC `resourceNames` scopes get/update but
not create). `EnsureCA` on a strongly-consistent typed `GetSecret` (never an informer
cache):

- **(a)** `tls.crt`+`tls.key` parse to a valid CA keypair → **ADOPT**, exit 0 (re-run is a
  pure no-op).
- **(b)** guard annotation `parapet.moonrhythm.io/edge-ca-generation` present but
  `tls.crt`/`tls.key` empty-or-unparseable → **HARD ANOMALY** (a populated CA was
  re-blanked by a GitOps prune, an apply of the empty stub, a Velero restore, or an
  operator recreate) → **NEVER regenerate**, exit non-zero with a distinct message, bump
  `parapet_edge_ca_unexpected_empty_total`.
- **(c)** virgin stub (no annotation **and** empty) → generate the CA in memory and write
  keypair + guard annotation + populated-at timestamp together.

> **Override of the brief (both red-team rounds, unanimous):** a k8s Job is **not** a
> guaranteed single writer — node-loss double-run, delete-recreate on redeploy/Helm/Argo,
> and manual re-apply all produce transient concurrent Job pods. So **RETAIN the
> `resourceVersion`-CAS** on the write plus a **re-read-immediately-before-Update
> no-op-if-now-populated** check: without the CAS two pods both observing the empty stub
> both `UpdateSecret` last-write-wins → two different CAs → the second silently distrusts
> everything signed against the first. On `apierrors.IsConflict` re-read and **ADOPT** the
> winner. The Secret-is-the-lock property (the CAS, not statelessness) linearizes the
> inevitable double-run. The **anti-regeneration guard** is the load-bearing safety
> property and now lives in the Job.

`NotFound` on the stub is a **fatal config error** (no fallback to a broad create grant).
Empty `POD_NAMESPACE` is fatal. **Failure semantics:** exit non-zero on any failure to
reach a known-good terminal state; **re-GET after `UpdateSecret` and assert the CA parses
before exit 0** (no swallowed write error, no silent no-op Complete). The create-once is
tested against `k8s.io/client-go/kubernetes/fake` (honors CAS) with a two-goroutine
concurrent-generate test asserting exactly one CA survives and the loser adopts.

### Bootstrap-Job vs serving-Deployment ordering (the cold-start window)

Job-before-serving is a **HARD ordering requirement**, not a should. Preferred: ship the
Job as a **Helm pre-install/pre-upgrade hook** (hook-weight before the Deployment) AND/OR
an **Argo PreSync hook**, preferred over an initContainer (which re-runs on every pod
restart/scale-up and would need write RBAC on the serving SA, defeating read-only-serving).
Belt-and-suspenders: serving readiness stays gated on a loaded CA, so even if ordering
slips no replica serves a CA-less 404. **Cold-start no-signer window:** until the Job
populates the CA, all serving replicas read no CA, all stay **not-ready (503)**, the
Service has zero endpoints, `POST /v1/edge-cert` is connection-refused, the trust-bundle
has no `ca_pem`. Edges **fail-static on their last-good leaf** (degraded, never fail-open);
brand-new edges get no-endpoints. Bounded by Job completion; unbounded only if the Job is
slow/failing (hence the Job-Failed alert + the absence-of-populated-CA-after-deadline
alert). On the core side: a trust-bundle returning no `ca_pem` MUST be treated as
**not-yet-bootstrapped** (keep retrying, never cache empty as last-good, never permanently
latch CIDR-only; self-heal on the first non-empty pull).

### Where the core gets the CA (the CP serves it; the core never reads the Secret)

The core **no longer reads the `parapet-edge-ca` Secret at all** — not the public cert, not
(incidentally) the private key. It pulls the edge CA's **public** cert(s) as `ca_pem` from
`GET /v1/trust-bundle`, alongside the `allowed_sans` the CP computes. `EDGE_TRUST_SECRET`
is **removed**; the core needs **zero** k8s access for trust (the fetch is an outbound
HTTPS call). Because the core never touches the CA Secret, **`parapet-edge-ca` can live in
a CP-only namespace with the CP as its only reader** — the prior namespace co-tenancy that
let the core SA read the CA *private* key is **eliminated, not deferred** (see
[Security model](#security-model)). The cert the CP signs **with** and the cert the core
**trusts** are still the same bytes from the same authority — the CP assembles `ca_pem`
directly from its live `Signer` (the overlap bundle old++new during rotation) — so they
cannot drift, with **no publish step and no second write target**. The old namespace
invariant tying the core's trust to `POD_NAMESPACE` is **dropped**.

### CA hot-reload + rotation (Job-driven, bundle-based, no cert-manager)

**The serving signer is hot-reloadable, not boot-once.** Every serving replica runs the
**CA-Secret read-watch** (`atomic.Pointer[*Signer]`, validate-then-swap; active key derived
solely from Secret content `tls-active: old|new`, converge within one debounce), so a
Job-driven rotation is picked up without restart. A boot-once read would leave a replica
signing with a stale in-memory key — strictly worse across N replicas with no leader. On a
runtime CA-Secret **DELETE/blank**, the replica **keeps its last-good in-memory signer**,
alerts, and **never drops to no-signer** (mirrors the core trust-watch keep-last-good) —
with the in-serving anti-regen guard now removed, this read-watch keep-last-good is the only
in-process safety net against a blanked Secret.

**Rotation is a run-once Job** (the `--bootstrap-ca` binary / a rotate subcommand), **NOT**
leader-elected serving. **Rotation invariant:** the NEW CA's public cert must be in
`ca_pem` (which the core trusts) BEFORE the CP signs any leaf with the new key — else fresh
leaves 502. Bundle support (`AppendCertsFromPEM` appends every block) lets `tls.crt`/`ca_pem`
hold an overlap bundle. The 4-stage promote/trim machine: (1) generate NEW; (2) write
`tls.crt = OLD ++ NEW`, stage NEW key, keep OLD active → core trusts both; (3) keep signing
OLD while leaves renew; (4) flip `tls-active: new`, keep both certs ≥ one full leaf-TTL,
then trim OLD — gated on the per-serving-replica `parapet_edge_ca_signer_fingerprint`
convergence interlock. **Stolen-CA-key emergency:** skip overlap, write only the new CA,
accept the brief gap — this is the stolen-CA-key runbook (SAN-drop can't revoke a forged
leaf riding a real SAN).

### k8s client: the first write path (Job-only)

The `k8s` client is read-only today (`Get*`/`Watch*`). Managed mode adds `GetSecret` +
`UpdateSecret` to the interface and both backends — but **`UpdateSecret` is invoked SOLELY
by the bootstrap/rotation Job, never by serving, never by the core**. Serving managed uses
`GetSecret` read-only at boot then the read-watch. Import `apierrors` for
`IsConflict`/`IsNotFound`. No `CreateSecret` (the stub is pre-created; `NotFound` is
fatal-config). `EnsureCA` is **idempotent** (re-run after a CA exists is a pure adopt).

## Deployment & RBAC (self-managed CA, two ServiceAccounts)

1. **Two SAs.** `edge-controlplane` (serving, **read-only**) and
   `edge-controlplane-bootstrap` (the Job, scoped write). The serving CP **stops** reusing
   the controller's SA.
2. **`controlplane.yaml`:** `serviceAccountName: edge-controlplane` (read-only); add
   `POD_NAMESPACE` via downward API `metadata.namespace`; hardened `securityContext`
   (`readOnlyRootFilesystem`, `runAsNonRoot`, `allowPrivilegeEscalation: false`); the
   `readinessProbe` comment updated to "503 until the cert store **and** (when issuance
   enabled) the CA signer have loaded"; `replicas` now safe to raise freely.
3. **`role-ca.yaml`** — namespaced Role with secrets `get, update` scoped to
   `resourceNames: [parapet-edge-ca]` in `POD_NAMESPACE`, bound to the **Job SA only**
   (never namespace-wide, never create, never delete). The serving SA does **not** get it.
4. **Cluster-wide read rebind:** because the serving CP runs `WATCH_NAMESPACE=""`
   (cluster-wide tenant-cert Reloader), the **serving** SA keeps a ClusterRoleBinding to the
   existing read ClusterRole — a namespaced RoleBinding alone silently breaks cert
   distribution. The Job SA needs no cluster-wide read.
5. **`ca-secret.yaml`** — the pre-created **empty** `parapet-edge-ca` stub in a **CP-only
   namespace** (the Secret, the Role, the RoleBinding all live there; no core workload
   occupies it → full CA-key-read isolation as the **default**). MUST carry GitOps
   drift-exclusion (`argocd.argoproj.io/sync-options: Prune=false` + `ignoreDifferences` on
   `/data` and `/metadata/annotations`; Flux field-manager note).
6. **The core keeps** its namespace-wide secrets list/watch (for SNI) but reads **nothing**
   from `parapet-edge-ca` — trust arrives over `GET /v1/trust-bundle`. **Zero new core
   RBAC**, and `EDGE_TRUST_SECRET` is gone. The core's only new config is
   `EDGE_TRUST_CP_ENDPOINT` + the mandatory `EDGE_TRUST_CP_CA` (the CP **server** CA,
   distinct from the edge CA in `ca_pem`).
7. **`bootstrap-job.yaml`** — `completions: 1`, `parallelism: 1`, `restartPolicy: OnFailure`,
   finite-but-generous `backoffLimit`, `ttlSecondsAfterFinished` (reap a Completed Job
   before the next sync recreates it), `POD_NAMESPACE` via downward API, sequenced before
   serving via the pre-install/PreSync hook.
8. **RBAC self-probes:** the serving CP probe-Lists secrets in `WATCH_NAMESPACE`; the Job
   probe-Gets the CA Secret; on 403 each fatal-logs the exact missing binding.
9. **etcd encryption-at-rest** is a managed-mode prerequisite (the CA key now lives in a
   Secret written by the Job and read by every serving replica); a Secret loss = forced CA
   rotation (overlap runbook).

## Security model

**Trust boundary.** Exactly the edges holding a private key whose cert chains to the
dedicated edge CA **and** whose URI SAN is in the live allow-set. Trust is
**operator-asserted**. mTLS trust is conferred **only on `:443`**.

**Spoofing.** A non-edge reaching `:443` cannot forge trust (`VerifiedChains` is populated
only after cryptographic verification against `ClientCAs`). A compromised edge cannot
request a SAN it isn't entitled to (the CP stamps it from the token identity).

### Why the trust endpoint drops the token (and the others keep it)

A bearer token authenticates the **client to the server** ("who is calling"); it does
**not** protect **response integrity** ("is what I got back genuine"). The trust bundle is
read-only and **non-secret by nature**: `ca_pem` is a *public* CA cert, and `allowed_sans`
is at worst mild fleet-recon (opaque ids), already bounded by the CP's ClusterIP +
edge-sources-only NetworkPolicy. What the core needs protection against is a **forged**
CA/allow-set — a trust-boundary takeover. The defense against forgery is **server-side TLS
the core verifies**, *not* a token the core *sends*. So the token on `/v1/trust-bundle` was
pure ceremony; dropping it removes one credential the core would hold/rotate/leak, with
**zero security loss, provided server-TLS verification stays mandatory and non-skippable**.
**The other endpoints KEEP their token, deliberately:** `GET /v1/certs` ships **private
keys**, `GET /v1/waf` ships **per-edge-scoped** rules (the scoping *is* the bound), `POST
/v1/edge-cert` **mints identity** — all serve secret or caller-scoped material and need to
authenticate *which* edge is calling. Only `/v1/trust-bundle` — broadcast-public, same
bytes for everyone — can safely drop it.

**Blast radius.** A leaked edge **leaf** key lets the holder spoof XFF **as that one edge**
until its SAN is dropped or its cert expires. The **crown jewel is the edge CA key**. The
bootstrap Job **GENERATES** it (once ever); serving replicas only **read/HOLD** it.
**CA-key isolation is now the default, not a wart:** the core never reads the
`parapet-edge-ca` Secret — it pulls only the public `ca_pem` — so the CA Secret lives in a
**CP-only namespace** with the dedicated CP SA as its sole reader; the prior concession
that the core SA could read the CA *private* key via namespace co-tenancy is **eliminated**.
The CP still concentrates risk (cluster-wide read of all tenant TLS keys via
`WATCH_NAMESPACE=""` **and** the fleet-minting CA key — pin `WATCH_NAMESPACE` to shrink
this), and **a stolen CA key still forges the entire fleet** (NameConstraints + EKU stop
only cross-purpose abuse, NOT impersonation — a forged leaf rides a real SAN, so per-request
SAN-drop can't revoke it), bounded **only by CA rotation**. Statelessness pushes all CA
durability onto etcd, so the read-watch keep-last-good in every serving replica is the only
in-process safety net against a re-blank. The new wrinkle: `allowed_sans` is broadcast
unauthenticated — **not** a security property; the ids are opaque, confer no capability
without a CA-chained key, are at worst mild recon; **operators MUST NOT encode secrets in
edge ids**, and the NetworkPolicy keeps the surface bounded.

**Fail-default: fail-closed.** A CP **unreachable at first boot** ⇒ `trustPol` nil ⇒ mTLS
branch false ⇒ edges distrusted (degraded-but-safe), CIDR/Cloudflare branch unaffected. A
bad/forged/empty/zero-cert `ca_pem` ⇒ validate-then-swap **rejects** and keeps last-good
(never nils the live pool). A **steady-state CP outage never drops existing trust** (fail-
static); only trust *changes* stall. A **persistently-unreachable CP MUST surface as a
loud, alerting condition** (`parapet_trust_source{none}` stuck pre-bundle), never a quiet
permanent degrade. **No path fails open.**

**The explicit tradeoff.** This forces re-encrypt TLS, a PKI lifecycle, and the CA key
living in-cluster. An expired edge cert hard-fails the handshake (502s); the CP-outage
budget (= `EDGE_CLIENTCERT_TTL` × renew-before-fraction) must exceed the CP recovery SLO.
It also adds a steady-state runtime dependency **for trust *changes* only** (core→CP to
onboard or revoke); steady-state trust of already-known edges is fail-static and
CP-independent. The trust feed must be **at least as available as the apiserver/watch-cache
it replaced** — so **CP HA (≥2 replicas behind the ClusterIP) is REQUIRED**, and the core
persists a warm-start cache (no-trust-until-revalidated) so a restart during a CP outage
does not distrust the fleet. There is **no leader to fast-recover** — N stateless replicas
+ the Service is the recovery story.

## Fail modes

| Failure | Behavior |
|---|---|
| Bootstrap Job not yet run / still running (cold start) | `parapet-edge-ca` empty/absent → all serving replicas read no CA, all not-ready (503), the Service has zero endpoints, `POST /v1/edge-cert` connection-refused, trust-bundle has no `ca_pem`. Edges fail-static on last-good leaf; new edges stay not-ready. **Degraded, never fail-open.** Bounded by Job completion; self-heals on populate. Core treats no-`ca_pem` as not-yet-bootstrapped (keep retrying, never cache empty). |
| Bootstrap Job re-runs after the CA is populated (redeploy / Helm / Argo / `kubectl apply`) | (a) parse → ADOPT, exit 0 (no-op). (b) guard annotation present but blanked → HARD ANOMALY, **never regenerate**, exit non-zero + `parapet_edge_ca_unexpected_empty_total++` + alert. The stub carries GitOps drift-exclusion. |
| Two bootstrap Job pods run concurrently (node-loss double-run, delete-recreate, re-apply) | The `resourceVersion`-CAS linearizes them: exactly one `UpdateSecret` wins, the other gets `IsConflict`, re-reads, ADOPTS. The re-read-before-Update no-op closes the common race earlier. Single-writer is **not** relied on as a k8s guarantee; the CAS is the lock. |
| Bootstrap Job fails silently (exhausts backoffLimit, or exits 0 without writing) | Forbidden: exit non-zero on any failure; re-GET after `UpdateSecret` and assert the CA parses before exit 0. Alerts on `kube_job_failed` AND absence-of-populated-CA-after-deadline AND `parapet_edge_ca_generated_total` exceeding 1 across the fleet lifetime. |
| A serving replica caches the CA, then a rotation/re-populate writes a new CA | The CA-Secret read-watch (`atomic.Pointer[*Signer]`, validate-then-swap; active key from Secret content) converges within one debounce; the per-replica `parapet_edge_ca_signer_fingerprint` interlock gates trimming the old CA. |
| Runtime CA-Secret DELETE/blank on a serving replica (GitOps prune, restored empty stub) | The replica **keeps its last-good in-memory signer**, alerts, never drops to no-signer. With the in-serving anti-regen guard removed, this is the only in-process safety net. |
| CP unreachable at first boot (no cached bundle, or warm-start hint > `EDGE_TRUST_CP_MAX_STALE`) | `trustPol` nil ⇒ edges distrusted (XFF overwritten); core serves; CIDR branch unaffected. **Fail-closed.** `parapet_trust_source{none}`; background retry flips to mTLS on the first valid bundle. A persistently-unreachable CP is a loud alert. |
| Core restart during a CP outage (in-memory bundle lost) | Reads `EDGE_TRUST_CP_CACHE_FILE` as a **warm-start hint only** — confers NO trust until revalidated. Degrades to CIDR-only until the CP returns. `parapet_trust_source{file}` then `{mtls}`. Persisting-and-trusting is forbidden (would resurrect a revoked SAN). CP HA makes this rare. |
| Forged / replayed OLDER bundle over any TLS gap | Rejected by **forward-only**: the core swaps only when `generation` strictly advances; a replayed older body bumps `parapet_trust_rollback_rejected_total` and is dropped. The integrity precondition is mandatory non-skippable server-TLS. |
| Bad / forged / empty / zero-cert `ca_pem` on a fetch | Validate-then-swap **rejects** (non-empty-input-yields-zero-certs is rejected), keeps last-good, bumps `parapet_trust_reload_rejected_total`, alerts. NEVER nils the live pool. An empty `allowed_sans` is accepted only when `generation` strictly advances. |
| Missing/unparseable `EDGE_TRUST_CP_CA`, or non-https `EDGE_TRUST_CP_ENDPOINT`, when on | **FATAL** startup error — never a warning, never a system-roots fallback, never plaintext. A self-test asserts `RootCAs != nil && !InsecureSkipVerify`. No `EDGE_CP_ALLOW_PLAINTEXT` analog on either end. |
| CP is a trust source but `CP_TLS_CERT`/`CP_TLS_KEY` empty (plaintext) | **FATAL CP startup error** (mirrors the `CP_TLS` pairing guard). The trust channel has no plaintext mode on either end. |
| Unauthenticated long-poll flood (connection/goroutine/FD exhaustion) | Bounded: a semaphore caps concurrent watch handlers (over-limit ⇒ 503 + Retry-After), a context deadline frees blocked handlers, a per-source-IP cap + body cap apply, absurd `since` rejected cheaply. The edge-sources-only NetworkPolicy is availability-load-bearing; the CP sets `WriteTimeout`/`IdleTimeout` ≥ the watch ceiling. |
| `/v1/waf` or trust-bundle generation seen flapping by a load-balanced client | Fixed: generation is resourceVersion-derived (replica-identical + monotonic), not a per-process counter. Two replicas reading identical source emit equal generation. The ETag stays the take/304 driver. |
| CP restart resets an in-memory generation below a core's held `since` | Cannot happen: generation is an etcd resourceVersion, not a CP process counter, so a CP restart never lowers it. (If a content-hash were ever used instead, the CP would have to re-floor above the core's `since` and return current truth — but resourceVersion makes this moot.) |
| Revocation across N stateless CP replicas + N core pods | Eventually-consistent, self-healing. Total exposure = max-CP-replica-watch-lag (a revoked token can mint one last full-TTL leaf off a lagging CP replica) + max-CORE-replica-watch-lag (a dropped SAN still honored on a lagging core pod), each = watch/relist lag + 300 ms debounce. Runbook confirms convergence on **all** replicas of **both** planes via the pod-labeled generation metric before declaring trusted/revoked. Short `EDGE_CLIENTCERT_TTL` bounds the last-mint window. |
| CP-side allow-set derivation bug widens trust (single uncross-checked authority) | Pinned by intra-process tests (`identityFor()` == the SAN `Signer.Sign` stamps; a known-revoked id absent from a fresh `allowed_sans`), recomputed from the same registry snapshot that authorizes `/v1/edge-cert`. The core logs/metrics `parapet_trust_allowed_sans_count` + `parapet_trust_bundle_hash` so an unexpected widening is alertable. |
| Allow-set change does not propagate (gen fails to bump / long-poll wedges) | Three mitigations: deterministic (sorted, NFC) SAN serialization before the gen/etag hash; the core watch client avoids a whole-request timeout (Transport idle/header timeouts + per-attempt ctx deadline + TCP keep-alive); the unconditional `EDGE_TRUST_CP_POLL_INTERVAL` safety poll. SLA: sub-second normally, ≤ one poll interval worst-case. |
| Fleet-wide re-issue storm under N stateless replicas | The per-token rate limit and global signing cap are **PER-REPLICA** (effective ceiling N×, scales silently as replicas rise). authz-reject + key-type whitelist before any signing; the cap returns 429/503 + Retry-After; per-edge jitter prevents phase-lock. A hard global cap needs externalized state (deferred). |
| CP readiness ("can sign") mistaken for system readiness ("core trusts the CA") | The edge can't self-detect the core-doesn't-trust-me state and WILL go ready and serve 502s in the convergence window. The onboarding gate **REQUIRES** confirming `parapet_trust_source{mtls}` / the trust-bundle hash includes the new CA before routing prod traffic. |
| `EDGE_TRUST_SECRET` set on upgrade but `EDGE_TRUST_CP_ENDPOINT` unset (knob rename) | The core emits a **loud startup error** naming the rename, rather than silently ignoring the old knob and dropping every edge to CIDR-only. Back-compat is stated against a named shipped baseline, not "today." |

## Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `TRUST_PROXY` | core | `cloudflare` | **Unchanged.** Static CIDR / `cloudflare`/`true`/`false` → the `cidrTrust` OR-branch. **Never add edge egress CIDRs here.** |
| `EDGE_TRUST_CP_ENDPOINT` | core | `""` (feature off) | HTTPS base URL of the control plane. Set ⇒ the core pulls its trust bundle from `GET /v1/trust-bundle` instead of watching a Secret; unset ⇒ identical to today (CIDR-only). **MUST be `https://`** — non-https is a fatal startup error, no plaintext analog ever. |
| `EDGE_TRUST_CP_CA` | core | `""` | PEM (path/inline) of the CA that signs the **CP server** cert → the trust client's `RootCAs`. **MANDATORY + FATAL** if missing/empty/unreadable/unparseable (or zero certs) when the endpoint is set — the only thing protecting the core from a forged trust anchor. No system-roots fallback, no skip-verify. SHOULD be a dedicated single-purpose CA; distinct from the edge CA in `ca_pem`. |
| `EDGE_TRUST_CP_WATCH_TIMEOUT` | core/CP | `30s` | Server-side long-poll block ceiling. The CP `http.Server` `WriteTimeout`/`IdleTimeout` MUST be ≥ this; the core uses a per-attempt context deadline of this + slack, **not** a whole-request `http.Client.Timeout`. |
| `EDGE_TRUST_CP_POLL_INTERVAL` | core | `5m` | Safety-net plain-GET poll, run **unconditionally** alongside the long-poll. Bounds worst-case revocation latency if a broadcast is missed or the watch goroutine wedges. |
| `EDGE_TRUST_CP_CACHE_FILE` | core | `""` (recommended: set) | Path to persist the last-good bundle (public `ca_pem` + opaque SANs — no secret-at-rest concern). Written on every successful swap; read on boot as a **warm-start hint that confers NO trust until revalidated**. Never authoritative. |
| `EDGE_TRUST_CP_MAX_STALE` | core | `1h` | Max age of the warm-start hint; an older file is ignored. Secondary bound (the primary is no-trust-until-revalidated). |
| `EDGE_TRUST_REQUIRE_SAN` | core | `true` | Trust requires the verified leaf's URI SAN ∈ the live allow-set; the allow-set now comes from `/v1/trust-bundle`'s `allowed_sans` (no longer re-derived in the core). Still **incompatible with CP-issuance when CA-only** (fail-closed). |
| `EDGE_DATAPLANE_MTLS` | edge | `false` | Enable the CP-issued data-plane client cert (CSR → `POST /v1/edge-cert`). Off ⇒ anonymous re-encrypt. Requires `EDGE_UPSTREAM_TLS=true`. Readiness gated on a loaded cert (fail-closed). |
| `EDGE_CLIENTCERT_KEY_TYPE` | edge | `ecdsa-p256` | In-memory ephemeral keypair type (`p256`/`p384`/`ed25519`). RSA not offered (bounds the CP CSR-verify DoS surface). |
| `EDGE_CLIENTCERT_TTL` | CP | `1h` | Issued **leaf** lifetime. Short — renewal is free — to bound a leaked-token-minted cert. Raise (24–72h) if outage tolerance dominates. |
| `EDGE_CLIENTCERT_SKEW` | CP | `10m` | NotBefore backdating slack. The cert is minted on the CP clock, **validated on the core clock**. NTP sync between CP and core is a prerequisite. |
| `EDGE_CLIENTCERT_RATE` + global signing cap | CP | `10/min` per token; cap unsized | **PER-REPLICA** behind the Service ⇒ effective fleet ceiling **N×**, scaling silently as replicas rise for HA. authz-reject + key-type whitelist run before any signing. A hard global cap needs externalized state (deferred). |
| `EDGE_CA_BOOTSTRAP` / `--bootstrap-ca` | CP (Job) | false (serving mode) | Runs the same binary in one-shot CA-bootstrap mode (`EnsureCA`: adopt-if-present, generate-if-absent, never-regenerate, **CAS-guarded**, re-read-verify-before-exit), then exit. **The only process that writes the CA Secret.** |
| `EDGE_CA_CERT` / `EDGE_CA_KEY` | CP | `""` (⇒ managed) | **Provided mode:** PEM paths to a mounted edge CA cert+key. Set ⇒ the CP uses them, never generates/writes; hot-reloaded. Both-or-neither (hard error if only one). Absent ⇒ managed (the Job generates). |
| `EDGE_CA_SECRET` | CP | `parapet-edge-ca` | Name of the CA Secret in `POD_NAMESPACE`. The **Job** writes it (scoped get/update); **serving** reads it (read-only get + read-watch). Pre-created empty with GitOps drift-exclusion. Lives in a CP-only namespace. |
| `EDGE_CA_TTL` | CP | `87600h` (10y) | Lifetime of a CP-generated edge CA cert. Long-lived (the leaf TTL is the short knob). Ignored in provided mode. Rotation is Job-driven. *(Open: shorten to 1–2y unless convergence-gated rotation has shipped.)* |
| `EDGE_CA_KEY_TYPE` | CP | `ecdsa-p384` | Key type for a CP-generated CA (`p384`/`ed25519`). Ignored in provided mode. |
| `POD_NAMESPACE` | CP | downward API `metadata.namespace` (**required**) | The CP's own namespace; the CA Secret is **read** here (serving-managed) and **written** here (the Job). NOT `WATCH_NAMESPACE`. Empty in bootstrap or serving-managed mode ⇒ fatal. |
| `WATCH_NAMESPACE` | CP | `""` (all namespaces) | Cluster-wide tenant-TLS read = highest blast radius. **Recommend pinning** to the tenant-secret namespace(s). Distinct from `POD_NAMESPACE`; the CA read/write never uses it. |
| `EDGE_UPSTREAM_CLIENT_CERT` / `_KEY` | edge | `""` | **Legacy mounted-cert (k8s-only) edge-side path**, superseded by `EDGE_DATAPLANE_MTLS` + CP-issuance. A mount detail, not a CA mode. |
| `EDGE_UPSTREAM_TLS` / `EDGE_UPSTREAM_SNI` | edge | `false` / `""` | **Unchanged.** `EDGE_UPSTREAM_TLS=true` is required for mTLS trust; SNI presented on re-encrypt. |

Metrics: `parapet_trust_source{mtls|cidr|none|file}`, `parapet_trust_reload_rejected_total`,
`parapet_trust_rollback_rejected_total`, `parapet_trust_bundle_age_seconds`,
`parapet_trust_allowed_sans_count`, `parapet_trust_bundle_hash` (core);
`parapet_edge_clientcert_loaded`, `parapet_edge_clientcert_not_after` (edge);
`parapet_edge_ca_generated_total` (Job; alert if > 1 fleet-lifetime),
`parapet_edge_ca_unexpected_empty_total`, `parapet_edge_ca_signer_fingerprint`
(per-serving-replica, pod-labeled). Both planes expose the registry/trust-bundle
generation they last applied (pod-labeled) for convergence gating.

## Onboarding flow (the payoff)

1. **One-time, code-only:** deploy the two SAs (read-only serving + scoped-write Job) and
   their RBAC, pre-create the **empty** `parapet-edge-ca` stub (CP-only namespace, GitOps
   drift-exclusion), set `POD_NAMESPACE` on both the serving Deployment and the Job, and
   ship the **bootstrap Job as a pre-install/PreSync hook ordered before serving**. On
   first install the Job **generates and persists** the edge CA once (managed mode) — **no
   openssl, no cert-manager**; serving becomes ready only once a CA is loaded. The core
   points `EDGE_TRUST_CP_ENDPOINT` at the CP and `EDGE_TRUST_CP_CA` at the CP **server** CA,
   then pulls the edge CA's public cert + the live allow-set over `GET /v1/trust-bundle`.
   *Only restart, ever — never again per-edge.*
2. **Per edge — grant a data-plane identity (one registry edit).** Add the edge's entry to
   `edge-controlplane-tokens` with an explicit `id`. This single edit authorizes its
   cert/WAF fetch, makes the CP **issue** its data-plane cert on `POST /v1/edge-cert`, and
   publishes its SAN in `allowed_sans`.
3. **Configure the edge:** `EDGE_DATAPLANE_MTLS=true`, `EDGE_UPSTREAM_TLS=true`,
   `EDGE_UPSTREAM_ADDR` → core `:443`. For a Docker edge that's it — its only input stays
   `EDGE_CP_TOKEN`.
4. **Deploy + verify.** Confirm `parapet_trust_source{mtls}` **and** that
   `parapet_trust_bundle_hash` / `parapet_trust_allowed_sans_count` reflect the new id **as
   observed by the core** before routing prod traffic (worst-case convergence one
   `EDGE_TRUST_CP_POLL_INTERVAL`).
5. **Revoke:** **delete the edge's registry entry** → its SAN leaves `allowed_sans` →
   distrusted, with latency = max-CP-replica-watch-lag + max-CORE-replica-watch-lag (each
   watch/relist lag + 300 ms debounce); confirm convergence on **all** replicas of **both**
   planes via the pod-labeled generation metric. Deleting only the token does NOT revoke an
   already-minted cert. For a **leaked CA key**, SAN-drop does NOT help — the only fix is
   **CA rotation** (the Job-driven overlap runbook), gated on the convergence metric.

## Phasing

1. **Phase 1 — the primary mechanism (a bare Docker edge works, no cert-manager, HA CP).**
   Core: the per-request closure + `GetConfigForClient` hot-swap (unchanged); the tokenless
   `TrustCpClient` long-poll (mandatory-server-TLS, fatal-on-missing-CA, forward-only
   resourceVersion-derived generation, validate-then-swap, fail-static, warm-start disk
   cache that confers no trust until revalidated); `EDGE_TRUST_REQUIRE_SAN=true`; the
   `X-Forwarded-Country/-ASN` strip; the metrics. CP-issuance: `POST /v1/edge-cert`,
   `edgecp/signer.go` (zero-value template + post-sign self-check + key-type whitelist +
   HSM/KMS seam), `Authz.Identity`, the **single in-CP `identityFor`** derivation (no shared
   cross-binary package). **Managed-CA via a run-once bootstrap Job** (`--bootstrap-ca`)
   running `EnsureCA` (adopt-or-generate-never-regenerate, ECDSA-P384, single-purpose,
   NameConstrained), **keeping the `resourceVersion`-CAS and the anti-regeneration guard
   INSIDE the Job** plus a re-read-before-write no-op; the k8s write path scoped to the Job
   SA; serving replicas read-only with the CA-Secret read-watch keeping the signer
   hot-reloadable. **Stateless-HA serving** (no leader election; Service +
   readiness-gated-on-loaded-CA), the **content-derived generation fix** for **both**
   `/v1/waf` and the trust-bundle, the Job-ordering hook, the `GET /v1/trust-bundle`
   endpoint (tokenless, `?watch` long-poll, bounded concurrency), and the CP-side fatal
   guard that trust-distribution requires `CP_TLS`. `NetworkPolicy` locking core `:80`/`:443`
   and the CP (now availability-load-bearing).
2. **Phase 2 — stronger hardening.** Mutual auth of the edge hop (edge pins the core CA,
   drop `InsecureSkipVerify`); **CA auto-rotation** (Job triggered at `NotAfter` × fraction)
   gated on the cross-replica convergence metric; an **HSM/KMS `Signer`** so the raw CA key
   never sits in pod memory; CRL/OCSP via `VerifyConnection`; real SPIRE SVID migration.
   *(The CP-only-namespace CA-key-read isolation is now the Phase-1 default, not a Phase-2
   item.)*
3. **Phase 3 — optional companion.** A `TRUST_PROXY_DYNAMIC=true` ConfigMap-of-CIDRs
   OR-branch for callers that genuinely cannot present a client cert — same atomic +
   validate-then-swap discipline.

## Alternatives considered

- **Core keeps watching the CA Secret + a shared SAN-derivation package (the prior design).**
  Rejected: it forced the core to hold k8s read on a namespace co-tenant with the CA
  *private* key, required a cross-binary derivation package with a split-brain risk (papered
  over by a conformance test), and made revocation latency depend on a 6th Secret watch. The
  tokenless CP pull is strictly better — one fewer credential, an unforgeable trust anchor
  (mandatory server-TLS), single-sourced allow-set, full CA-key isolation — at the honest
  cost of a steady-state core→CP dependency for trust *changes* (mitigated by fail-static +
  a warm-start cache + required CP HA).
- **In-serving CA generation with a `resourceVersion`-CAS create-once (the prior managed
  mode).** Rejected for HA: it kept write RBAC on every serving replica and made the serving
  process stateful-ish. The CAS + anti-regen guard are **retained but relocated into a
  run-once Job**; serving becomes read-only and trivially replicable. (A naive "a Job is a
  single writer so drop the CAS" was itself rejected — a Job is not a guaranteed single
  pod.)
- **CP mints key+cert and ships both (vs CSR-based).** Rejected as default — strictly weaker
  (puts a private key on the wire). The CSR form keeps the key edge-local.
- **Token-gated `TrustProxy` (HMAC header).** A near-tie co-leader on operational
  single-source-of-truth (grafted). Rejected as primary on security: replayable header,
  order-fragile strip, O(N) HMAC amplification, clock-skew.
- **Dynamic IP trust list (ConfigMap of CIDRs).** Lowest effort; grafted its
  operator-asserted-trust + keep-last-good discipline. Rejected as primary (no security-bar
  raise; widens the spoof surface for NAT'd edges). Kept as the optional Phase 3 companion.
- **SPIFFE/SPIRE workload identity.** Operationally disqualifying now (out-of-cluster
  attestation needs SPIRE federation + a second rotating CA bundle). Grafted only the
  URI-SAN naming.
- **CA-only mTLS (`EDGE_TRUST_REQUIRE_SAN=false`).** Supported for non-issuance deployments
  but **forbidden with CP-issuance** (no per-request revocation lever).
- **cert-manager-issued CA / cert-manager-proxy issuance (removed).** Added a hard CRD
  dependency + async round-trip + an out-of-band CA-creation step that defeats the zero-PKI
  goal. The CP now self-manages the CA via the Job; provided mode covers existing PKIs.

## Open questions

- **Generation source:** confirm `max(resourceVersion)` across the source ConfigMaps/Secrets
  as the generation (the only option both replica-identical AND monotonic). resourceVersion
  is officially opaque (treat as monotonic-per-object; handle a delete+recreate that resets
  it by also keying on object UID so a recreate triggers a re-sync, not a permanent reject).
  If a hash is ever preferred, **rename** the field to an opaque equality-only fingerprint
  with ordering/since/rollback semantics forbidden.
- **Purge journal (Phase 5, design-only):** the lone genuinely-stateful feature,
  **known-broken under `replicas>1`** with a per-process in-memory monotonic `seq` (an admin
  `POST` lands on one replica only; per-replica `seq`/`min_seq` fire `flush_required`
  spuriously). MUST be externalized (a ConfigMap/CRD journal every replica observes via its
  existing watch; `POST` becomes a write-to-k8s) before shipping multi-replica. Do not
  enable `/v1/purges` with `replicas>1` until then.
- **Hard global signing cap:** a true fleet-wide ceiling vs the per-replica N× loosening
  needs externalized rate-limit state (a shared token bucket). Accept N× (simplest), set
  per-replica = `ceil(target/N)` (imperfect under uneven LB), or defer? `N` is not directly
  available inside a pod (would come from an env/Deployment field).
- **Long-poll concurrency cap default:** what semaphore size balances "never starve the
  token-gated endpoints" against "a small legit core fleet + its safety poll is never 503'd"?
  Tie to the expected core replica count behind the NetworkPolicy.
- **CP HA enforcement:** ≥2 replicas is now REQUIRED — should the core warn if it can detect
  a single-replica CP, or is this left to deployment review?
- **First-boot ordering on a fresh cluster:** the core's first bundle needs the Job's
  `EnsureCA` to have populated the CA (503 until then) AND the CP server cert present — pin
  the deploy ordering / readiness-gating so a cold cluster converges without a manual
  restart, and decide whether the core blocks startup on the first bundle or starts
  CIDR-only and converges.
- **`EDGE_CLIENTCERT_TTL` vs CP-outage budget:** pin a default that exceeds the CP recovery
  SLO, or expose `TTL` + renew-before as paired knobs with a guard that renew-before < `TTL`
  by a safe margin?
- **Empty-stub feasibility:** do target k8s versions reject a zero-length `tls.crt` on a
  `kubernetes.io/tls` CREATE? If so, ship the stub as type `Opaque` (type is advisory to our
  code and can't change on `Update`).
- **Mutual auth of the edge hop:** should the edge verify the core's server cert (pin the
  core CA, drop `InsecureSkipVerify` in `forward.go`)? Today only edge→core (data plane) and
  core→CP (trust) directions are asymmetric by design.

## Conformance / contract

On acceptance, fold into [`SPEC.md`](SPEC.md): the trust predicate
(`cidrTrust OR (verified-edge-CA-chain AND SAN ∈ allow-set)`); the `POST /v1/edge-cert`
(CSR in, chain out, CP-decided SAN, no key on the wire) and the **tokenless** `GET
/v1/trust-bundle` (with the `?watch` long-poll and the forbidden-401/403 property)
endpoints; the managed (bootstrap-Job) / provided CA model and the **stateless-serving +
run-once-Job** posture; the **content-derived generation contract** (replica-identical AND
monotonic; resourceVersion-derived) for **both** `/v1/waf` and the trust-bundle; the new env
vars (`EDGE_TRUST_CP_*`, `EDGE_DATAPLANE_MTLS`, `EDGE_CLIENTCERT_*`, `EDGE_CA_*`, CP
`POD_NAMESPACE`/`WATCH_NAMESPACE`); the `X-Forwarded-Country/-ASN` ingress strip; and the
per-request order (trust evaluation precedes WAF/rate-limit). Conformance tests: the
intra-process `identityFor()` == `Signer.Sign` SAN; a known-revoked id absent from a fresh
`allowed_sans`; the two-goroutine concurrent-generate CAS test against client-go fake
(exactly one CA survives, the loser adopts), exercised against the Job `EnsureCA`; two
`WafStore`/serving replicas fed identical source report **equal** generation; the
NameConstraints `x509.Verify` accept/reject pair. The Rust implementation in [`rust/`](rust/)
tracks the same contract or records a divergence.

[TLS SNI fallback memory]: the proxy serves a self-signed fallback on an SNI miss when the
live cert table loses `GetCertificate`; the `GetConfigForClient` self-test exists to prevent
re-introducing that class of bug during a trust reload.
