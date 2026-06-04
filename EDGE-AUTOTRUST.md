# Auto-trust edge proxy (data-plane trust without a restart)

> **Status: DRAFT / design-only — not implemented.** This proposes how the
> in-cluster **core** proxy (`cmd/parapet-ingress-controller`, "parapet") comes to
> trust a newly-deployed **edge** proxy (`cmd/edge-proxy` + [`edge/`](edge/))
> automatically — without an operator editing `TRUST_PROXY` and restarting the
> core. It builds on the edge architecture in [`EDGE.md`](EDGE.md). Per
> [`CLAUDE.md`](CLAUDE.md), the contract changes in [`SPEC.md`](SPEC.md) first.
> **Trust is CA-only:** the core trusts an edge iff `cidrTrust(r) OR a verified TLS
> chain to the dedicated edge CA` — a pure cryptographic predicate, no SAN
> allow-set, no per-request map read. Issuance stays token-gated; *trust* is
> chain-to-CA. **No cert-manager** (a run-once bootstrap Job self-manages the edge
> CA). The core pulls a tokenless trust bundle from the CP over verified server-TLS.
> The serving CP is **stateless across N replicas** (no leader election).
>
> **Headline consequence:** *revocation is now CA rotation.* There is no per-edge
> trust lever; revoking one edge re-keys the fleet's shared CA. Leaf TTL is **7
> days**, so a compromised edge stays trusted until the rotation completes
> (operator-driven minutes-to-low-hours) — **not seconds, and not 7 days**.

## The problem

The edge sits in front of the core and sets `X-Forwarded-For` / `X-Forwarded-Proto`
(and, with a GeoIP DB, `X-Forwarded-Country` / `X-Forwarded-ASN`) so the core's WAF,
per-IP rate limits, GeoIP, and access logs see the **real client**, not the edge.
For the core to honor those headers, the edge's source must be in the core's
**trust list** — today the `TRUST_PROXY` env var (a CIDR list, or `cloudflare`).

`TRUST_PROXY` is read **once at startup** (`main.go:214-237`), compiled into a
`parapet.Conditional`, and frozen. So adding/replacing an edge means editing that
env **and restarting the core pod** — and the CIDR model is brittle for
out-of-cluster, NAT'd, autoscaling edges.

> **Why trust is security-critical.** parapet calls `TrustProxy(r)` **per request**
> (`proxy.go`). Trusted → honor the incoming `X-Forwarded-*`. Untrusted → overwrite
> with the peer IP. Any source the core trusts can **spoof `X-Forwarded-For`** to
> bypass IP WAF rules / per-IP rate limits and poison GeoIP/logs. Auto-trust must
> mean *trust exactly the sanctioned edges*, hot-reloadably.

## The key enabler

`parapet.Conditional` is `func(r *http.Request) bool`, evaluated **per request**.
A closure installed **once** can read an `atomic.Pointer` to a live trust policy
that is **hot-swapped** from the trust bundle the core pulls from the CP
(`GET /v1/trust-bundle`), via the same validate-then-swap discipline the edge's
`CpClient` uses (`edge/cp.go`, `edge/refresh.go`) — fail-static, all-or-nothing,
never rebuilding the route mux. **No restart.** The question is only *what
credential the edge presents* and *how the core learns the live trust policy*.

## Recommended design: edge mTLS (CA-only)

Authenticate the **edge → core hop with mutual TLS**. Trust follows a private key,
not a source IP.

1. **A dedicated, single-purpose edge CA.** Created once and reused; it signs
   **nothing else**, so "chains to this CA" means exactly "is a sanctioned-edge
   credential." By default (**managed** mode) a **run-once bootstrap Job** generates
   it and persists it; the serving CP only **reads** it and signs. **provided** mode
   lets an operator mount their own CA. The key never reaches an edge — only leaf
   certs do. See [Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert).

2. **The CP issues each edge a leaf** over the bearer channel — the edge sends a CSR
   to `POST /v1/edge-cert`, the CP signs it with the edge CA and returns only the
   chain; the **private key never leaves the edge**. The CP stamps a URI SAN
   (`spiffe://parapet.moonrhythm.io/edge/<id>`), **but the SAN is kept only for
   non-trust uses** (`X-Forwarded` upstream identity, WAF zone, audit) and is
   **never consulted for trust** — a mis-stamped, stale, or over-broad SAN can never
   widen the trust boundary.

3. **The edge presents it** on the re-encrypt hop (`EDGE_UPSTREAM_TLS=true`) via a
   live `GetClientCertificate` callback. A client cert can only ride TLS, so edge
   trust is conferred **only on `:443`**; plaintext `:80` is never mTLS-trusted.

4. **The core verifies it.** The `:443` `tls.Config` gets
   `ClientAuth = tls.VerifyClientCertIfGiven` (the cert is optional — Cloudflare /
   browsers present none) and a `ClientCAs` pool sourced from the trust-bundle
   `ca_pem`. The stdlib populates `r.TLS.VerifiedChains` only after cryptographic
   verification against `ClientCAs`; a presented-but-unverifiable cert aborts the
   handshake.

5. **The per-request trust predicate** (installed once; see [Core wiring](#core-wiring)):

   ```
   trust(r) := cidrTrust(r)                         // existing TRUST_PROXY (e.g. cloudflare)
            OR len(r.TLS.VerifiedChains) > 0        // a chain cryptographically verified to the edge CA
   ```

   The edge CA signs nothing but edge leaves, so a verified chain **is** the trust
   grant — a single non-empty check, no SAN lookup, no allow-set, no operator-asserted
   string set in the per-request path.

### Single source of truth (onboard in one place); the SAN is not load-bearing

Onboarding still touches one registry, `edge-controlplane-tokens`, shape
`{ "<token>": { "id": ..., "domains": [...], "disabled": bool } }`. The `id` is
still stamped into the leaf SAN — but **only for labeling/audit/WAF-zone
attribution**. An over-broad or wrong `id` is now an *audit* issue, not a
trust-widening. Removing the only operator-asserted string set from the per-request
trust path **eliminates the silent fleet-wide trust-widening risk** of an over-broad
allow-set — a strict safety improvement, at the cost of coarser (fleet-wide)
revocation granularity (see [Revocation](#revocation--ca-rotation)).

The CP no longer derives or broadcasts an allow-set; the core no longer derives
anything. The cross-binary `identityFor` derivation, the "sole uncross-checked
authority" risk, and the SAN cross-check conformance test all disappear because the
only thing the core verifies is a cryptographic chain.

## Deployment models: k8s edge vs Docker edge

The data-plane client cert works for **both** shapes with the same gesture
("provision one token"); it always arrives via `POST /v1/edge-cert`.

**k8s edge.** Runs as a Deployment. cert-manager is no longer part of this design;
an operator who already runs it can still *mount* a client cert via the legacy
`EDGE_UPSTREAM_CLIENT_CERT`/`_KEY` path — a mount detail, not a CA mode.

**Docker edge (the motivating case).** A bare `docker run`; its **only required
input is `EDGE_CP_TOKEN`**. It already pulls its public cert+key (`GET /v1/certs`)
and WAF rules (`GET /v1/waf`) from the CP, fail-static, keys in memory only. The
data-plane identity rides the same loop: `POST /v1/edge-cert`, key in memory only.

| | k8s edge | Docker edge |
|---|---|---|
| Public cert+key / WAF | `GET /v1/certs` / `GET /v1/waf` | same |
| **Data-plane client cert** | `POST /v1/edge-cert` (mounted-cert optional) | **`POST /v1/edge-cert`** |
| Required edge input | token (+ optional mounted cert) | **`EDGE_CP_TOKEN`, and nothing else** |

## Core wiring

In `main.go`, replace the one-shot `trustProxy` block (`:214-237`). Keep the static
parse **verbatim** into a fixed local `cidrTrust`. Add a single atomic:

```go
var clientCAs atomic.Pointer[x509.CertPool]   // the only trust state in the core
```

(There is **no** `trustPolicy`/`trustPol`/`allowedSANs` — those are deleted.)
Install **one** closure, assigned to **both** servers' `TrustProxy`:

```go
trustProxy = func(r *http.Request) bool {
    if cidrTrust != nil && cidrTrust(r) { return true }               // metric: cidr
    if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 { return false } // metric: none / not-:443
    return true                                                        // verified chain to the edge CA == trust
}
```

`sanAllowed`, the `requireSAN` branch, and `trustPol.Load()` are gone. Keep the `:80`
`r.TLS == nil` short-circuit (CIDR-only on plaintext) and the `GetConfigForClient`
hot-swap (`c.ClientCAs = clientCAs.Load()`, fresh per handshake, never nil) +
startup self-test (asserts `GetCertificate` + `ClientCAs` +
`ClientAuth == VerifyClientCertIfGiven`) **verbatim**. Only the *feed* into
`clientCAs` changes; trust no longer reads any per-request map.

### The trust pull (tokenless CP client)

Gated by `EDGE_TRUST_CP_ENDPOINT != ""` (default off ⇒ identical to today). There is
**no k8s watcher** for trust. A tokenless `TrustCpClient` (new file, e.g.
`trust/client.go`) mirrors `edge/cp.go`'s `CpClient` minus the `Authorization`
header. `FetchTrustBundle(sinceGen, etag)` builds
`base + "/v1/trust-bundle?watch=1&since=<sinceGen>"`, decodes
`{generation, ca_pem, ca_id}` (no `allowed_sans`), returns `Unchanged` on 304.

A single long-poll goroutine, on a good 200: **strict all-or-nothing parse** of
`ca_pem` into an `x509.CertPool` — reject a non-empty input that yields *fewer*
certs than blocks present (never a partial `AppendCertsFromPEM`, never a system-roots
fallback; keep last-good, bump `parapet_trust_reload_rejected_total`); **reject any
bundle whose `generation <=` held** (forward-only, `parapet_trust_rollback_rejected_total`);
then atomically `Store` `clientCAs`. **The strict parse now applies during rotation
too** — a truncated/garbled NEW block in the `OLD ++ NEW` overlap bundle must be
rejected (keep last-good), never half-applied, so a bad NEW block blocks the rotation
loudly rather than silently dropping NEW (which would 502 just-re-minted edges).

**Deliberate inversion of `edge/cp.go`:** a missing/empty/unparseable
`EDGE_TRUST_CP_CA`, or an `AppendCertsFromPEM` that adds **zero** certs, is a **FATAL
startup error**; `InsecureSkipVerify` is never set; a non-`https://` endpoint is
rejected fatally — **no plaintext analog ever**. `EDGE_TRUST_CP_CA` SHOULD be a
dedicated single-purpose CA signing only the CP server cert; the client verifies the
CP cert hostname against the endpoint host.

### Freshness: long-poll, not bare poll

With per-request SAN revocation gone, the generation/long-poll no longer carries
per-edge revocation; it now matters **only for CA rotation** — the core must trust
NEW before edges re-mint and drop OLD promptly after convergence, which is exactly
when freshness matters. **Keep the long-poll** (`?watch=1&since=<generation>` blocks
until the generation advances or `EDGE_TRUST_CP_WATCH_TIMEOUT` ~30 s → 304); steady-
state freshness can relax, so `EDGE_TRUST_CP_POLL_INTERVAL` may lengthen. The
etag/generation is derived over `generation || ca_pem || ca_id`, where **`ca_id` is
a stable sorted-SHA256 fingerprint over the CA certs in `ca_pem`** (so map-iteration
nondeterminism cannot stall the bump). The unconditional safety-net plain-GET poll
runs alongside as a correctness backstop; the watch call avoids a whole-request
`http.Client.Timeout` (Transport timeouts + per-attempt ctx deadline + TCP
keep-alive). The CP `http.Server` `WriteTimeout`/`IdleTimeout` MUST be ≥ the ceiling.

### Generation (resourceVersion-derived, replica-identical + monotonic)

`generation` is the **`parapet-edge-ca` Secret's own `metadata.resourceVersion`** (a
single source object), parsed to `uint64` (`edgecp/resourceversion.go`). etcd is a single
global monotonic revision counter, so this is server-assigned (**identical on every CP
replica** that reads the same object), monotonic, and persisted across CP restarts **by
construction** — no process counter (this replaces the `prev+1` that two replicas desync,
the `wafstore.go` flap class). **It is NOT a `max()` across objects** — a `resourceVersion`
is only comparable within one object's history, so the token registry (when it becomes a
Secret) gets its OWN separate generation for its own concern, never folded in.

Guards: (1) the CP-side **monotonic floor** in `SetSigner` rejects `generation <= served`
(an out-of-order watch re-list can't regress; counted by `parapet_edge_ca_signer_floored_total`);
(2) a non-numeric `resourceVersion` (the k8s contract permits it) keeps last-good and raises
`parapet_edge_ca_signer_rv_unparsed` (fail-closed — never `0`, never a counter fallback);
(3) the `ca_id` no-churn gate means a metadata-only write does **not** advance generation.
**Forward-only is LOAD-BEARING for CA-rotation-as-revocation:** a replayed OLDER bundle over
any TLS gap could re-add a just-dropped OLD CA (**re-trusting a compromised edge**) or remove
a just-added NEW CA (mass 502); the core swaps only on a strictly-advancing generation.

**Provided mode** has no Secret RV: `generation` comes from `EDGE_CA_PROVIDED_GENERATION`
(bump it on each rotation) or the cert file's mtime — it **must advance on every rotation**,
or the core rejects the new bundle as a rollback.

> **One-way door (rollback footgun).** Switching to a `resourceVersion`-derived generation
> moves the value from a small counter to a large etcd revision. Once the core has applied an
> RV-derived generation, a plain deploy **rollback** to the old counter scheme makes the core
> reject the now-smaller generation as a rollback and **freeze trust at last-good**. Rolling
> back requires resetting the core's remembered trust generation (restart the core after the
> CP is rolled back). Distinct from the delete+recreate UID-reset residual.

### Warm-start cache (fail-closed)

The core persists the last-good bundle (`ca_pem` + `ca_id`, public — no secret-at-rest
concern) to `EDGE_TRUST_CP_CACHE_FILE`, **but it confers NO trust until revalidated**.
A restarted core with the CP down reads it as a warm-start hint, stays **CIDR-only**,
and flips to mTLS only after the first live fetch supersedes it — because persisting-
and-trusting could **resurrect an OLD CA the operator just rotated out**
(re-trusting a compromised edge) across a restart-during-outage. `EDGE_TRUST_CP_MAX_STALE`
caps the hint's age. `parapet_trust_source{file|mtls|cidr|none}` makes the state
alertable. (Header hardening unchanged: the core unconditionally strips client-supplied
`X-Forwarded-Country/-ASN` at ingress.)

> **Implemented** (`trust.Manager.EnableWarmStart`/`writeCache`, `apply`'s floor check). The
> hint is realized as a generation **floor** (anti-resurrection) — the cached CA is
> deliberately NOT loaded into `ClientCAs`, so "stays CIDR-only until revalidated" falls out
> for free (per-request trust keys on `r.TLS.VerifiedChains`, which is empty until a live
> apply populates the pool) and a stale-CA handshake can never reject a NEW-leaf edge.
> Because no per-request decision is "file-sourced" under that safe design, the alertable
> state is the **`parapet_trust_warmstart_active`** gauge (1 while running on an
> unrevalidated floor) rather than a per-request `trust_source{file}` counter; the
> anti-resurrection rejection is `trust_apply_total{result="floor_rejected"}`.

## Edge wiring

The default data-plane identity is CP-issued (`EDGE_DATAPLANE_MTLS=true`; requires
`EDGE_UPSTREAM_TLS=true`). `edge/clientcert.go` holds the leaf in an in-memory
`ClientCertStore` (`atomic.Pointer[tls.Certificate]`); `Update` is **all-or-nothing**
(keep the prior pair on failure). `RunEdgeCertRefresh` renews on remaining-life
(re-mint when ≤ 0.66 × the leaf's own lifetime remains, i.e. ~4.6 d left of a 7-d
leaf, ~2.4 d in) with backoff + jitter + `Retry-After`.

### Force-re-mint trigger: proactive overlap (primary) + reactive (floor)

With a 7-day TTL good edges will **not** naturally renew during a rotation, so
dropping OLD without a trigger would 502 the fleet until natural renewal (days). So:

- **Proactive (primary).** The trust-bundle gains `ca_id`; the edge observes it via a
  **`ca_id` field added to the token-gated `GET /v1/waf` 200 body** — the edge has
  **no** trust-bundle call (it only does `FetchCert`/`FetchWaf`; the trust-bundle is a
  core-only, tokenless endpoint), so `ca_id` rides the edge's existing ETag-revalidated
  refresh loop, its bearer token, and its `EDGE_REFRESH_INTERVAL` poll — no new
  endpoint/auth/goroutine. On a `ca_id` change the edge immediately re-runs the CSR →
  `POST /v1/edge-cert` flow to get a NEW-CA leaf **before** OLD is dropped. This is why
  the revoke flow is ADD-new → edges-re-mint → confirm-converged → DROP-old, and why
  the drop is convergence-gated: the proactive path is the **mass path**, so the drop
  is a no-op for good edges.
- **Reactive (floor).** If an edge missed the signal, its upstream handshake fails at
  the drop with a `bad_certificate`/`certificate_unknown`/`unknown_ca` alert. The
  ErrorHandler (`edge/forward.go`, today a generic 502 for *all* upstream errors) MUST
  **classify narrowly**: re-mint **only** on those TLS cert-verify alerts, **never** on
  a generic 502, dial error, timeout, or healthy-core HTTP status — otherwise an
  unrelated core outage triggers a fleet-wide re-mint storm and a tight loop. Add a
  per-edge single-flight + backoff and a **circuit-breaker** (stop after K consecutive
  re-mints that did NOT change `ca_id` — the failure isn't a trust problem). The brief
  per-edge 502 blip self-heals once the new leaf lands (`retryMiddleware`).

**Anti-thundering-herd on both triggers:** a rotation flips `ca_id` for the whole
fleet at once, so spread re-mints by full jitter in `[0, EDGE_CLIENTCERT_REMINT_JITTER]`
(default ≥ 60 s, sized to exceed signer drain) + exponential backoff + `Retry-After`
honoring (the signer is per-replica-rate-limited; one token per edge means the per-token
bucket does NOT bound the aggregate) + per-edge single-flight.

**Fail-static two-hop separation.** Re-minting touches the **data-plane** (edge→core)
client cert **only**. The edge keeps serving its **public** leaf to clients throughout
(client TLS is independent) and keeps presenting its current (OLD-CA) client cert during
the overlap — **safe because the core trusts `OLD ++ NEW`**. `ClientCertStore.Update`
all-or-nothing means a failed re-mint keeps the prior pair; the edge degrades but never
fails open and never drops public TLS.

## Control-plane wiring: CP issues the client cert

### Stateless serving control plane (HA via replicas + Service)

The serving CP holds **no control-plane-owned state**: every input (the edge-CA keypair,
the registry, tenant TLS, WAF) is read from the apiserver into a reconstructible cache,
so replicas are byte-identical. HA is the ClusterIP Service over N pods with the
`/healthz?ready=1` gate; the CP is off the request path (pull on timers/long-poll,
fail-static). **No leader election, no in-serving CAS, no write RBAC.** Signing is
deterministic per request. Multiple concurrently-valid serials per edge (one per replica
that served a renewal) are expected; revocation is CA rotation, not serial/CRL.

### `GET /v1/trust-bundle` — the tokenless trust endpoint

```
GET /v1/trust-bundle    (NO Authorization header)   [If-None-Match]   [?watch=1&since=<generation>]
  200 {"generation": N, "ca_pem": "<edge-CA PUBLIC cert bundle; OLD++NEW during rotation>", "ca_id": "<sorted-SHA256 of the CA certs in ca_pem>"}
       NEVER a private key. ca_id changes whenever a CA is added to or dropped from ca_pem.
       ETag over generation || ca_pem || ca_id.   Cache-Control: no-cache
  304 (If-None-Match matched OR a ?watch elapsed with no change)
  503 (CA not yet initialized — bootstrap Job hasn't populated it; core fail-statics and retries)
```

A sibling of the no-auth `GET /healthz` — it **never inspects `Authorization`**. The
handler assembles `ca_pem` as the **public** cert(s) only from the live `Signer`;
the core uses `ca_id` only for observability/convergence (the trust input is `ca_pem`).
There is **no `allowed_sans`** and **no 401/403 path**. **No-token is safe only because
server-TLS is the integrity boundary** (a token authenticates the client, not the
response; `ca_pem` is public, `ca_id` is a fingerprint) — so the CP MUST refuse to start
in plaintext when it is a trust source (`CP_TLS_CERT`/`CP_TLS_KEY` required; fatal
otherwise), with no plaintext analog on either end. The secret/scoped endpoints
(`/v1/certs`, `/v1/waf`, `/v1/edge-cert`) **keep** their token.

**Bounding the unauthenticated long-poll:** a bounded semaphore on concurrent watch
handlers (over-limit ⇒ 503 + `Retry-After`), a context deadline ≤ the ceiling, a
per-source-IP cap, and a body cap — the edge-sources-only NetworkPolicy is now
**availability-load-bearing**, a hard prerequisite.

### The issuance endpoint (`POST /v1/edge-cert`)

CSR-based; the private key never leaves the edge. A token whose registry entry has
`disabled:true` (or is absent) is treated as **UNKNOWN → 401**, so a blacklisted token
cannot mint. The CP whitelists the key type/curve **before** `CheckSignature` (ECDSA
P-256/P-384 or Ed25519; reject RSA → 400), then `Signer.Sign(csr.PublicKey, authorizedSAN)`.

### Signing: template, custody, rate-limiting

`Signer.Sign` builds the leaf template **from a zero value** — only `SerialNumber`
(CSPRNG), `NotBefore = now - skew`, `NotAfter = now + EDGE_CLIENTCERT_TTL`, `KeyUsage =
DigitalSignature`, `ExtKeyUsage = [ClientAuth]`, `URIs = [authorizedSAN]` (audit-only),
`IsCA = false`. Post-sign self-check re-parses and asserts the shape; refuse otherwise.

**`edgecp/authz.go` — the `disabled` tombstone.** The registry shape becomes
`{"<token>":{"id":...,"domains":[...],"disabled":bool}}`. A **single chokepoint**:
`Known`, `Identity`, **and** `Allowed` all treat `disabled:true` (and a deleted entry)
as **ABSENT** — a **full lockout**: a disabled token cannot mint (`/v1/edge-cert`),
fetch **private keys** (`/v1/certs`), or fetch WAF (`/v1/waf`). Prefer the tombstone
over deletion (audit trail; blocks an accidental GitOps re-add silently re-enabling a
revoked edge; survives a registry restore); deletion is equally honored. **Residual,
stated loudly:** `disabled`/deletion stops only **future** minting — the already-minted
leaf chains to the live CA and stays trusted until expiry or CA rotation (see
[Revocation](#revocation--ca-rotation)).

**CA custody — managed (Job) vs provided.** Managed (default): the run-once bootstrap
Job generates a single-purpose, NameConstrained ECDSA-P384 CA (`KeyUsage =
CertSign|CRLSign`, EKU `clientAuth`, `MaxPathLenZero`) and persists it; serving reads +
hot-reloads, never writes. Provided: mounted `EDGE_CA_CERT`/`EDGE_CA_KEY` (validated:
`IsCA`, EKU `clientAuth`, warn/refuse if no `PermittedURIDomains`). `cmd/edge-controlplane/main.go`
branches FIRST on `EDGE_CA_BOOTSTRAP`/`--bootstrap-ca` (run `EnsureCA`, then exit);
`POD_NAMESPACE` is fatal-if-empty in bootstrap and serving-managed mode.

**Rate-limiting + the rotation thundering herd.** The per-token bucket and global
signing cap are **per-replica** (effective ceiling N×). A rotation flips `ca_id`
fleet-wide at once, so without spreading, every edge re-mints simultaneously against the
CPU-bound ECDSA-P384 signer — a self-inflicted DoS that, because drop-OLD is
convergence-gated, would **extend** the window the compromised edge stays trusted.
Require jitter + backoff + `Retry-After` on both triggers; **proactive overlap is the
mass path** (good edges already hold NEW-CA leaves before the drop), reactive is the
per-edge floor only.

### CA generation: the run-once bootstrap Job (single intentional writer)

`edgecp.EnsureCA` runs in the `--bootstrap-ca` one-shot binary, then exits. On a
strongly-consistent typed `GetSecret`: (a) valid keypair → ADOPT (re-run is a no-op);
(b) guard annotation present but blanked → **HARD ANOMALY**, never regenerate, exit
non-zero + `parapet_edge_ca_unexpected_empty_total`; (c) virgin stub → generate, write
keypair + guard annotation. **A k8s Job is not a guaranteed single writer**
(node-loss double-run, Helm/Argo delete-recreate, manual re-apply), so **RETAIN the
`resourceVersion`-CAS** + a re-read-before-Update no-op; on `IsConflict` re-read and
ADOPT. Re-GET after Update and assert the CA parses before exit 0. The same machinery
serves rotation (below).

### Bootstrap-Job vs serving ordering (the cold-start window)

Job-before-serving is a HARD requirement (Helm pre-install / Argo PreSync hook,
preferred over an initContainer). Belt-and-suspenders: serving readiness is gated on a
loaded CA. Until the Job populates the CA, serving replicas are not-ready (503), the
Service has zero endpoints, the trust-bundle has no `ca_pem`; edges fail-static on their
last-good leaf (degraded, never fail-open). The core treats a no-`ca_pem` trust-bundle as
not-yet-bootstrapped (keep retrying, never cache empty).

### Where the core gets the CA (the CP serves it; the core never reads the Secret)

The core **never reads `parapet-edge-ca`** — it pulls the public `ca_pem` from
`GET /v1/trust-bundle`. `EDGE_TRUST_SECRET` is removed; the core needs **zero** k8s
access for trust. Because the core never touches the CA Secret, **`parapet-edge-ca`
lives in a CP-only namespace** with the CP as its only reader — the core-SA-can-read-the-CA-key
concern is **eliminated**. The CP assembles `ca_pem` from its live `Signer`, so the
signing CA and the trusted CA cannot drift, with no publish step.

### Revocation = CA rotation

> ⚠️ **BLACKLISTING A TOKEN DOES NOT REVOKE TRUST.** Removing or disabling a token in
> `edge-controlplane-tokens` only stops the edge minting a **new** leaf. Its
> already-minted leaf chains to the still-live edge CA and stays **fully trusted** (can
> spoof `X-Forwarded-For`, bypass per-IP WAF/rate-limits, poison GeoIP/logs) until that
> leaf **expires (up to 7 days)** OR the CA is **rotated out**. For any real compromise
> (stolen leaf key, owned edge box), **CA ROTATION IS MANDATORY, not optional.** The
> effective revocation SLA = time-to-rotate + fleet-converge + drop-OLD (operator-driven
> minutes-to-low-hours) — **not seconds, and not the 7-day TTL**.

**CA rotation is now the revocation primitive** — a routine, on-demand, safety-critical
operation, not the rare 10-year event. It is driven by the same `--bootstrap-ca`/rotate
Job (never leader-elected serving) and is modeled as an **idempotent-per-phase state
machine** with a persisted annotation on the CA Secret
(`parapet.moonrhythm.io/edge-ca-rotation-phase: overlap|converged|trimmed`) + an
intent/deadline annotation naming *why* (revoke of id X). The overlap flow:

1. Generate a NEW CA in memory; `resourceVersion`-CAS-write `tls.crt = OLD ++ NEW`,
   NEW key staged, `tls-active: old`.
2. Serving replicas converge (read-watch, `atomic.Pointer[*Signer]`, active key chosen
   solely from `tls-active`); the trust-bundle `ca_pem` broadcasts `OLD ++ NEW` and
   `ca_id` flips.
3. The core's long-poll picks up `OLD ++ NEW`, rebuilds `ClientCAs`, trusts **both** —
   **rotation invariant: NEW's public cert is in the `ca_pem` the core trusts BEFORE any
   leaf is signed under NEW.**
4. Flip `tls-active: new`; good edges re-mint onto NEW (proactive, jittered).
5. **The convergence interlock** (below) gates the OLD drop; then CAS-write
   `tls.crt = NEW` only — the moment OLD is dropped, the revoked edge's OLD-CA leaf stops
   verifying and it is distrusted.

The trim is re-runnable (an interrupted rotation is resumed by re-invoking the tool,
never regenerating a third CA). `parapet_edge_ca_rotation_stuck` **pages** while the
Secret sits in `overlap` past its deadline — a half-applied rotation means the
compromised edge is still trusted. The stolen-CA-key emergency (skip overlap, accept the
gap) is unchanged.

#### The convergence interlock (drop-OLD is metric-gated, never timer-gated)

Dropping OLD is the **only** step that actually distrusts the revoked edge, and dropping
it before the fleet re-mints 502s every not-yet-converged edge — so it MUST be gated on
**positively observed** convergence across **both planes**, never on elapsed time. The
Job/tool MUST NOT write `tls.crt = NEW` until pod-/edge-labeled metrics confirm: (1)
every serving CP replica reports the NEW `parapet_edge_ca_signer_fingerprint` AND has
`OLD ++ NEW` in its trust-bundle output; (2) the core(s) report `ca_id == new-set`; (3)
every **good** edge reports `parapet_edge_clientcert_ca_id == new`; (4) the revoked id
has **no leaf under NEW** (verify absence). A missing/unreporting/partitioned replica or
edge **blocks** the drop (fail-closed) — holding the overlap open is cheap and safe;
dropping early is the only unsafe move. The only bypass is a loud, logged operator
override. Size the deadline to ≥ one `EDGE_REFRESH_INTERVAL` (proactive detection lag) +
`EDGE_CLIENTCERT_REMINT_JITTER` + signer drain. A convergence stall extends the
compromised-trusted window, so the stuck alert is a page.

**Pre-rotation barrier (close the re-mint race).** The blacklist must **converge on
every CP replica** (each replica's authz-snapshot generation ≥ the disabling generation,
via a pod-labeled metric) **before** flipping `ca_id` — a precondition, not a parallel
step — else the compromised edge mints a fresh NEW-CA leaf off a lagging replica during
the overlap and survives the drop. Residual: a leaf minted in the sub-second
pre-convergence window (if the barrier was skipped) survives to the next rotation.

**The active-signer-fingerprint refinement (implemented).** `ca_id` convergence (step 3
above) proves the edge holds the OLD++NEW *bundle* but **NOT that its leaf is *signed by*
NEW**: `Sign()` appends the full served bundle to every leaf, so
`parapet_edge_clientcert_ca_id` is byte-identical for `active=old` and `active=new`. After
the OLD-drop the core's `ClientCAs={NEW}`, so an OLD-*signed* leaf fails verification → a
502 for that otherwise-good edge. So the active flip (step 4) is a **separate gated phase**
the revoke tool drives strictly *after* the ca_id widen barrier and *before* the drop, and
an **active-signer fingerprint** is threaded CP→edge→converge so the drop interlock
*cryptographically* asserts every good edge's leaf is NEW-signed, not merely inferred from
the bundle ca_id:
- CP: `Signer.ActiveFP()` (the sha256 of the CA actually signing) rides every
  cert/edge-cert/WAF/trust-bundle response (`X-Parapet-Signing-Cert-Fp` / `signing_cert_fp`)
  and the `parapet_edge_ca_active_signer_fp{ca_id,sigfp}` gauge. The signer reloader's no-op
  short-circuit keys on the **(ca_id, active-fp) tuple** so the `active=old→new` flip (an
  unchanged bundle ⇒ unchanged ca_id) actually installs the NEW signer instead of silently
  no-op'ing.
- Edge: `deriveIssuerFP` resolves *which* chain CA signed the live leaf
  (AuthorityKeyId==SubjectKeyId, exactly-one-match, fail-closed) → `SignerFP()` →
  `parapet_edge_clientcert_signer_fp`; the proactive re-mint triggers on a divergence on
  **either** axis (ca_id OR signer fp), so the flip re-chains the leaf to NEW.
- Drop interlock (`edgecp/converge`): the destructive gate additionally requires every CP
  replica + every good edge to be NEW-signed (`signer fp == NEW`), the blacklist to have
  converged on every replica (`authz gen == AuthzGeneration(post-revoke registry)`), and the
  **CP-authoritative issuance ledger** (`parapet_edge_ca_issued_total{edge_id,sigfp}`) to
  show the revoked id with **zero** issuances under NEW — a guarantee that does NOT rest on
  the (forgeable) edge self-report. The revoked id is **exempt** from the live-OLD vetoes (it
  is the intended casualty; vetoing on it would deadlock the revoke).

The CA-Secret state machine is `overlap`/`active=old` (`RotateCA`, a pure non-destructive
widen) → `active=new` (`SetActiveNew`, reversible) → `trimmed` (`TrimCA`, the destructive
NEW-only drop; requires `active=new` first so OLD isn't dropped while it is the active
signer). The `EDGE_CA_REVOKE` one-shot orchestrator sequences all of it, gating each
irreversible step on `converge-status` and resuming idempotently on retry.

### k8s client: the first write path (Job-only)

`GetSecret` + `UpdateSecret` are added but **`UpdateSecret` is invoked SOLELY by the
bootstrap/rotation Job**, never by serving, never by the core. Serving managed uses
`GetSecret` read-only at boot then the read-watch.

## Deployment & RBAC (self-managed CA, two ServiceAccounts)

Two SAs: `edge-controlplane` (serving, **read-only** — namespace-wide secrets
list/watch + a ClusterRoleBinding to the existing read ClusterRole, needed because
`WATCH_NAMESPACE=""` drives cluster-wide tenant-cert distribution) and
`edge-controlplane-bootstrap` (the Job, **scoped write** — `get,update` on
`resourceNames: [parapet-edge-ca]` in a CP-only namespace). The empty `parapet-edge-ca`
stub is pre-created with GitOps drift-exclusion (`Prune=false`, `ignoreDifferences` on
`/data` and `/metadata/annotations`). `controlplane.yaml` sets `serviceAccountName:
edge-controlplane`, `POD_NAMESPACE` via downward API, a hardened `securityContext`, and
a `readinessProbe` that is 503 until the cert store **and** (when issuance enabled) the
CA signer have loaded. `bootstrap-job.yaml`: `completions:1, parallelism:1,
restartPolicy:OnFailure`, finite `backoffLimit`, `ttlSecondsAfterFinished`, sequenced
before serving via the pre-install/PreSync hook — **and re-used as the rotation Job**.
The core keeps its existing RBAC and reads nothing from `parapet-edge-ca`. RBAC
self-probes fatal-log the exact missing binding on 403. etcd encryption-at-rest is a
prerequisite (the CA key lives in a Secret).

## Security model

**Trust boundary.** Exactly the edges holding a private key whose cert chains to the
dedicated edge CA. (No allow-set clause.)

**Spoofing.** A non-edge reaching `:443` cannot forge trust (`VerifiedChains` is
populated only after cryptographic verification against `ClientCAs`). The stamped SAN is
**audit-only and never load-bearing for trust**. The trust bundle is public; the defense
against a forged CA is **verified server-TLS, not a token** (which is why
`/v1/trust-bundle` safely drops the token while the secret/scoped endpoints keep theirs).

**Blast radius.** A leaked edge **leaf** key lets the holder spoof XFF **as the fleet**
(CA-only cannot scope a leaf to an IP or an id) until the CA is rotated out. The crown
jewel is still the edge CA key (the bootstrap Job GENERATES it once; serving replicas
read/HOLD it), forging the **entire fleet** if stolen, bounded **only by CA rotation**.
The CA Secret lives in a CP-only namespace (full key-read isolation). `allowed_sans` no
longer exists, so there is no broadcast roster.

> **Stolen leaf key / cloned edge box (an accepted CA-only consequence).** CA-only is
> pure chain-to-CA — no per-leaf pin, no IP binding. A leaf key exfiltrated from one edge
> and replayed from a **different IP** is cryptographically identical to the legitimate
> edge and **fully trusted**, indistinguishable from it; there is **no per-edge lever to
> kill just the clone** (blacklisting the token does not invalidate the already-stolen
> leaf). The only remedy is **CA rotation**. Because the leaf key is now long-lived (7 d,
> 168× the old 1 h), require the edge to hold the leaf key **in memory only** (never on
> disk), **recommend an optional non-exportable-key path** (TPM/PKCS#11 via
> `GetClientCertificate`) for high-value edges, and keep the SAN stamped so audit logs can
> **attribute** which edge identity a connection used — clone detection is an out-of-band
> log/anomaly concern, never a trust mechanism.

> **Honest consequences of the CA-only + 7-day + revoke-by-rotation model.** (1) Per-edge
> revoke = fleet-level CA rotation; no per-edge lever. (2) A compromised edge stays
> trusted until rotation completes (blacklist only stops re-minting). (3) CA rotation is
> now routine and safety-critical — a botched rotation (drop OLD before convergence) 502s
> the entire fleet. (4) We take **both** proactive overlap (no-blip steady path) and
> reactive (self-heals a missed poll), accepting the extra overlap complexity as the price
> of not 502-ing the fleet on every revoke. (5) Net safety improvement: trust is a pure
> cryptographic predicate with no operator-asserted string set in the per-request path —
> at the cost of coarser (fleet-wide) revocation granularity. The operator has accepted
> this tradeoff.

**Fail-closed.** A CP unreachable at first boot ⇒ `clientCAs` nil ⇒ mTLS branch false ⇒
edges distrusted (degraded-but-safe), CIDR branch unaffected. A bad/forged/empty/zero-cert
`ca_pem` ⇒ reject + keep last-good. A steady-state CP outage never drops existing trust;
a persistently-unreachable CP is a loud alert. **No path fails open.** The CP-outage budget
= `EDGE_CLIENTCERT_TTL` × renew-before-fraction (~4.6 days at 7 d), which must exceed the
CP recovery SLO. **CP HA (≥2 replicas) is REQUIRED.**

## Fail modes

| Failure | Behavior |
|---|---|
| **Operator blacklists the token (`disabled:true`) but never rotates the CA** | The compromised edge's already-minted leaf chains to the live OLD CA and stays **fully trusted** until expiry (≤7 d). Mitigated by the boxed top-of-section WARNING, the single `revoke --edge` tool that does both steps atomically, and `parapet_edge_token_disabled_without_rotation` firing until the CA generation that distrusts the leaf advances. The default-dangerous path — made impossible to miss. |
| **Blacklisted edge re-mints a NEW-CA leaf during the overlap (race across N stateless replicas)** | The blacklist must converge on **every** CP replica (pod-labeled authz-snapshot generation ≥ the disabling generation) **before** flipping `ca_id` — a barrier, not a parallel step. The pre-drop gate additionally asserts the revoked id has **no leaf under NEW** (verify absence). Residual: a leaf minted in the sub-second pre-convergence window (if the barrier was skipped) survives to the next rotation. |
| **Half-applied rotation (NEW added, OLD never dropped)** | Silent indefinite trust of the revoked edge — the worst outcome. Mitigated by the idempotent-per-phase state machine (`overlap\|converged\|trimmed` annotation + intent/deadline), `parapet_edge_ca_rotation_stuck` paging while stuck in `overlap` past deadline, and a re-runnable trim that never regenerates a third CA. |
| **Drop-OLD gated on a timer instead of measured convergence** | Forbidden. A hard convergence interlock across both planes (every CP replica reports NEW fingerprint + `OLD++NEW`; core reports `ca_id==new`; every good edge reports `parapet_edge_clientcert_ca_id==new`; revoked id absent under NEW); any unreporting/partitioned replica/edge blocks the drop (fail-closed); a loud logged override is the only bypass. |
| **Stolen leaf key replayed from a cloned box (different IP)** | Undetectable under CA-only (no per-leaf pin, no IP binding); fully trusted and indistinguishable from the real edge. Accepted consequence; the only remedy is CA rotation. Require memory-only key, recommend TPM/PKCS#11, keep the SAN for out-of-band audit attribution. |
| **`disabled:true` honored at only some authz call sites** | A disabled token could still mint via `/v1/edge-cert` or pull tenant **private keys** via `/v1/certs`. Required: a single chokepoint where `Known`/`Identity`/`Allowed` treat `disabled` (or deleted) as ABSENT — a full lockout. Residual: stops only future minting (rotation still mandatory for the live leaf). |
| **Reactive re-mint misclassifies a non-trust upstream error** | `forward.go`'s ErrorHandler today collapses all errors to a generic 502. Required: re-mint **only** on a `bad_certificate`/`certificate_unknown`/`unknown_ca` handshake alert, never on dial/timeout/HTTP-status; per-edge single-flight + backoff + a circuit-breaker after K no-`ca_id`-change attempts — so an unrelated core outage can't cause a fleet-wide re-mint storm / tight loop. |
| **Reactive-drop thundering herd → self-inflicted DoS on `POST /v1/edge-cert`** | Dropping OLD without confirming proactive convergence fails every good edge's handshake at once; all M edges re-mint against the per-replica-rate-limited, CPU-bound signer, which 429/503s and stalls convergence (extending the compromised-trusted window). Mitigated: proactive overlap is the mass path (convergence-gated drop is a no-op for good edges); reactive is the per-edge floor; jitter + backoff + `Retry-After` + single-flight. |
| **Replayed older trust-bundle un-trusts a re-minted fleet or re-trusts a dropped CA** | Forward-only/anti-rollback is load-bearing: the core swaps only on a strictly-advancing `generation` (resourceVersion-derived), rejects `generation<=held` (`parapet_trust_rollback_rejected_total`), over mandatory non-skippable verified server-TLS. |
| **Malformed/partial NEW CA PEM in the `OLD++NEW` overlap bundle** | Strict all-or-nothing parse on both core and edge (reject non-empty-yields-fewer-certs; never partial-append; keep last-good; bump the reject metric). The convergence gate asserts the core's pool actually contains the NEW fingerprint before any leaf is signed under NEW — a bad NEW block blocks the rotation loudly rather than half-applying it. |
| **CP unreachable at first boot / core restart during a CP outage** | First boot: `clientCAs` nil ⇒ CIDR-only (fail-closed); background retry flips to mTLS on the first valid bundle. Restart-during-outage: the warm-start file is a hint only (no trust until revalidated); `parapet_trust_source{file}` then `{mtls}`. A persistently-unreachable CP is a loud alert. CP HA required. |
| **Renewal failure inside the renew-before margin lets a leaf expire** | An expired client cert hard-fails the upstream handshake (502, same symptom as a CA drop). Guard: renew-before-fraction strictly in (0,1) with renew-instant leaving ≥ several `EDGE_REFRESH_INTERVAL` of slack, plus backoff+jitter retries; CP-outage budget = `TTL` × renew-before-fraction must exceed the CP recovery SLO. |
| **Bootstrap Job race / re-run / silent fail** | The `resourceVersion`-CAS linearizes concurrent Job pods (loser adopts); the anti-regeneration guard makes a re-blank a HARD ANOMALY (never regenerate); exit non-zero + re-GET-verify before exit 0; alerts on `kube_job_failed`, absence-of-populated-CA-after-deadline, and `parapet_edge_ca_generated_total > 1`. |

## Convergence metrics (observability)

The rotation is observable from Prometheus across all three planes. Every series is
labelled (or joined) by **`ca_id`** — the order-independent fingerprint of a CA *set*
(`caid.FromPEM`/`FromDER`, byte-identical wherever it is computed). All are
pure-instrumentation Prometheus metrics on the shared `parapet` registry / `:9187`
`/metrics` (the control plane adds a **separate** `:9187` listener; see below).

| Metric | Plane | Type | Labels | Meaning |
|---|---|---|---|---|
| `parapet_edge_ca_target_ca_id` | CP | gauge=1 | `ca_id` | **The convergence target** — the `ca_id` the serving CP signs under; what the fleet should reach. |
| `parapet_edge_ca_signer_fingerprint` | CP | gauge=1 | `ca_id` | The CA this CP replica signs under (== target on a healthy fleet). |
| `parapet_edge_ca_signer_generation` | CP | gauge=gen | `ca_id` | Monotonic generation of the serving signer; a lagging replica shows a stale value. |
| `parapet_edge_ca_bundle_certs` | CP | gauge=n | `ca_id` | CA count in the served bundle: **2 during `OLD++NEW` overlap**, else 1. |
| `parapet_edge_ca_signer_loaded` | CP | gauge 0/1 | — | 1 once a signer is loaded; 0 = CP up but not yet provisioned (vs scrape-missing). |
| `parapet_trust_bundle_generation` | core | gauge=gen | `ca_id` | The `ca_id`/generation the core currently trusts. |
| `parapet_trust_bundle_age_seconds` | core | gaugefunc | — | Seconds since the core last applied a bundle; rising fleet-wide = convergence stalled. |
| `parapet_trust_apply_total` | core | counter | `result` | `applied`/`rollback_rejected`/`floor_rejected`/`parse_rejected`/`empty_rejected` — `rollback_rejected` (in-session) and `floor_rejected` (cross-restart warm-start floor) are the anti-replay/anti-resurrection signals. |
| `parapet_trust_fetch_failed_total` | core | counter | — | Couldn't reach/decode the CP (vs reached-but-rejected). |
| `parapet_trust_source_total` | core | counter | `source` | Per-request trust decision: `cidr`/`verified-chain`/`none`. |
| `parapet_trust_warmstart_active` | core | gauge 0/1 | — | 1 while running on an unrevalidated warm-start floor (mTLS withheld, CIDR-only); 0 once a live fetch revalidates. Alert if it stays 1. |
| `parapet_edge_clientcert_ca_id` | edge | gauge=1 | `ca_id` | CA set that issued the edge's **live** client leaf (lags the target until the edge re-mints). |
| `parapet_edge_clientcert_not_after_seconds` | edge | gauge=unix | `ca_id` | Expiry of the edge's live leaf — an edge stuck on OLD with imminent expiry is the danger case. |
| `parapet_edge_clientcert_loaded` | edge | gauge 0/1 | — | 1 once the edge holds a usable client cert. |
| `parapet_edge_clientcert_remint_total` | edge | counter | `result`,`trigger` | `ok`/`keygen_fail`/… by `proactive`/`reactive`/`timer` — is the re-mint loop succeeding. |
| `parapet_edge_refresh_total` | edge | counter | `edge_id` | **Independent liveness** — bumped on EVERY successful CP poll regardless of `ca_id` change. The interlock gates on `increase(...) >= 1` so a wedged-but-scrapable edge frozen at the target can't false-green. |
| `parapet_edge_registry_total` | CP | gauge 0/1 | `edge_id` | The expected-edge reporter set (1=enabled, 0=blacklisted). The interlock reads `label_values(==1)` to discover which edges must converge. |
| `parapet_edge_authz_generation` | CP | gauge | — | Replica-identical fingerprint of the loaded token registry — the blacklist-barrier (B0) signal (all CP replicas must agree before a revoke flips the active CA). |

> **`edge_id` label.** Every edge convergence metric carries an `edge_id` (from `EDGE_ID`,
> matching the CP token id) so the interlock joins per-edge by a reschedule-stable key, not
> the ephemeral pod/`instance`. A scrape-config `edge_id` relabel (kube-SD) should be
> asserted to match the in-metric `edge_id`. Duplicate ids are refused at CP startup.

**Convergence model — all three planes reach the CP target `ca_id`.** Because `Sign()`
appends the full served bundle (`OLD++NEW` during overlap) to every leaf, the edge's
`ca_id` (computed over its chain's CA blocks) equals the CP/core `ca_id` *once the edge
re-mints*. So convergence is a single predicate against the self-describing target
series — no hardcoded value, no recording rule:

```promql
# CP target ca_id (one series); compare every plane to its label value.
parapet_edge_ca_target_ca_id                      # → {ca_id="<TARGET>"} 1
# Edges NOT yet converged (still on the old CA — the re-mint lag indicator):
count(parapet_edge_clientcert_ca_id) by (instance)
  unless on() group_left() (parapet_edge_ca_target_ca_id * 0
    + on(ca_id) group_right() parapet_edge_clientcert_ca_id)
```

The edge lags by design (it converges when it re-mints); a non-zero lagging count is
*expected* during a rotation and must drain before OLD is dropped (the sub-PR 4/5
interlock gates the destructive drop on exactly this).

**Operational caveats (read before writing alerts):**
- **`ca_id` is a set fingerprint, never key material** (public-cert SHA-256). Safe as a label.
- **Aggregate `ca_id` vecs with `max by (instance)`, never `sum`** — mid-rotation a replica
  transiently emits both the overlap and a single-CA `ca_id`, so `sum` double-counts.
- **Cardinality is bounded, not free.** Each vec is `Reset()`-then-`Set()` so exactly one
  live series exists *per process*; across TSDB retention the distinct `ca_id` count is
  bounded by `rotation_rate × retention × 3` (overlap), not unbounded. There is a
  sub-microsecond `Reset→Set` absence window on each swap — a known benign flap; don't alert on it.
- **`source=verified-chain` undercounts** dual-path edges: `cidr` takes precedence in the
  per-request decision, so an edge that *also* matches a trusted CIDR counts as `cidr`. A
  `verified-chain` flatline *after* a rotation is still the earliest convergence-failure signal.
- **Pod identity comes only from scrape relabeling** (kube-SD `job`/`pod` labels), never an
  in-process label. The `count(... ) == count(up{job})` style predicate depends on the
  deploy wiring those labels.

**Control-plane `/metrics` is a new, unauthenticated `:9187` listener** (`CP_METRICS_LISTEN`,
default `:9187`, set `""` to disable). It is **separate** from the token-gated API mux, so a
scraper reaches it without the bearer token. The payload is non-secret (fingerprints,
counters, generations — no key material), but rotation/generation transitions are observable
recon, so **a NetworkPolicy must restrict it to the scraper** (shipped in
`deploy/edge/controlplane.yaml`). The listener starts **only in the serving process** — the
run-once bootstrap/rotate Jobs `os.Exit` before it. A failed metrics bind is logged loudly but
**not fatal** — the CP keeps serving issuance + trust distribution (its primary job must never be
taken down because an observability port is contended); a missing `/metrics` is already loud as
the scrape target's `up == 0`, and the convergence interlock fails closed on a non-reporting target.

**Run-once Job observability is logs, not scraped counters.** `EnsureCA`/`RotateCA` run in
Jobs that `os.Exit` before any scrape, so CA-generated / unexpected-empty events are
**structured `slog` lines + non-zero exit codes** (alert via `kube_job_failed`), deliberately
not Prometheus counters (a Pushgateway would be a new failure domain).

## Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `TRUST_PROXY` | core | `cloudflare` | **Unchanged** — the `cidrTrust` OR-branch. Never add edge egress CIDRs here. |
| `CP_METRICS_LISTEN` | CP | `:9187` | Separate unauthenticated `/metrics` listener (serving process only); `""` disables. Restrict via NetworkPolicy. |
| `EDGE_TRUST_CP_ENDPOINT` | core | `""` (off) | HTTPS base URL of the CP. Set ⇒ the core pulls `GET /v1/trust-bundle`. **MUST be `https://`** — non-https is fatal, no plaintext analog ever. |
| `EDGE_TRUST_CP_CA` | core | `""` | PEM of the CA that signs the **CP server** cert → `RootCAs`. **Mandatory + fatal** if missing/empty/unparseable; no system-roots fallback, no skip-verify. Dedicated single-purpose CA; distinct from the edge CA in `ca_pem`. |
| `EDGE_TRUST_CP_WATCH_TIMEOUT` / `_POLL_INTERVAL` | core/CP | `30s` / `5m` | Long-poll ceiling; safety-net poll. The poll now bounds **CA-rotation** propagation only (not per-request revocation), so it may lengthen; keep the long-poll for fast rotation convergence. |
| `EDGE_TRUST_CP_CACHE_FILE` / `_MAX_STALE` | core | `""` (off) / `3600` (s, =1h) | Warm-start cache. After every successful poll the core persists `{generation, ca_id, ca_pem, written_at}` (public; atomic temp+rename) and on startup loads its generation as an anti-rollback **floor** (a bundle below it ⇒ `trust_apply_total{result="floor_rejected"}`), so a restart-during-outage can't resurrect a rotated-out CA via a stale CP replica. It confers **NO trust** until a live fetch revalidates — the cached CA is **not** loaded into `ClientCAs`, so trust stays CIDR-only meanwhile (`trust_warmstart_active=1`) and flips to mTLS on the first live apply. `written_at` tracks last CP **contact** (refreshed on 304s too), so `_MAX_STALE` (seconds) bounds time-since-contact: a longer outage discards the floor and cold-starts (larger = safer vs. resurrection; smaller = recovers faster from a CP-side generation reset). |
| `EDGE_TRUST_REQUIRE_SAN` | core | **forced false, deprecated** | CA-only is the only model; the per-request SAN check is removed. Setting `true` with CP-issuance is a **fatal config error**. Slated for removal. |
| `EDGE_DATAPLANE_MTLS` | edge | `false` | Enable the CP-issued client cert. Requires `EDGE_UPSTREAM_TLS=true`. Readiness gated on a loaded cert. |
| `EDGE_ID` | edge | hostname | The edge's STABLE logical id, stamped as the `edge_id` label on every convergence metric (the OLD-drop interlock joins per-edge by it). **Required with `EDGE_DATAPLANE_MTLS=true`** and **must match this edge's CP token id**. Without mTLS, defaults to the hostname (convergence is moot). |
| `EDGE_CLIENTCERT_TTL` | CP | **`168h` (7 d)** | Issued **leaf** lifetime (was 1 h). Buys a ~multi-day CP-outage budget (= `TTL` × renew-remaining-fraction ≈ 4.6 d). Renewal stays remaining-life (≤ 0.66×TTL, ~4.6 d remaining). The paired-knob guard: renew-before-fraction in (0,1) with ≥ several `EDGE_REFRESH_INTERVAL` of slack before expiry. |
| `EDGE_CLIENTCERT_REMINT_JITTER` | edge | `60s` (≥ signer drain) | Max random delay before a force-re-mint (proactive or reactive), to prevent a re-mint thundering herd when `ca_id` flips fleet-wide. With exponential backoff + `Retry-After` + per-edge single-flight + a no-`ca_id`-change circuit-breaker. The periodic poll loops also jitter their FIRST tick by `[0,EDGE_REFRESH_INTERVAL]` so the signal-delivery instants decorrelate, not just the mints. |
| `EDGE_CLIENTCERT_REMINT_BACKOFF_BASE` / `_COOLDOWN` | edge | `2s` / `5×EDGE_REFRESH_INTERVAL` | Exponential-backoff base on a non-ok mint (×2, jittered, capped at `EDGE_REFRESH_INTERVAL`); breaker-open cooldown. |
| `EDGE_CLIENTCERT_REMINT_BREAKER_K` / `_PROACTIVE_J` | edge | `3` / `5` | Open the **reactive** breaker after K consecutive ok-mints that don't change `ca_id` (a core-side reject re-minting can't fix); the **proactive** breaker after J ok-mints that don't reach the observed target. Transient (non-ok) mints never feed either — they're the backoff path. A genuine `ca_id` flip / convergence resets. |
| `EDGE_CLIENTCERT_RENEW_REMAINING_FRACTION` | edge | `0.66` | Remaining-life renewal floor: re-mint when `remaining ≤ fraction × the leaf's own lifetime`. The timer floor that converges even a zero-signal edge; keep `(1-elapsed)×TTL > CP-recovery SLO`. |
| `CP_EDGE_SIGN_CONCURRENCY` / `CP_EDGE_SIGN_RETRY_AFTER` | CP | `GOMAXPROCS` / `5s` | Bound concurrent edge-cert signs; shed the rotation re-mint surge with `503 + Retry-After` (the only fleet-aggregate backpressure — one token per edge doesn't bound the aggregate). The edge coordinator honors the `Retry-After`. |
| `EDGE_CLIENTCERT_KEY_TYPE` / `_SKEW` / `_RATE` | edge/CP | `ecdsa-p256` / `10m` / `10/min` | Ephemeral key type; NotBefore backdate (negligible vs 7 d, but NTP between CP and core stays a prerequisite); per-token issuance limit (**per-replica**, effective N×). |
| `EDGE_CA_BOOTSTRAP` / `--bootstrap-ca` | CP (Job) | false | One-shot CA bootstrap **and rotation** mode (`EnsureCA`: adopt/generate/never-regenerate, CAS-guarded). The only writer of the CA Secret. |
| `EDGE_CA_CERT` / `_KEY` | CP | `""` (⇒ managed) | Provided mode (mounted CA). Both-or-neither. Absent ⇒ managed (the Job generates). |
| `EDGE_CA_PROVIDED_GENERATION` | CP | cert mtime | Provided-mode trust-bundle generation (managed mode derives it from the CA Secret's `resourceVersion`). **MUST strictly advance on each provided-CA rotation** or the core rejects the new bundle as a rollback. |
| `EDGE_CA_SECRET` | CP | `parapet-edge-ca` | The CA Secret in a CP-only namespace; Job writes (scoped), serving reads (read-only + read-watch). Pre-created empty, GitOps drift-exclusion. |
| `EDGE_CA_TTL` | CP | `8760h–17520h` (1–2 y) | Edge CA cert lifetime. **Shortened** from 10 y now that rotation is a routine on-demand primitive — but kept comfortably longer than the expected revoke-driven rotation interval so a scheduled CA expiry doesn't collide with on-demand rotations. |
| `POD_NAMESPACE` / `WATCH_NAMESPACE` | CP | downward API (**required**) / `""` | CA Secret namespace (read serving-managed, write Job); pin `WATCH_NAMESPACE` to shrink the cluster-wide tenant-TLS read blast radius. |
| `EDGE_CONVERGE_STATUS` | CP (Job/CLI) | false | Run-once **convergence reader**: query Prometheus, exit 0 only if every plane reached the target `ca_id`, else 1 with named blockers. **Read-only** — what sub-PR 5's revoke Job calls before the OLD-drop. Never on the serving path. |
| `EDGE_CONVERGE_PROM_URL` / `_EXPECTED_CP` / `_EXPECTED_CORE` / `_MIN_EDGES` | CP (Job) | — | Prometheus API base; expected CP-replica and core counts; and the **edge-count floor** (a registry/scrape drift that empties the expected-edge set must fail closed, not converge vacuously — `MIN_EDGES` ≤ 0 is itself refused). A missing reporter ⇒ count mismatch ⇒ block. |
| `EDGE_CONVERGE_FRESHNESS` / `_STABLE_READS` / `_POLL_INTERVAL` / `_SCRAPE_INTERVAL` | CP (Job) | `5m` / `2` / `30s` / `15s` | Liveness window; consecutive converged reads required; gap between them; the scrape interval. The reader **refuses** unless `poll × reads ≥ 2×scrape` AND `≥ EDGE_REFRESH_INTERVAL` (a flap can't read as converged). |
| `EDGE_CONVERGE_EXCLUDE` | CP (Job) | `""` | `id=reason,…` — LOUD, reason-required convergence-veto waivers for decommissioned edges (echoed in the verdict; an empty reason is refused). |
| `EDGE_CONVERGE_REVOKED_TOKEN` / `_CP_URL` / `_CP_CA` | CP (Job) | `""` | The revoked token + CP endpoint for the absence probe (must be rejected 401/403). Absent ⇒ `revoked-unverified` (fail-closed). |
| `EDGE_CONVERGE_EXPECTED_CA_ID` / `_SIGNER_FP` / `_AUTHZ_GEN` / `_REVOKED_EDGE_ID` | CP (Job) | `""` / `""` / `0` / `""` | Drop-checkpoint pins. `EXPECTED_CA_ID` pins the resolved target to *this* rotation. Setting `EXPECTED_SIGNER_FP` (the NEW signing fp) switches the predicate from the ca_id widen barrier to the destructive OLD-drop gate: every CP replica + good edge must be NEW-signed, `AUTHZ_GEN` (the post-blacklist `AuthzGeneration`) must match on every replica, and `REVOKED_EDGE_ID` must have zero NEW issuances (and is exempt from the live-OLD vetoes). `SIGNER_FP` set without `AUTHZ_GEN` is a refused half-interlock. |
| `EDGE_CA_REVOKE` | CP (Job) | false | Run-once **revoke orchestrator**: drives the full phased rotation (widen → wait Gate A → flip → wait Gate B → trim), gating each irreversible step on convergence. Requires `EDGE_CA_REVOKE_EDGE_ID`, `EDGE_CONVERGE_PROM_URL`, the live probe inputs, and the post-blacklist `CP_TOKENS` (preflight refuses unless the id is present-and-`disabled`). Idempotent/resumable; a timeout leaves the rotation at its last completed step. |
| `EDGE_CA_REVOKE_EDGE_ID` / `EDGE_CA_REVOKE_TIMEOUT` | CP (Job) | `""` / `30m` | The edge id to sever; the per-gate convergence-wait deadline (a timeout never drops OLD — re-run resumes). |

Registry shape: `{"<token>":{"id":...,"domains":[...],"disabled":bool}}`. New trust-bundle
field `ca_id`. Metrics: `parapet_trust_source{mtls|cidr|none|file}`,
`parapet_trust_reload_rejected_total`, `parapet_trust_rollback_rejected_total`,
`parapet_trust_bundle_age_seconds` (core); `parapet_edge_clientcert_loaded`,
`parapet_edge_clientcert_not_after`, **`parapet_edge_clientcert_ca_id`**,
**`parapet_edge_clientcert_signer_fp`**, `parapet_edge_cp_active_signer_fp` (edge);
**`parapet_edge_token_disabled_without_rotation`**, **`parapet_edge_ca_rotation_stuck`**,
`parapet_edge_ca_generated_total`, `parapet_edge_ca_unexpected_empty_total`,
`parapet_edge_ca_signer_fingerprint`, **`parapet_edge_ca_active_signer_fp`**,
**`parapet_edge_ca_issued_total{edge_id,sigfp}`** (the CP-authoritative issuance ledger),
`parapet_edge_ca_signer_active_flip_failed`, `parapet_edge_authz_generation` (CP,
pod-labeled). **Removed:**
`parapet_trust_allowed_sans_count` and the deterministic-SAN-serialization-before-etag
requirement.

## Onboarding flow (the payoff)

1. **One-time, code-only:** deploy the two SAs + RBAC, pre-create the empty
   `parapet-edge-ca` stub (CP-only namespace, GitOps drift-exclusion), set
   `POD_NAMESPACE`, and ship the **bootstrap Job as a pre-install/PreSync hook before
   serving**. On first install the Job generates+persists the edge CA (managed) — no
   openssl, no cert-manager. The core points `EDGE_TRUST_CP_ENDPOINT` + `EDGE_TRUST_CP_CA`
   and pulls the public CA + `ca_id` over `GET /v1/trust-bundle`.
2. **Per edge — grant identity (one registry edit).** Add the edge's entry with an `id`
   (now labeling/audit, **not** a trust grant). This authorizes its cert/WAF fetch and
   makes the CP issue its leaf via `POST /v1/edge-cert`.
3. **Configure the edge:** `EDGE_DATAPLANE_MTLS=true`, `EDGE_UPSTREAM_TLS=true`,
   `EDGE_UPSTREAM_ADDR` → core `:443`. Docker edge: only input stays `EDGE_CP_TOKEN`.
4. **Deploy + verify.** Confirm `parapet_trust_source{mtls}` and that the core's active
   CA set / `ca_id` reflects the CA (worst-case convergence one `EDGE_TRUST_CP_POLL_INTERVAL`).
5. **Revoke — see the boxed warning and the runbook below.**

### Revoke an edge

> ⚠️ **Blacklisting a token does NOT revoke trust** — see [Revocation](#revocation--ca-rotation).
> For a real compromise, CA rotation is mandatory.

**Implemented as the `EDGE_CA_REVOKE` run-once Job** (`runRevoke`), one idempotent,
resumable gesture (resumable via the rotation-phase annotation + per-step CAS):
(0) **operator blacklist** — set `disabled:true` in `CP_TOKENS` (preferred over delete; a
full lockout) and restart the serving CPs (the hot authz-watch is deferred); the Job's
preflight **refuses** unless the id is present-and-`disabled` and derives the
`ExpectedAuthzGen` pin from that same registry. Then the Job: (1) **widen** the bundle to
OLD++NEW (`RotateCA`); (2) **wait Gate A** — every CP+core+edge holds OLD++NEW (`ca_id`
converged); (3) **flip** the active signer to NEW (`SetActiveNew`); good edges re-mint
under NEW (proactive, jittered); (4) **wait Gate B** — the destructive-drop interlock:
every CP replica + good edge NEW-*signed* (the active-fp gates), the blacklist converged
on every replica (`authz gen`), the revoked id with zero NEW issuances, and the live probe
rejecting the token; (5) **drop** OLD (`TrimCA`) — the revoked edge's OLD-CA leaf stops
verifying and it is distrusted. A gate timeout leaves the rotation at its last completed
step (re-run resumes) and never drops OLD. Never expose a bare `blacklist` verb that does
only step (0) without loudly printing "TRUST NOT YET REVOKED — run revoke";
`parapet_edge_token_disabled_without_rotation` fires until the rotation completes.

## Phasing

1. **Phase 1 — the primary mechanism.** Core: the CA-only closure (`cidrTrust OR
   verified-chain`), `GetConfigForClient` hot-swap, the tokenless `TrustCpClient`
   long-poll (mandatory server-TLS, forward-only resourceVersion-derived generation,
   strict all-or-nothing parse, warm-start hint), the `X-Forwarded` strip, the metrics.
   CP-issuance: `POST /v1/edge-cert`, the signer, the **`disabled` tombstone full
   lockout**. Trust-bundle `{generation, ca_pem, ca_id}`. **Managed-CA via the run-once
   bootstrap Job** (CAS + anti-regen guard inside the Job). **Stateless-HA serving**.
   The **force-re-mint trigger** (`ca_id` on `/v1/waf` + proactive re-mint + the narrow
   reactive classifier + jitter/backoff/circuit-breaker). The **convergence-gated overlap
   CA rotation** (now the revocation primitive — moved from Phase 2) and the **`revoke
   --edge` tool**. `NetworkPolicy` locking core `:80`/`:443` and the CP.
2. **Phase 2 — stronger hardening.** Edge pins the core CA (drop `InsecureSkipVerify`);
   an **HSM/KMS `Signer`** so the raw CA key never sits in pod memory; the **non-exportable
   leaf key path** (TPM/PKCS#11) for high-value edges; CRL/OCSP; real SPIRE SVID
   migration.
3. **Phase 3 — optional `TRUST_PROXY_DYNAMIC` CIDR companion** for callers that cannot
   present a client cert.

## Alternatives considered

- **SAN allow-set per-request trust (the prior design, removed by decision).** It gave
  per-edge revocation in seconds (drop the registry entry → SAN leaves the allow-set), at
  the cost of a per-request operator-asserted string set the CP was the sole uncross-checked
  authority for, a cross-binary derivation, and a single-fleet-widening-bug surface. Removed
  in favor of CA-only: a pure cryptographic trust predicate with no silent trust-widening —
  **trading per-edge instant revocation for coarser, fleet-wide revoke-by-CA-rotation.** The
  operator accepted this; `EDGE_CLIENTCERT_TTL=7d` + the `revoke --edge` tool make the
  rotation the explicit, tooled revocation path.
- **CP mints key+cert and ships both.** Rejected (puts a private key on the wire); CSR-based
  keeps the key edge-local.
- **Token-gated `TrustProxy` (HMAC header) / dynamic IP list / SPIFFE-SPIRE.** Rejected as
  primary (replayable header / no security-bar raise / out-of-cluster attestation infra);
  the SAN naming is grafted from SPIFFE.
- **cert-manager-issued CA.** Removed (CRD dependency + out-of-band CA creation defeats the
  zero-PKI goal). The bootstrap Job self-manages the CA; provided mode covers existing PKIs.

## Open questions

- **`revoke --edge` tooling form** (subcommand vs CLI vs Job) and the metric-read channel
  it uses to gate the OLD-drop (Prometheus query / a CP convergence-status endpoint).
- **`ca_id` channel:** confirm `ca_id` on `GET /v1/waf` (cheapest) — but `/v1/waf` is only
  fetched on `EDGE_REFRESH_INTERVAL` and a serve-no-WAF edge still needs the signal; verify
  every edge polls it even with WAF distribution off, or attach `ca_id` to `/v1/certs` too.
- **Convergence gate vs a permanently-dead edge:** the interlock blocks the drop on any
  non-reporting good edge (fail-closed) — but a dead edge would block every revoke forever.
  Define the operator-override and how a decommissioned (vs partitioned) edge is excluded
  without re-introducing a per-edge allow-set.
- **`EDGE_CLIENTCERT_REMINT_JITTER` vs signer capacity:** the jitter window must exceed the
  fleet's signer drain (M edges / (N replicas × rate × sign-cost)); does a rotation need a
  temporary signing-capacity bump or a fleet-size-aware jitter default?
- **Circuit-breaker K** default and its coupling to `EDGE_REFRESH_INTERVAL`.
- **`EDGE_CA_TTL` shortening (1–2 y):** confirm the shorter CA TTL doesn't itself trigger a
  forced rotation (and a fleet re-mint) on an inconvenient cadence — keep it comfortably
  longer than the expected revoke-driven rotation interval.
- **Non-exportable leaf key (TPM/PKCS#11):** Phase 2, or required now given the 7-day (168×)
  leaf-key exposure window for compromise-sensitive deployments?
- **Generation source** (resourceVersion opacity / UID-reset handling), **purge journal**
  externalization before `replicas>1`, **hard global signing cap**, **long-poll concurrency
  cap default**, **CP HA enforcement**, **first-boot cluster ordering**, **empty-stub
  feasibility** (Opaque vs `kubernetes.io/tls`) — unchanged from prior rounds.

## Conformance / contract

On acceptance, fold into [`SPEC.md`](SPEC.md): the predicate (`cidrTrust OR
verified-edge-CA-chain` — no SAN clause); `POST /v1/edge-cert` and the **tokenless**
`GET /v1/trust-bundle` (`{generation, ca_pem, ca_id}`, `?watch` long-poll, no 401/403);
the managed (bootstrap-Job) / provided CA model, the **stateless-serving + run-once-Job**
posture, and **CA rotation as the revocation primitive** (overlap bundle + convergence
interlock); the **`disabled` tombstone** full-lockout; the content-derived generation
contract; the force-re-mint trigger; the new env vars; the `X-Forwarded` strip. Conformance
tests: (1) **DELETE** "a known-revoked id absent from a fresh `allowed_sans`" (the mechanism
no longer exists); (2) **KEEP** "`identityFor()` == the SAN `Signer.Sign` stamps" but
**re-scoped as a labeling/audit check, explicitly NOT a trust check**; (3) **ADD** the
load-bearing trust test: `x509.Verify` of an edge leaf against the trust-bundle `ca_pem`
pool returns a non-empty chain, plus the NameConstraints accept/reject pair; (4) **ADD** a
rotation test: an `OLD++NEW` overlap `ca_pem` verifies leaves under **both**; after trim, an
OLD-CA leaf fails; the strict all-or-nothing parse rejects a truncated NEW block (keep
last-good); (5) **ADD** a disabled-token test: a `disabled` entry is treated as UNKNOWN at
`Known`/`Identity`/`Allowed` (no mint, no `/v1/certs`, no `/v1/waf`); (6) the two-goroutine
concurrent-generate CAS test against client-go fake. The Rust implementation in
[`rust/`](rust/) tracks the same contract or records a divergence.

[TLS SNI fallback memory]: the proxy serves a self-signed fallback on an SNI miss when the
live cert table loses `GetCertificate`; the `GetConfigForClient` self-test prevents
re-introducing that class of bug during a trust reload.
