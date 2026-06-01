# Auto-trust edge proxy (data-plane trust without a restart)

> **Status: DRAFT / design-only — not implemented.** This proposes how the
> in-cluster **core** proxy (`cmd/parapet-ingress-controller`, "parapet") comes to
> trust a newly-deployed **edge** proxy (`cmd/edge-proxy` + [`edge/`](edge/))
> automatically — without an operator editing `TRUST_PROXY` and restarting the
> core. It builds on the edge architecture in [`EDGE.md`](EDGE.md). Per
> [`CLAUDE.md`](CLAUDE.md), the behavior contract changes in [`SPEC.md`](SPEC.md)
> first; on acceptance, the contract bits (the trust predicate, the new env vars,
> the new `POST /v1/edge-cert` endpoint, the per-request order) fold into `SPEC.md`
> and the architecture into `EDGE.md`. **No cert-manager dependency:** the control
> plane self-manages the edge CA.

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
that is **hot-swapped** from a watched Kubernetes Secret — exactly the
`debounce` + validate-then-swap idiom the WAF reload already uses
(`controller_waf.go`), which never rebuilds the route mux. **No restart.** The
question is only *what credential the edge presents* and *where the trust policy
comes from*.

## Recommended design: edge mTLS (client-cert-as-trust)

Authenticate the **edge → core hop with mutual TLS**. Trust follows a private key,
not a source IP.

1. **A dedicated, single-purpose edge CA.** Created once and reused forever; it
   signs **nothing else**, so "chains to this CA" means exactly "is a sanctioned-edge
   credential." By default (**managed** mode) the **control plane generates the CA on
   first boot and persists it** to its own RBAC-locked `parapet-edge-ca` Secret — no
   cert-manager, no out-of-band openssl. For orgs with an existing PKI, **provided**
   mode lets the operator mount their own CA (`EDGE_CA_CERT`/`EDGE_CA_KEY`) and the CP
   uses it without generating. Either way the key never reaches an edge — only leaf
   certs do. See [Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert).

2. **Each edge gets a short-lived client cert with a stable URI SAN
   `spiffe://parapet.moonrhythm.io/edge/<id>`.** By default the **control plane
   issues it** over the edge's existing bearer-authenticated HTTPS channel — the
   edge sends a CSR to `POST /v1/edge-cert`, the CP signs it with the edge CA and
   returns only the cert chain; the **private key never leaves the edge**, and the
   **CP decides the SAN from the token identity** (ignoring any SAN in the CSR), so a
   compromised edge cannot request a SAN it isn't entitled to. Renewal is generous
   (renew at ~⅓ lifetime *remaining*) so it never races expiry — see
   [Edge wiring](#edge-wiring).

3. **The edge presents it** on the re-encrypt hop. `edge/forward.go`'s
   `EDGE_UPSTREAM_TLS=true` path gets the client cert via
   `tls.Config.GetClientCertificate` — a **live callback** reading the in-memory
   cert, so a renewal is picked up with **no edge restart**. A client cert can only
   ride TLS, so edge trust is conferred **only on the core's `:443` listener**; the
   plaintext `:80` listener can present none and is never mTLS-trusted.

4. **The core verifies it.** The `:443` `tls.Config` gets
   `ClientAuth = tls.VerifyClientCertIfGiven` (the cert is **optional** —
   Cloudflare-direct and browser traffic present none and complete the handshake
   unchanged) and a `ClientCAs` pool sourced from the watched trust Secret. The
   standard library cryptographically verifies any presented client cert (with
   `ExtKeyUsageClientAuth`) against `ClientCAs` during the handshake and, on
   success, populates `r.TLS.VerifiedChains`. A presented-but-unverifiable cert
   **aborts the handshake**.

5. **The per-request trust predicate** (installed once; see [Core wiring](#core-wiring)):

   ```
   trust(r) :=  cidrTrust(r)                                  // existing TRUST_PROXY (e.g. cloudflare)
            OR ( len(r.TLS.VerifiedChains) > 0                // a chain verified to the edge CA, AND
                 AND leafURISAN(r) ∈ liveAllowSet )           // its SAN is in the live allow-set
   ```

   The SAN check is re-evaluated **per request** against an `atomic.Pointer`-held
   allow-set, so **dropping a SAN distrusts that edge within ~300 ms** — even on
   existing keep-alive / HTTP-2 connections. That is the fast per-edge revocation
   lever (but **not** a defense against a stolen *CA* key — see the Security model).

### Single source of truth (onboard in one place)

The SAN allow-set is derived from the **same `edge-controlplane-tokens` Secret the
control plane already authorizes against** (`edgecp.Authz`, `edgecp/authz.go`).
The registry shape becomes `{ "<token>": { "id": "<edge-id>", "domains": [...] } }`,
where `id` is an **explicit, separate opt-in grant** of a data-plane identity.

**Onboarding/offboarding touches one registry:**

- Adding an entry with an `id` → the control plane issues that edge's data-plane
  cert (stamping its SAN) **and** the core adds the same SAN to its allow-set.
- **Deleting an entry = data-plane revoke** in ~300 ms, closing the split-brain
  where revoking only the control-plane token left the edge trusted until its cert
  expired.

The SAN in the minted cert and the core's allow-set entry are byte-identical **by
construction**, because both derive from the one registry via **one shared function
in one package, imported by BOTH `cmd/edge-controlplane` (the signer) and
`cmd/parapet-ingress-controller` (the core allow-set)** — never two independent
`identityFor()` implementations (a split-brain bug waiting to happen: e.g. one side
lowercasing the id, the other not, as `authz.go:27` already lowercases domains).
Canonical form: `spiffe://parapet.moonrhythm.io/edge/<id>` where `<id>` is
**lowercased, trimmed, NFC-normalized, and validated as a SPIFFE path segment** (no
`/`, no whitespace, bounded length) — **rejected fail-closed at load time on BOTH
sides** if invalid. A conformance test asserts CP-stamped-SAN == core-allow-set
entry for a fixed registry fixture.

The identity is **never auto-derived** from the token's domains or its mere
presence: a serve-all (`"*"`) token gets **no** data-plane identity by default
(widest blast radius), and an existing registry **migrates to no identity** for
every token — preserving "feature off ⇒ identical to today." The add/delete
reload-skew between the two planes (~one debounce each) is **fail-closed in both
directions**: a SAN in the allow-set with no live cert is harmless; a minted cert
whose SAN isn't yet trusted just degrades to untrusted. Both planes expose the
registry generation/hash they last applied as a metric, so an operator can confirm
convergence before declaring an edge trusted.

## Deployment models: k8s edge vs Docker edge

There are two edge deployment shapes, and the data-plane client cert must work for
**both** with the same onboarding gesture ("provision one token"). The cert always
arrives the same way — the CP issues it via `POST /v1/edge-cert`; only how the edge
is packaged differs:

**k8s edge.** The edge runs as a Deployment in some cluster (its own or the core's).
The data-plane client cert rides `POST /v1/edge-cert` exactly as for Docker. An
operator who already runs cert-manager and wants to *mount* a client cert can still
do so via the legacy `EDGE_UPSTREAM_CLIENT_CERT`/`_KEY` file path — but that is a
mount detail on the edge, **not a CA mode on the CP**. cert-manager is no longer part
of this design.

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

The payoff is uniformity: the Docker edge's onboarding stays "add one token to the
registry," and the same token edit that authorizes its key/WAF fetch also makes the
CP issue its data-plane identity **and** adds that identity to the core's allow-set.

## Core wiring

In `cmd/parapet-ingress-controller/main.go`, replace the one-shot `trustProxy`
block (`:214-237`) — but keep the existing static parse **verbatim** into a fixed
local `cidrTrust` (`"true"` → `parapet.Trusted()`; `"false"`/`""` → nil; else
`parapet.TrustCIDRs(list)` with the `predefinedCIDRs["cloudflare"]` expansion from
`config.go`). Add a trust-policy holder owned by the controller:

```go
type trustPolicy struct{ allowedSANs map[string]struct{} }
var trustPol   atomic.Pointer[trustPolicy]
var clientCAs  atomic.Pointer[x509.CertPool]   // SEPARATE atomic from the SNI cert table
```

Install **one** closure, assigned to **both** servers' `TrustProxy` field (as
today):

```go
trustProxy = func(r *http.Request) bool {
    if cidrTrust != nil && cidrTrust(r) { return true }       // metric: cidr
    if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 { return false } // metric: none
    p := trustPol.Load(); if p == nil { return false }
    if requireSAN { return sanAllowed(r.TLS.PeerCertificates[0], p.allowedSANs) }
    return true // CA-only mode (EDGE_TRUST_REQUIRE_SAN=false): any chain to the dedicated edge CA
}
```

`sanAllowed` matches the leaf's **URI** SANs (`r.TLS.PeerCertificates[0].URIs`)
*exactly* against the allow-set — URI-typed, never substring. The `:80` server's
`r.TLS == nil` short-circuits the mTLS branch, leaving CIDR-only — byte-for-byte
today's plaintext behavior.

**Hot-swap `:443` `ClientCAs` without clobbering the SNI cert table.** Do **not**
clone and replace the whole `tls.Config` on a trust reload (that path risks
dropping `GetCertificate` and regressing into the self-signed-fallback gotcha — see
the [TLS SNI fallback memory]). Instead set, once, before `Serve()`:

```go
base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
    c := base.Clone()
    c.ClientCAs = clientCAs.Load()   // fresh per handshake; never nil
    return c, nil                    // carries GetCertificate = ctrl.GetCertificate (live), ClientAuth, fallback
}
```

`GetConfigForClient` must be non-nil before `Serve()` and must **never** return nil
(return last-good on any error). A startup **self-test** asserts the served config
carries `GetCertificate` **and** `ClientCAs` **and**
`ClientAuth == VerifyClientCertIfGiven`.

### The trust watch

`controller.go` + a new `controller_trust.go` mirroring `controller_waf.go`: a 6th
watcher, gated by `EDGE_TRUST_SECRET != ""` (default off ⇒ identical to today).
Reuse the generic `watchResource[*v1.Secret]` for `POD_NAMESPACE`; on change call
`reloadTrustDebounced` (a 300 ms `debounce`). It **never rebuilds `ctrl.mux`** (trust
is orthogonal to routes) and is **validate-then-swap, all-or-nothing** like WAF
`SetRules`. Parse the CA bundle: read key **`tls.crt`** first (the managed
`kubernetes.io/tls` `parapet-edge-ca` Secret), falling back to `ca.crt` (a
hand-rolled bundle / provided-mode convention); whichever is non-empty is fed to
`x509.NewCertPool().AppendCertsFromPEM`. A **non-empty input that yields zero certs
is rejected** (keep last-good, log, bump `parapet_trust_reload_rejected_total`). On
success, atomically `Store` **both** `clientCAs` and `trustPol` so they can never
disagree. A rejected reload keeps last-good **and alerts loudly** — a stale allow-set
silently degrades every edge onboarded after the rejection.

**Runtime keep-last-good on disappearance.** Distinguish **startup absence**
(`EDGE_TRUST_SECRET` set but the Secret/key never loaded ⇒ degrade to CIDR-only,
safe, warn) from **runtime disappearance** (the watched Secret is DELETED, or its
`tls.crt`/`ca.crt` goes empty, *after* a good bundle was applied). A runtime
DELETE/empty event MUST **keep last-good `clientCAs`** and bump
`parapet_trust_reload_rejected_total` + alert — it MUST NEVER nil the live pool,
because nilling it instantly distrusts the whole fleet (every edge's XFF
overwritten). Only a deliberately-empty bundle *at startup* means "mTLS disabled."

**Header hardening (a real gap today, not just for mTLS):** mount a middleware
**first** in `main.go`'s `m` chain (before `ctrl`) that **unconditionally deletes**
client-supplied `X-Forwarded-Country` / `X-Forwarded-ASN` at ingress.
`forwardGeoHeaders` (`main.go:329`) only *overwrites* them when a DB is loaded — so
a core with no GeoIP DB currently passes a **client-forged** `X-Forwarded-Country`
straight upstream. Treat both as edge-set-only. (`X-Real-Ip` / `X-Forwarded-For`
stay governed by parapet's trust/distrust.)

## Edge wiring

The default data-plane identity is **CP-issued** (see
[Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert)). A new
`EDGE_DATAPLANE_MTLS` (bool, default false — off ⇒ anonymous re-encrypt, identical
to today) turns it on; `EDGE_UPSTREAM_TLS=true` is a prerequisite (loud startup
error if mTLS is on with TLS off, mirroring the existing https-endpoint guard at
`main.go:52-56`; warn if mTLS is off while the upstream is core `:443`).

- **`edge/clientcert.go` (new)** — an in-memory `ClientCertStore`
  (`atomic.Pointer[tls.Certificate]`) with a `GetClientCertificate` callback
  returning the live (complete key+chain) cert, and an **all-or-nothing**
  `Update(chainPEM, heldKey)` that `tls.X509KeyPair`-validates the new pair and
  atomically swaps — **if validation fails, the prior pair is kept** (never clears
  the pointer, never swaps in a broken cert). `GetClientCertificate` returns
  last-good non-empty whenever possible; a never-loaded empty return is loud
  (metric + log) and gates readiness — never a silent half-rotated state.
- **`edge/refresh.go`** — `RefreshEdgeCertOnce(cp, ccStore)`: generate an ephemeral
  key **into a local var** (not the live store), build the CSR, `cp.FetchEdgeCert(...)`,
  on success `ccStore.Update(chain, localKey)` as **one atomic unit**, on error
  fail-static (keep the in-memory cert, log a warning). `RunEdgeCertRefresh` mirrors
  `RunCertRefresh` but **renews on remaining-life/renew-before, not bare interval
  equality**, with **aggressive backoff retries** as expiry nears, adds **per-edge
  jitter** (the current `RunCertRefresh` has none → a co-booted fleet stays
  phase-locked, a thundering-herd risk on a signing endpoint), and **honors the CP's
  `Retry-After`**.
- **`edge/forward.go` `NewForwarder`** gains a `*ClientCertStore` param (nil ⇒
  anonymous re-encrypt, back-compat); on `useTLS` it sets
  `tlsConfig.GetClientCertificate = ccStore.GetClientCertificate`.
  `InsecureSkipVerify` stays for now (the edge still doesn't verify the core's
  server cert — see [open questions](#open-questions)).
- **Readiness is fail-closed.** When `EDGE_DATAPLANE_MTLS=true`, the readiness gate
  (`cmd/edge-proxy/main.go:197`) becomes
  `(serveAll || store.Loaded()) && clientCert.Loaded()` — a hard AND that
  **serve-all does NOT bypass**. First-boot issuance failure keeps the edge
  **not-ready** (503), not serving-while-untrusted, with a bounded background retry.
  **But CP-readiness ≠ system-readiness:** the edge cannot self-detect "the core does
  not yet trust my CA" (trust convergence happens in another process), so it can go
  ready and still 502 in the convergence window — see the system-readiness fail mode.

The edge remains the first hop and sets **no** `TrustProxy`, so it keeps
overwriting incoming `X-Forwarded-*` with the true client peer before forwarding —
the **transitive-trust invariant** the core relies on.

## Control-plane wiring: CP issues the client cert

The default data-plane identity is **CP-issued over the existing bearer channel**,
CSR-based, so the private key **never leaves the edge**.

### The issuance endpoint (`POST /v1/edge-cert`)

New endpoint on `edgecp.Server.Handler()` (alongside `GET /v1/certs` / `GET
/v1/waf`), in the exact style of EDGE.md's REST table:

```
POST /v1/edge-cert    Authorization: Bearer <token>
  request body (application/json): {"csr_pem": "<PKCS#10 CSR, PEM>"}
  200 {"chain_pem":"<leaf+edge-CA-intermediates PEM>", "not_after":"<RFC3339>", "serial":"<hex>"}
       chain_pem : leaf-first (edge leaf + edge-CA intermediates); NO key — the key never leaves the edge
       not_after / serial : surfaced for edge renewal scheduling + logging (parapet_edge_clientcert_not_after)
       Cache-Control: no-store, Pragma: no-cache (per-edge identity; NO ETag/304 — fresh key each renewal)
  400 (missing/malformed/oversized CSR, bad PEM, CSR signature fails verify, unsupported/over-large key type)
  401 (no/invalid token)  403 (token has no edge data-plane identity grant)  405 (not POST)
  413 (CSR body over the 16 KiB cap)  429 (per-token rate limit OR global signer saturation — Retry-After set)
```

It is the **only mutating endpoint** (everything else is `GET`). The CP returns
**`chain_pem` only** (no key on the wire — the edge holds it). `Cache-Control:
no-store` **and** `Pragma: no-cache` are set. **No ETag / `If-None-Match` / 304**: a
fresh ephemeral key each renewal means a new public key → new leaf → new chain.
Body capped at 16 KiB via `io.LimitReader`. Absent signer ⇒ the endpoint **404s**
(fully backward-compatible).

**CSR flow** (reusing `edge/refresh.go` + `edge/cp.go` `CpClient`):

1. **Edge — ephemeral key in memory.** Generate `ecdsa.GenerateKey(elliptic.P256())`
   (default; `EDGE_CLIENTCERT_KEY_TYPE`) **into a local variable**. Never written to
   disk — same posture as `CertStore` keys (`edge/certstore.go:26-27`).
2. **Edge — build CSR.** `x509.CreateCertificateRequest` with a minimal template;
   any hint SAN/CN is **irrelevant** (the CP overrides it). PEM-encode.
3. **Edge — POST over the bearer channel.** New `CpClient.FetchEdgeCert(csrPEM)`
   mirroring `FetchCert`/`FetchWaf`: POSTs `{"csr_pem":…}`, sets `Authorization:
   Bearer <token>`, body-capped read, returns chain+not_after+serial on 200 / error
   otherwise (caller fail-static). `do()` is generalized to take method+body
   (today GET-only).
4. **CP — verify + sign** (`handleEdgeCert`, new): `bearer(r)` + `authz.Known(token)`
   → 401; `authz.Identity(token)` → 403 if no grant; decode CSR; **whitelist the key
   type/curve BEFORE verifying** (ECDSA P-256/P-384 or Ed25519 only; reject RSA →
   400) so a `CheckSignature` DoS on an oversized key is impossible;
   `csr.CheckSignature()` (mandatory — an unsupported sig alg is a hard 400, never a
   silent pass) → 400 on failure; then `Signer.Sign(csr.PublicKey, authorizedSAN)`.
5. **CP — return chain only.** 200 with `chain_pem` + `not_after` + `serial`.
6. **Edge — assemble + hold atomically.** Pair the chain with the in-memory key into
   a `tls.Certificate` and atomically store the **complete** keypair+chain.
7. **Edge — present via `GetClientCertificate`** per handshake — no restart, no file.

### Signing: template, custody, rate-limiting

All in `edgecp/` + `cmd/edge-controlplane`, reusing existing primitives.

**`edgecp/server.go`.** New `handleEdgeCert` + `mux.HandleFunc("POST /v1/edge-cert",
…)`. New `signer atomic.Pointer[*Signer]` (nil ⇒ 404), wired by `WithSigner` like
`WithWAF`. **Absent signer ⇒ backward-compatible.**

**`edgecp/signer.go` (new).** `Signer` holds the parsed edge CA cert + key (behind an
interface — the **HSM/KMS seam**); `Sign` builds the leaf `x509.Certificate` template
**from a zero value — never from the parsed CSR** — setting ONLY: `SerialNumber`
(128-bit CSPRNG); `NotBefore = now - EDGE_CLIENTCERT_SKEW`, `NotAfter = now +
EDGE_CLIENTCERT_TTL`; `KeyUsage = DigitalSignature`; `ExtKeyUsage =
[ExtKeyUsageClientAuth]` ONLY; `URIs = [authorizedSAN]` from the token (the shared
derivation package); `BasicConstraintsValid = true, IsCA = false`. The CSR
contributes **exactly one thing: `csr.PublicKey`**. The template **explicitly never**
assigns `Subject`/`DNSNames`/`IPAddresses`/`EmailAddresses`/`URIs`/`Extensions`/
`ExtraExtensions` from the CSR. **Post-sign self-check (mandatory in BOTH CA modes):**
re-parse the issued leaf and assert `IsCA==false`, `KeyUsage==DigitalSignature`,
`ExtKeyUsage==[ClientAuth]`, `URIs==[authorizedSAN]`,
`len(DNSNames)==len(IPAddresses)==0`; **refuse to return** a cert that fails any
check. A conformance test feeds a CSR carrying `CA:true`, a rogue URI/DNS SAN, and a
malicious CN and asserts none appear in the leaf.

**`edgecp/authz.go` — per-edge identity (explicit opt-in).** Extend `Authz` with
`identities map[string]string` (token → id) populated alongside `tokens` in
`NewAuthz`, plus `Identity(token) (string, bool)`. The grant is **explicit and
separate**, NOT auto-derived from the token's presence or its domains; `Identity`
returns `("",false)` (→ 403) unless the operator set it. A serve-all (`"*"`) token
**MUST NOT** get a default identity. Migration defaults every token to NO identity.

**CA custody — managed (default) vs provided.** The edge CA is the new crown jewel
and **lives with the CP**. Two modes, decided at boot by the **presence** of
`EDGE_CA_CERT`/`EDGE_CA_KEY` (no `EDGE_CA_MODE` knob):

- **`managed` (default — zero PKI, zero openssl, zero cert-manager).** On first boot
  the CP **generates** a single-purpose edge CA and **persists** it to its own
  `parapet-edge-ca` Secret (`kubernetes.io/tls`, in `POD_NAMESPACE`), reuses it
  across restarts/replicas, and **hot-reloads** it on change. The generated CA
  template (from a zero value): key **ECDSA P-384** (`EDGE_CA_KEY_TYPE=ed25519`
  alt), PKCS#8; `SerialNumber` 128-bit CSPRNG; `Subject` CN `parapet-edge-ca`
  (cosmetic); `NotBefore = now-10m`, `NotAfter = now + EDGE_CA_TTL` (default 10y —
  the **leaf** TTL is the short knob); `KeyUsage = CertSign | CRLSign` ONLY;
  `ExtKeyUsage = [ClientAuth]` ONLY; `BasicConstraintsValid=true, IsCA=true,
  MaxPathLenZero=true`; `NameConstraints.PermittedURIDomains = ["parapet.moonrhythm.io"]`.
  **Honest scope:** this pins the SAN **host** only — SPIFFE path-segment scoping to
  `/edge/*` is *not* expressible as a URI NameConstraint (the issuance template's
  `URIs=[authorizedSAN]` + post-sign self-check pin the path). So the constraint stops
  cross-domain/serverAuth abuse of a stolen key, **NOT** edge-fleet impersonation. **A
  conformance test must prove** `x509.Verify` rejects `spiffe://evil.example/edge/x`
  and accepts `spiffe://parapet.moonrhythm.io/edge/x` under this constraint before it
  is counted as a control. Managed mode emits a **loud startup log** that the CP now
  HOLDS (and on first boot GENERATED) a fleet-minting CA key, and requires the new
  `k8s` write path, the dedicated CP ServiceAccount, and `POD_NAMESPACE`.
- **`provided` (escape hatch — operator's own PKI).** Both `EDGE_CA_CERT`/`EDGE_CA_KEY`
  point at mounted PEM files; the CP **uses** them, **never generates**, **never
  writes** the Secret, and **needs no `get`/`update` RBAC**. Hot-reload the mounted
  files (validate-then-swap). **Validation (mandatory):** the CA MUST be `IsCA` and
  carry EKU `clientAuth` (reject pure serverAuth / hard-reject `anyExtendedKeyUsage`);
  **warn loudly (or refuse behind a flag) if it lacks
  `NameConstraints.PermittedURIDomains`** — the leak-containment guarantee is void
  without it. It SHOULD be a **dedicated single-purpose** CA, never a shared org
  intermediate. Not cert-manager-specific: cert-manager may *populate* the mounted
  Secret, but the CP sees opaque files — no CRD, no `CertificateRequest`, no polling.

**`cmd/edge-controlplane/main.go`.** Branch on `EDGE_CA_CERT`/`EDGE_CA_KEY`: both set
⇒ provided (read, validate, build `Signer`); both empty ⇒ managed (`edgecp.EnsureCA`
adopt-or-generate + persist, synchronous, before serving); exactly one set ⇒ hard
config error (mirrors the `CP_TLS_CERT`/`CP_TLS_KEY` pairing guard at `main.go:41-44`).
In managed mode, `POD_NAMESPACE` MUST be non-empty (downward-API `metadata.namespace`)
— a missing `POD_NAMESPACE` is a **fatal** startup error, never a silent
wrong-namespace write. Either branch yields one `*Signer` wired via
`server.WithSigner(signer)`; neither ⇒ nil signer ⇒ `POST /v1/edge-cert` 404
(back-compat).

**Rate-limiting + DoS.** A **per-token** token-bucket (`EDGE_CLIENTCERT_RATE`,
default 10/min → 429) blunts a single-token forged-CSR flood. It does **nothing**
against a fleet-wide restart storm (N tokens), so add a **global signing concurrency
cap** (a bounded worker pool / semaphore around `Signer.Sign`) returning **429/503 +
`Retry-After`** when saturated. The authz reject and the **key-type whitelist run
before** any signing, so an unauthorized or oversized-key flood costs no CA work.
Keep the endpoint behind the CP's edge-sources-only `NetworkPolicy`.

### Managed-CA bootstrap: replica-safe create-once + anti-regeneration guard

`edgecp.EnsureCA(ctx, k8sClient, podNamespace, secretName)` runs **synchronously
before serving** (mirroring `wafReloader.LoadOnce` at `main.go:88-93`); only after it
returns a valid `Signer` is `WithSigner` wired. Until then `POST /v1/edge-cert` 404s
— never sign with a half-initialized/unpersisted CA.

**Precondition (manifest):** the operator pre-creates an **empty** `parapet-edge-ca`
Secret. RBAC `resourceNames` can scope `get`/`update` but **cannot** scope `create`;
the stub lets us grant scoped `update` instead of broad namespace `create`.

**The CAS read MUST be a strongly-consistent typed `Secrets(ns).Get`** (the new
`k8s.GetSecret`), never an informer/lister cache (a stale-empty cache read can
livelock the loser into regenerating). Algorithm `ensureCA(ctx)`:

1. `GetSecret(podNamespace, parapet-edge-ca)`. Cases:
   - **(a) populated** (`tls.crt`+`tls.key` parse into a valid CA keypair) → **ADOPT**,
     build `Signer`, log "adopted existing edge CA", return. *(Steady state, replica
     scale-up, and the CAS-loser all land here.)*
   - **(b) guard annotation present but `tls.crt` empty** → **HARD ANOMALY** (a
     populated CA was re-blanked). **NEVER regenerate** (a regenerate is
     indistinguishable from the catastrophic re-blank and would distrust the whole
     fleet). Keep any in-memory CA, bump `parapet_edge_ca_unexpected_empty_total`,
     alert, fail readiness. CA replacement is the **overlap rotation**, never
     delete+regenerate.
   - **(c) virgin empty stub** (no guard annotation, never populated) → go to 2.
   - **(d) `NotFound`** → **fatal config error** ("operator must pre-create the empty
     parapet-edge-ca Secret"). Do NOT fall back to a broad `create` grant.
2. Generate keypair + self-signed CA **in memory** (local vars).
3. On the **observed** Secret object (carrying its `resourceVersion`), set
   `Data["tls.crt"]`/`Data["tls.key"]` **and a guard annotation**
   `parapet.moonrhythm.io/edge-ca-generation` + populated-at timestamp, and call
   `k8s.UpdateSecret(...)`. `Update` is a compare-and-swap on `resourceVersion`:
   succeeds only if the stored version is unchanged.
4. **Success** → I am the winner; use my keypair; bump `parapet_edge_ca_generated_total`.
5. **Conflict** (`apierrors.IsConflict`, the loser path) → RE-READ and **ADOPT** the
   winner's keypair (case a), discard mine. Still-empty re-read (transient, never
   possible once the guard annotation is set) → jittered bounded backoff;
   **exhaustion is a hard non-zero exit** (kubelet restarts) — never a silent
   no-signer 404.

The API server's `resourceVersion` CAS **linearizes** the replicas: exactly one
`Update` on the empty stub wins; the other gets `Conflict` and adopts. **The Secret
IS the lock — no leader election, no leases.**

**Anti-regeneration is the load-bearing safety property.** The guard annotation
(case b) closes the GitOps/operator re-blank hazard: a Flux/Argo sync or `kubectl
apply` that resets the stub to empty does NOT trigger a regenerate-and-distrust. The
pre-created stub in `deploy/` MUST carry GitOps drift-exclusion
(`argocd.argoproj.io/sync-options: Prune=false`, an `ignoreDifferences` on `/data`,
a Flux server-side-apply field-manager note). Alert if `parapet_edge_ca_generated_total`
ever increments more than once across the fleet's lifetime.

**Testability:** the create-once MUST be tested against
`k8s.io/client-go/kubernetes/fake` (or envtest), which honors `resourceVersion` CAS
and returns `IsConflict`, with a two-goroutine concurrent-generate test asserting
exactly one CA survives and the loser adopts. The **fs backend's `UpdateSecret` is
non-CAS** (best-effort in-memory) so managed mode against fs **regenerates per boot**
— fine for local dev, **never** prod, and cannot validate the linearization.

### Where the core gets the CA (one Secret, no publish step)

The **core reads the public CA cert directly from the same `parapet-edge-ca` Secret**
via its existing trust watch — no separate publish step, no extra CP write, no skew.
Point the core at it: `EDGE_TRUST_SECRET=parapet-edge-ca`, reading key **`tls.crt`**
(fallback `ca.crt`). The cert the CP signs **with** and the cert the core **trusts**
are the **same bytes in the same Secret**, so they cannot drift; the core needs **zero
new RBAC** (it already list/watches secrets in the namespace). (Rejected: a separate
`parapet-edge-trust` Secret holding only `ca.crt` — a second write target and a
re-introduced publish/skew window for nothing the namespace co-tenancy doesn't already
concede.)

**Namespace invariant:** the CP's CA Secret and the core's `EDGE_TRUST_SECRET` watch
MUST be in the **same** namespace, and that namespace is `POD_NAMESPACE` for **both**.
The CP's CA read/write targets `POD_NAMESPACE` (the pod's own namespace), **NOT**
`WATCH_NAMESPACE` (which defaults to `""` = all-namespaces and cannot be a write
target). The core already injects `POD_NAMESPACE` via the downward API
(`deploy/deployment.yaml:38-41`); the CP manifest does not today and MUST be amended.

### CA hot-reload + rotation (CP-driven, bundle-based, no cert-manager)

**The signer is hot-reloadable, not boot-once.** `EnsureCA` does the create-once; a
**CA-Secret watch** (a 2nd CP watcher, mirroring the cert `Reloader`) then keeps the
signer live: validate-then-swap into `atomic.Pointer[*Signer]`. A boot-time-only
signer would let a replica that booted **before** a rotation keep signing with a stale
in-memory key — intermittent 502s during the bundle-trim step. Every replica exposes
`parapet_edge_ca_signer_fingerprint`; the rotation interlock confirms **all** replicas
converged before trimming.

**Rotation invariant:** the NEW CA's public cert must be in the core's `ClientCAs`
BEFORE the CP signs any leaf with the new key — else fresh leaves 502. The enabler is
**bundle support**: `AppendCertsFromPEM` appends every CERTIFICATE block, so `tls.crt`
can hold an **overlap bundle** (old ++ new CA concatenated), and validate-then-swap
treats a partially-bad bundle as a rejected reload (keep last-good).

**Rotation is single-writer** (Phase 1: a one-shot Job / subcommand, or
leader-elected — NOT the steady-state `replicas: 2`). The Secret-as-lock CAS
linearizes only create-once, not a 4-stage promote/trim state machine. So the **active
signer is derived SOLELY from Secret content** (e.g. a `tls-active: old|new` field),
never per-replica state, and every stage is gated on a **core-observed**
trust-bundle-hash metric:

1. Generate NEW CA in memory.
2. Write `tls.crt = OLD ++ NEW`, stage NEW key as `tls-next.key`, keep OLD active.
   Core's watch fires → trusts BOTH. (Invariant satisfied.)
3. Keep signing with OLD while every short-TTL leaf renews; watch
   `parapet_edge_clientcert_not_after` / registry-generation convergence.
4. **Promote:** set `tls-active: new` (all replicas swap within one debounce), keep
   BOTH certs in the bundle for ≥ one full leaf-TTL, then trim the OLD cert — only
   after the convergence metric shows zero leaves on the old CA.

**CA-key-compromise emergency:** skip overlap, write ONLY the new CA, accept the brief
gap (existing edges 502 until they re-fetch a new-CA leaf). **This is the stolen-CA-key
runbook** — SAN-drop cannot revoke a forged leaf riding a real SAN. Auto-rotation is
Phase 2.

### k8s client: the first write path

The `k8s` client is **read-only** today (`k8s/k8s.go` exposes only `Get*`/`Watch*`;
`cluster.go` wraps List/Watch; `fs.go` is the local fixture backend). Managed mode
needs the **first** write path, added to the interface and **both** backends with
package-level forwarders:

- `GetSecret(ctx, ns, name) (*v1.Secret, error)` — single-object read preserving
  `resourceVersion` for the CAS. cluster: `Secrets(ns).Get`. fs: matching secret or
  `apierrors.NewNotFound`.
- `UpdateSecret(ctx, ns, *v1.Secret) (*v1.Secret, error)` — the CAS write; sends
  `s.ResourceVersion`; apiserver rejects a stale version with `Conflict`. cluster:
  `Secrets(ns).Update`. fs: best-effort in-memory (**non-CAS**, dev-only).

Import `k8s.io/apimachinery/pkg/api/errors` for `IsConflict`/`IsNotFound`. No
`CreateSecret` in the recommended posture (the stub is pre-created; `NotFound` is
fatal-config). The **core never uses these writes** — they live solely in the CP
boot/rotation path. `ensureCA` is **idempotent**: re-running after a CA exists is a
pure adopt (no write).

## Deployment & RBAC (self-managed CA)

The CP **stops reusing** the controller's ServiceAccount — splitting the SA is the
prerequisite for isolating the mint/write capability from the core. Concrete manifest
changes:

1. **New `deploy/edge/serviceaccount.yaml`** — ServiceAccount `edge-controlplane`.
2. **`controlplane.yaml`:** `serviceAccountName: edge-controlplane` (was
   `parapet-ingress-controller`); add `POD_NAMESPACE` via downward API `fieldRef:
   metadata.namespace` (**required** in managed mode); add a hardened `securityContext`
   (`readOnlyRootFilesystem`, `runAsNonRoot`, `allowPrivilegeEscalation: false`) and an
   egress `NetworkPolicy`; add `EDGE_CA_SECRET` (and optionally `EDGE_CA_TTL`,
   `EDGE_CA_KEY_TYPE`).
3. **New `deploy/edge/role-ca.yaml`** — namespaced Role `edge-controlplane` in
   `POD_NAMESPACE` with secrets `get, update` scoped to
   `resourceNames: [parapet-edge-ca]` (resourceNames scopes get/update/patch/delete
   but **cannot** scope create — exactly why the stub is pre-created), + RoleBinding to
   the new SA.
4. **Cluster-wide read rebind (the migration footgun):** because the CP runs
   `WATCH_NAMESPACE=""` (cluster-wide tenant-cert Reloader), the new SA needs a
   **ClusterRoleBinding** to the existing `parapet-ingress-controller` read ClusterRole.
   A namespaced RoleBinding alone **silently breaks cert distribution**. If
   `WATCH_NAMESPACE` is pinned, a namespaced RoleBinding to the read Role suffices —
   the binding scope MUST match `WATCH_NAMESPACE`. Ship `deploy/edge/role-binding-read.yaml`.
5. **New `deploy/edge/ca-secret.yaml`** — the pre-created **empty** `parapet-edge-ca`
   Secret in `POD_NAMESPACE`. (Confirm whether target k8s rejects a zero-length
   `tls.crt` on a `kubernetes.io/tls` CREATE; if so ship it as type `Opaque` — type is
   advisory to our code and cannot change on `Update`.) MUST carry GitOps
   drift-exclusion so a reconciler never prunes or blanks the CP-populated Secret.
6. **The core keeps** its namespace-wide secrets list/watch (it needs all tenant TLS
   for SNI) and reads ONLY the public `tls.crt` from `parapet-edge-ca` via
   `EDGE_TRUST_SECRET` — **zero new core RBAC**.
7. **CP startup RBAC self-probe:** after `k8s.Init`, probe-List secrets in
   `WATCH_NAMESPACE` and probe-Get the CA Secret; on 403, fatal-log naming the exact
   missing binding.
8. **etcd encryption-at-rest** is a managed-mode prerequisite (loud startup warning if
   undetectable): the long-lived CA key now lives in a Secret, exposed in etcd backups
   and to anyone with namespace secret-get without it.

## Security model

**Trust boundary.** Exactly the edges holding a private key whose cert chains to the
dedicated edge CA **and** whose URI SAN is in the live allow-set. Trust is
**operator-asserted**: only an operator editing the registry Secret moves the boundary.
mTLS trust is conferred **only on `:443`**.

**Spoofing.** A non-edge reaching `:443` **cannot forge trust**: `VerifiedChains` is
populated only after the Go stack cryptographically verifies the presented cert against
`ClientCAs`; forging requires the edge CA key. A compromised edge **cannot request a SAN
it isn't entitled to** — the CP stamps the SAN from the bearer token's registry
identity and ignores the CSR's SAN.

> **Honest scoping.** mTLS authenticates the **connection, not the headers.** A trusted
> edge — or anything wielding a stolen edge *leaf* key — can still set
> `X-Forwarded-For` for its own requests; the claim is **"an unauthenticated peer is
> never trusted,"** not "XFF can never be spoofed." Second caveat: with the shipped
> `TRUST_PROXY: cloudflare` default, a non-edge from a Cloudflare CIDR is CIDR-trusted
> with no cert. **Never add edge egress CIDRs to `TRUST_PROXY`**, and lock both
> data-plane ports with a `NetworkPolicy`.

**Replay.** None on the data plane — the cert is proven inside a live mTLS handshake.

> **Token-minted leaf certs outlive token revocation.** A leaked-but-not-yet-revoked
> token POSTed to `/v1/edge-cert` mints a self-contained cert the core verifies for its
> full TTL. Revoking the token stops *future* issuance but does **not** revoke a minted
> cert — only **dropping the registry entry** (which drops its SAN from the live
> allow-set, re-checked per request) revokes it, in ~300 ms. Runbook for a leaked
> **token**: delete the registry entry. `EDGE_CLIENTCERT_TTL` is kept short to shrink
> the window; **CP-issuance is INCOMPATIBLE with `EDGE_TRUST_REQUIRE_SAN=false`** (the
> per-request SAN check is the only bound on such a cert).

**Blast radius.** A leaked edge **leaf** key lets the holder spoof XFF **as that one
edge** until its SAN is dropped (~300 ms) or its cert expires. The **crown jewel is the
edge CA key** (mints any edge). In **managed** mode the CP both **GENERATES and HOLDS**
it — a deliberate escalation from the CP's prior posture (it distributed tenant *leaf*
keys; it now holds, and mints, a *CA* that forges fleet-wide edge trust). **State this
plainly:** a stolen edge-CA key forges the **entire** fleet's identities. NameConstraints
(`PermittedURIDomains`) and EKU `clientAuth` only stop **cross-purpose** abuse (other URI
domains, serverAuth leaves) — they do **not** bound edge-fleet impersonation, because a
forged leaf carries a SAN already in the allow-set, so **per-request SAN-drop does NOT
revoke a forged leaf without also distrusting the legitimate edge.** The **only** real
bound on a stolen CA key is **CA rotation** (the overlap/emergency runbook); that, not
SAN-drop, is the stolen-CA-key runbook. Mitigations that genuinely shrink the
window/surface: a **single-purpose** CA (`KeyUsage=CertSign|CRLSign`, `MaxPathLen=0`,
EKU `clientAuth`), its **own** tightly-RBAC'd Secret read only by the **dedicated CP
ServiceAccount**, the CP's edge-sources-only `NetworkPolicy` + hardened pod, **provided**
mode (key never in an in-cluster Secret) for high-assurance, and a future **HSM/KMS
`Signer`** so the raw key never sits in pod memory. **Phase-1 honesty:** because the
**core** SA needs namespace-wide secret read for SNI certs, the core CAN read the CA
private key from `parapet-edge-ca` in the shared namespace — the dedicated CP SA isolates
the **mint/write** capability, NOT key-read. Full key-read isolation requires moving
`parapet-edge-ca` to a CP-only namespace (Phase-1 *option*, applyable manifest) or
provided mode. The CP also concentrates risk: the same process holds cluster-wide read of
**all** tenant TLS keys (`WATCH_NAMESPACE=""`) **and** the fleet-minting CA key — pin
`WATCH_NAMESPACE` to specific tenant-secret namespaces to shrink this.

**Fail-default: fail-closed, degrading to the static CIDR branch.** A missing trust
Secret ⇒ `trustPol` nil ⇒ mTLS branch false ⇒ edges distrusted (degraded but safe),
Cloudflare CIDR unaffected. An empty/garbage `ca.crt` on reload ⇒ validate-then-swap
**rejects** and keeps last-good. First-boot issuance failure ⇒ edge **not-ready**. A
trust Secret that **vanishes at runtime** keeps **last-good** `clientCAs` and alerts — it
never nils the live pool; only a *never-loaded* startup absence degrades to the CIDR
branch. **No path fails open.**

**The explicit tradeoff.** This forces re-encrypt TLS, a PKI lifecycle, and the CA key
living with the CP (managed mode). An **expired edge cert hard-fails the handshake**
(502s); the CP-outage budget (= `EDGE_CLIENTCERT_TTL` × renew-before-fraction) must
exceed the operator's CP recovery SLO. Accepted: a cryptographic, IP-independent,
per-edge-revocable identity that makes a bare Docker edge work with nothing but a token.

## Fail modes

| Failure | Behavior |
|---|---|
| Trust Secret absent / never created (startup) | mTLS branch false (`trustPol` nil); edges distrusted (XFF overwritten); core serves; Cloudflare CIDR unaffected. **Fail-closed, degraded-not-down.** Startup warning + `parapet_trust_source{none}`. |
| `ca.crt`/`tls.crt` empty/garbage on reload | Validate-then-swap **rejects**, last-good kept, `parapet_trust_reload_rejected_total++`, **loud alert**. Never fails open. |
| Managed CA Secret deleted / blanked at RUNTIME (operator, GitOps prune, restore of the empty stub) | CP: the guard annotation makes a re-blanked-but-previously-populated stub a HARD ANOMALY — the CP **NEVER regenerates** (would mint a new CA and distrust the fleet), keeps its in-memory CA, bumps `parapet_edge_ca_unexpected_empty_total`, alerts, fails readiness. Core: a runtime DELETE/empty of `EDGE_TRUST_SECRET` keeps **LAST-GOOD** `ClientCAs` + alerts — never nils the live pool. Replacement is the overlap rotation, never delete+regenerate. The `deploy/` stub carries GitOps drift-exclusion. |
| Two CP replicas both observe an empty stub and both generate (split-CA race) | `resourceVersion` CAS linearizes them: exactly one `Update` wins (rv advances), the other gets `Conflict`, re-reads, **ADOPTS** the winner's keypair. The Secret IS the lock — no leader election. The CAS read MUST be a strongly-consistent typed `Get` (never an informer cache, which can serve a stale-empty stub and livelock the loser); retry exhaustion is a hard non-zero exit. |
| CP started managed with empty `POD_NAMESPACE` (downward API not wired) | **FATAL** startup error before any write — the CA Secret has no known namespace and a wrong-namespace write would land where the core never sees it. Mirrors the `CP_TLS` pairing guard. |
| CP switched to the dedicated SA without the cluster-wide read rebind (`WATCH_NAMESPACE=""`) | The cluster-wide tenant-cert Reloader 403s → stale/empty cert store → edges fail to fetch certs → data-plane outage. MUST bind a ClusterRoleBinding to the existing read ClusterRole. The CP startup RBAC self-probe fails loud, naming the missing binding. |
| A CP replica booted before a CA rotation keeps signing with the stale key | Prevented by the CA-Secret watch: signer is `atomic.Pointer[*Signer]`, hot-reloaded on change; the active key derives solely from Secret content (`tls-active`) so all replicas converge within one debounce. The interlock confirms all `parapet_edge_ca_signer_fingerprint` match before trimming. |
| Edge client cert expired / CP down past `NotAfter` | `VerifyClientCertIfGiven` aborts the handshake → 502s. Until expiry, the edge keeps its last-good in-memory cert (**fail static**) and retries with backoff. Outage budget = `TTL` × renew-before-fraction; size `TTL` above the CP recovery SLO. |
| Leaked-but-not-yet-revoked token replayed to `/v1/edge-cert` | Mints a cert for ITS OWN SAN, valid for the full TTL. Token revocation does NOT revoke it — **only deleting the registry entry** drops its SAN (per-request → distrusted ~300 ms). Bounded by short `EDGE_CLIENTCERT_TTL`. |
| Stolen edge-CA key (managed mode) | Attacker forges the **ENTIRE fleet's** identities. NameConstraints + EKU stop only cross-purpose abuse, NOT impersonation (a forged leaf rides a real SAN, so SAN-drop can't revoke it without distrusting the legit edge). The ONLY bound is **CA ROTATION**. Phase-1 honesty: the CA key is readable by the core SA (namespace co-tenancy); the dedicated CP SA isolates mint/write, not key-read. |
| CP signs with a CA the core's `ClientCAs` doesn't yet trust (rotation skew) | Fresh certs fail verification → 502s. Prevented by the overlap invariant (new CA in the bundle BEFORE signing with it) + the convergence interlock. CP hot-reloads the CA so rotation needs no restart. |
| Clock skew: core clock behind the CP by > `EDGE_CLIENTCERT_SKEW` | A fresh cert is "not yet valid" at the core → handshake aborts → 502s, self-healing once skew elapses. The validator is the **core** clock. Mitigated by the NotBefore backdating (default 10m), an NTP-sync prerequisite, and a distinct notBefore/notAfter failure metric. |
| First-boot issuance fails under `EDGE_DATAPLANE_MTLS=on` (CP down at startup) | **Fail-CLOSED on readiness:** edge stays not-ready (503), not routed to. Bounded background retry flips ready when the first cert lands. Readiness `= (serveAll || store.Loaded()) && clientCert.Loaded()` — serve-all does NOT bypass. CP HA recommended. |
| CP readiness ("can sign") mistaken for system readiness ("core trusts the CA") | The edge cannot self-detect the core-doesn't-trust-me state and WILL go ready and serve 502s in the convergence window (core debounce + watch + etcd lag, worst-case seconds). The onboarding gate **REQUIRES** confirming `parapet_trust_source{mtls}` / the trust-bundle-hash includes the new CA before routing prod traffic; optionally an edge-side post-issuance re-encrypt probe before flipping ready. |
| Provided-mode CA mounted without NameConstraints / clientAuth EKU | The CP validates: `IsCA` required; EKU must contain `clientAuth` (reject pure serverAuth / anyEKU); **warn loudly (or refuse behind a flag)** if `NameConstraints.PermittedURIDomains` is absent. The post-sign self-check still bounds the emitted leaf in both modes. |
| Malformed / oversized-key / unsupported-alg CSR (DoS probe) | 16 KiB body cap (413); the **key-type/curve whitelist rejects (400) BEFORE `CheckSignature`** so an oversized-RSA verify-DoS is impossible. authz + reject precede any CA signing. |
| Fleet-wide re-issue storm (rollout / drain / CP recovery) | Per-token rate limit does NOT help (N tokens). A **global signing concurrency cap** returns 429/503 + `Retry-After`; the edge honors it with backoff; the edge refresh loop adds **jitter** so a co-booted fleet doesn't stay phase-locked. |
| `ClientCertStore.Update` gets an unparseable / mismatched chain | All-or-nothing: `tls.X509KeyPair(chain, heldKey)` failing keeps the PRIOR pair (never clears the pointer, never swaps a broken cert), logs + bumps a rejection metric. Never a silent half-rotated state. |
| `GetConfigForClient` returns nil / omits `ClientAuth`/`GetCertificate` | Guarded: base config built non-nil before `Serve()`; callback returns last-good, never nil; startup self-test asserts the three properties. |

## Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `TRUST_PROXY` | core | `cloudflare` | **Unchanged.** Static CIDR list / `cloudflare`/`true`/`false` → the `cidrTrust` OR-branch. **Never add edge egress CIDRs here.** |
| `EDGE_TRUST_SECRET` | core | `""` (feature **off**) | Name of the Secret in `POD_NAMESPACE` carrying the edge CA **public** cert into `ClientCAs`. Set to `parapet-edge-ca` to single-source from the managed CA Secret. Reads key **`tls.crt`** first, `ca.crt` as fallback. MUST be the same namespace as the CP's CA Secret (= `POD_NAMESPACE` for both). Unset ⇒ mTLS disabled, identical to today. |
| `EDGE_TRUST_REQUIRE_SAN` | core | `true` | Trust requires the verified leaf's URI SAN ∈ the live allow-set (enables per-edge revocation). **Incompatible with CP-issuance: the per-request SAN check is the ONLY bound on a cert minted from a leaked token. When the same edge CA backs issuance, the CP MUST refuse to issue and/or the core MUST refuse CA-only — fail-closed.** |
| `EDGE_DATAPLANE_MTLS` | edge | `false` | Enable the CP-issued data-plane client cert (CSR → `POST /v1/edge-cert`, presented via `GetClientCertificate`). Off ⇒ anonymous re-encrypt, identical to today. Requires `EDGE_UPSTREAM_TLS=true` (loud error otherwise). When on, readiness is gated on the client cert (fail-closed). |
| `EDGE_CLIENTCERT_KEY_TYPE` | edge | `ecdsa-p256` | Key type for the in-memory ephemeral keypair (never leaves the edge). `ecdsa-p256`/`p384`/`ed25519` — matches the CP's accepted-key whitelist. RSA not offered (bounds the CP's CSR-verify DoS surface). |
| `EDGE_CLIENTCERT_TTL` | CP | `1h` | Issued **leaf** cert lifetime. Short — renewal is free over the loop — to bound a leaked-token-minted cert. Outage budget = `TTL` × renew-before-fraction; raise (24–72h) if outage tolerance dominates (call out the tension). |
| `EDGE_CLIENTCERT_SKEW` | CP | `10m` | NotBefore backdating slack. The cert is minted on the CP clock but **validated on the core clock**. NTP sync between CP and core is a hard prerequisite. |
| `EDGE_CLIENTCERT_RATE` | CP | `10/min` | Per-token issuance rate limit (429). A **global** signing concurrency cap (429/503 + `Retry-After`) is separate and necessary — per-token does nothing against a fleet-wide restart storm. |
| `EDGE_CA_CERT` / `EDGE_CA_KEY` | CP | `""` / `""` (⇒ managed mode) | **Provided mode:** PEM paths to a MOUNTED edge CA cert+key. Set ⇒ the CP uses them and does NOT generate/write the Secret; hot-reloaded from disk. Both-or-neither (hard config error if only one). Absent ⇒ **managed** mode (CP self-generates). Not cert-manager-specific. |
| `EDGE_CA_SECRET` | CP | `parapet-edge-ca` | Name of the Secret in `POD_NAMESPACE` the CP adopts-or-generates the CA into (managed). Operator pre-creates it **empty** (with GitOps drift-exclusion). Keys `tls.crt`/`tls.key`; carries the `parapet.moonrhythm.io/edge-ca-generation` guard once populated. Read/written in `POD_NAMESPACE`, never `WATCH_NAMESPACE`. |
| `EDGE_CA_TTL` | CP | `87600h` (10y) | Lifetime of a CP-**generated** edge CA cert (managed/generate path). Long-lived (the CA is the anchor; the short knob is the leaf TTL). Ignored in provided mode. *(Open: shorten to 1–2y unless convergence-gated rotation has shipped.)* |
| `EDGE_CA_KEY_TYPE` | CP | `ecdsa-p384` | Key type for a CP-generated CA: `ecdsa-p384` (default) or `ed25519`. Ignored in provided mode. |
| `POD_NAMESPACE` | CP | downward API `metadata.namespace` (**required in managed mode**) | The CP's own namespace; the CA Secret is read/written here (NOT `WATCH_NAMESPACE`). Empty in managed mode ⇒ fatal startup error. Must be added to `deploy/edge/controlplane.yaml` (the core already wires it). |
| `WATCH_NAMESPACE` | CP | `""` (all namespaces) | Existing knob; documented here for its security weight. `""` = cluster-wide tenant-TLS read = highest blast radius. **Recommend pinning** to the namespace(s) holding tenant TLS Secrets. Distinct from `POD_NAMESPACE`; the CA read/write never uses it. |
| `EDGE_UPSTREAM_CLIENT_CERT` / `_KEY` | edge | `""` / `""` | **Legacy mounted-cert (k8s-only) edge-side path**, superseded as the default by `EDGE_DATAPLANE_MTLS` + CP-issuance. PEM paths to a mounted client cert+key, live-reloaded from disk. An edge mount detail, not a CA mode. |
| `EDGE_UPSTREAM_TLS` | edge | `false` | **Unchanged.** Must be `true` for mTLS trust. Selects the re-encrypt path. |
| `EDGE_UPSTREAM_SNI` | edge | `""` | **Unchanged.** SNI/`ServerName` presented to the core on re-encrypt. |

Metrics: `parapet_trust_source{mtls|cidr|none}`, `parapet_trust_reload_rejected_total`
(core); `parapet_edge_clientcert_loaded` (0/1), `parapet_edge_clientcert_not_after`
(edge); `parapet_edge_ca_generated_total`, `parapet_edge_ca_signer_fingerprint`,
`parapet_edge_ca_unexpected_empty_total` (CP). Both planes also expose the registry
generation/hash they last applied, so an operator can confirm convergence before
declaring an edge trusted.

## Onboarding flow (the payoff)

1. **One-time, code-only:** deploy the dedicated `edge-controlplane` ServiceAccount +
   its scoped Role/RoleBinding (`get,update` on `resourceNames: [parapet-edge-ca]`) +
   the cluster-wide read rebind (when `WATCH_NAMESPACE=""`), pre-create the **empty**
   `parapet-edge-ca` Secret (with GitOps drift-exclusion annotations), set
   `POD_NAMESPACE` on the CP via the downward API, and roll the core + CP **once** to
   pick up the new code. On first boot the CP **generates and persists** the edge CA
   itself (managed mode) — **no openssl, no cert-manager, no out-of-band CA**. The core
   points `EDGE_TRUST_SECRET=parapet-edge-ca` and reads the public cert from the same
   Secret. *This is the only restart, ever — never again per-edge.* (Provided mode: skip
   the generate — mount `EDGE_CA_CERT`/`EDGE_CA_KEY`; the CP needs no `get`/`update`.)
2. **Per edge — grant a data-plane identity (one registry edit).** Add the edge's entry
   to `edge-controlplane-tokens` with an explicit `id`. This single edit (a) authorizes
   its cert/WAF fetch, (b) makes the CP **issue** its data-plane client cert on `POST
   /v1/edge-cert` — key generated in the edge's memory, never mounted, never renewed by
   hand — and (c) adds its SAN `spiffe://…/edge/<id>` to the core's live allow-set.
3. **Configure the edge:** `EDGE_DATAPLANE_MTLS=true`, `EDGE_UPSTREAM_TLS=true`,
   `EDGE_UPSTREAM_ADDR` → core `:443`. For a Docker edge that's it — **no client-cert
   file mounts**; its only input stays `EDGE_CP_TOKEN`.
4. **Deploy + verify.** The edge generates a keypair in memory, fetches its cert, and
   re-encrypts to `:443` presenting it. **Confirm `parapet_trust_source{mtls}` / the
   trust-bundle-hash includes the CA before routing prod traffic** (the edge can't
   self-detect the core-doesn't-trust-me window). No `TRUST_PROXY` edit, no core restart.
5. **Revoke:** **delete the edge's registry entry** → its SAN leaves the allow-set →
   distrusted within ~300 ms (deleting only the token does NOT revoke an already-minted
   cert). For a **leaked CA key**, SAN-drop does NOT help (a forged leaf rides a real
   SAN) — the only fix is **CA rotation** (overlap runbook), gated on the convergence
   metric.

## Phasing

1. **Phase 1 — the primary mechanism (a bare Docker edge works, no cert-manager).** Core:
   the per-request closure, `GetConfigForClient` hot-swap over a **separate** atomic from
   the SNI cert table, the `EDGE_TRUST_SECRET` watch (validate-then-swap, keep-last-good,
   runtime-keep-last-good-on-delete, alert-on-reject), `EDGE_TRUST_REQUIRE_SAN=true`
   single-sourced, the `X-Forwarded-Country/-ASN` strip, the metrics. CP-issuance: `POST
   /v1/edge-cert`, `edgecp/signer.go` (zero-value template + post-sign self-check +
   key-type whitelist + HSM/KMS seam interface), `Authz.Identity`, the **shared SAN
   derivation package**, the global signing concurrency cap. **Managed-CA bootstrap:**
   `edgecp.EnsureCA` (adopt-or-generate, ECDSA-P384, single-purpose, NameConstrained)
   under the `resourceVersion`-CAS create-once over the pre-created empty Secret, the
   **anti-regeneration guard**, the new `k8s.GetSecret`/`UpdateSecret` write path, the
   CA-Secret **watch** keeping the signer hot-reloadable (`atomic.Pointer[*Signer]`), the
   dedicated CP ServiceAccount + scoped Role + cluster-wide read rebind, `POD_NAMESPACE`
   on the CP, the CP startup RBAC self-probe, and the CA metrics. **Provided** mode ships
   alongside as the escape hatch. Edge: `EDGE_DATAPLANE_MTLS` wiring with atomic key+chain
   swap, jitter, fail-closed readiness. `NetworkPolicy` locking core `:80`/`:443`.
2. **Phase 2 — stronger hardening.** Mutual auth of the hop (edge pins the core CA, drop
   `InsecureSkipVerify`); the CP-only-namespace CA-key-read isolation as a turnkey
   manifest; **CA auto-rotation** (CP rotates at `NotAfter` × fraction) gated on the
   cross-replica convergence metric; an **HSM/KMS `Signer`** so the raw CA key never sits
   in pod memory; CRL/OCSP via `tls.Config.VerifyConnection` if revocation must beat TTL +
   SAN-drop; real SPIRE SVID migration (the SAN naming already aligns).
3. **Phase 3 — optional companion.** A `TRUST_PROXY_DYNAMIC=true` ConfigMap-of-CIDRs
   OR-branch for callers that genuinely cannot present a client cert — same atomic +
   validate-then-swap discipline, never panic on the watch path.

## Alternatives considered

- **CP mints key+cert and ships both (vs CSR-based).** Simpler on the edge, the only
  viable fallback if an edge runtime cannot do x509 keygen. **Rejected as default —
  strictly weaker:** it puts a *private key on the wire*. The CSR form keeps the key
  edge-local for no added operator burden.
- **Token-gated `TrustProxy` (HMAC header).** A near-tie co-leader on operational
  single-source-of-truth — we **grafted** that strength (the SAN allow-set from the same
  registry). Rejected as primary on security: a replayable header credential,
  order-fragile strip middleware, an O(N) HMAC CPU-amplification vector, and a clock-skew
  failure mode. mTLS has none of these.
- **Dynamic IP trust list (ConfigMap of CIDRs).** Lowest effort; we graft its
  operator-asserted-trust principle and keep-last-good discipline. Rejected as primary: it
  does **not raise the security bar** and widens the spoof surface for NAT'd edges. Kept as
  the optional Phase 3 companion.
- **SPIFFE/SPIRE workload identity.** Strongest in theory, operationally disqualifying now
  (out-of-cluster attestation needs SPIRE federation + a second rotating CA bundle whose
  staleness breaks the data plane). We graft only its **URI-SAN naming** and leave a Phase
  2 migration path.
- **CA-only mTLS (`EDGE_TRUST_REQUIRE_SAN=false`).** Supported for **non-issuance**
  deployments but **forbidden with CP-issuance**: CA-only trusts any chain to the edge CA
  with no per-request SAN check, so a cert minted from a leaked token would stay trusted
  for the full TTL — resurrecting exactly the split-brain single-sourcing closes.
- **cert-manager-issued CA / cert-manager-proxy issuance (removed).** An earlier draft
  offered `EDGE_CA_MODE=cert-manager` (the CP proxies a `CertificateRequest`) and an
  out-of-band cert-manager self-signed Issuer for the CA. **Removed:** it added a hard CRD
  dependency, an async issuance round-trip, and an out-of-band CA-creation step that
  defeats the zero-PKI goal for a bare Docker edge. The CP now self-manages the CA
  (managed mode); operators with an existing PKI use **provided** mode (mounted CA, no
  CRDs). cert-manager can still *populate* the mounted Secret, but the CP treats it as
  opaque files — no `CertificateRequest`, no polling, no CRD.

## Open questions

- **Empty-stub feasibility:** do the target k8s versions reject a zero-length `tls.crt`
  on a `kubernetes.io/tls` Secret CREATE? If yes, the pre-created stub must be type
  `Opaque`. Confirm and pin one stub type.
- **NameConstraints enforcement:** does `x509.Verify` actually enforce
  `PermittedURIDomains` for a `spiffe://` leaf URI against `parapet.moonrhythm.io`? Add a
  conformance test (reject `spiffe://evil.example/edge/x`, accept the legit form) **before**
  counting NameConstraints as a security control — the stdlib's URI-SAN NameConstraint
  support is underspecified.
- **`EDGE_CA_TTL` default:** 10y maximizes single-theft value of a plaintext-Secret key.
  Pin shorter (1–2y) until convergence-gated rotation ships, or keep 10y only contingent
  on rotation being implementable? Tie the decision to whether etcd encryption-at-rest is
  a hard prerequisite.
- **CP-only namespace for the CA Secret:** ship the key-read-isolation manifest (core SA
  cannot read `parapet-edge-ca`) as a Phase-1 option now, or defer? The core's SNI read is
  namespace-wide by necessity, so co-tenancy concedes core-reads-the-key unless the CA
  Secret moves namespaces.
- **HSM/KMS `Signer`:** the interface lands in Phase 1; does the in-memory impl suffice
  for first ship, and is a KMS round-trip per issuance acceptable against the
  fleet-restart-storm concurrency budget?
- **System-readiness gap:** add an edge-side post-issuance probe (test re-encrypt
  handshake to the core before flipping ready), or accept the gap with the core-side
  `parapet_trust_source{mtls}` / bundle-hash as a REQUIRED onboarding gate?
- **Rotation single-writer mechanism:** ship Phase-1 rotation as a one-shot Job/subcommand,
  or add leader election to the steady-state `replicas: 2`? The Secret-as-lock CAS
  linearizes only create-once, not the 4-stage promote/trim.
- **`EDGE_CLIENTCERT_TTL` vs CP-outage budget:** pin a default that exceeds the operator's
  CP recovery SLO, or expose `TTL` + renew-before as paired knobs with a guard that
  renew-before < `TTL` by a safe margin?

## Conformance / contract

On acceptance, fold into [`SPEC.md`](SPEC.md): the trust predicate
(`cidrTrust OR (verified-edge-CA-chain AND SAN ∈ allow-set)`), the new
`POST /v1/edge-cert` endpoint (CSR in, chain out; CP-decided SAN; no key on the wire),
the managed/provided CA model, the new env vars (`EDGE_TRUST_*`, `EDGE_DATAPLANE_MTLS`,
`EDGE_CLIENTCERT_*`, `EDGE_CA_*`, CP `POD_NAMESPACE`/`WATCH_NAMESPACE`), the shared
SAN-derivation package + its CP-SAN == core-allow-set conformance test, the
NameConstraints-enforcement test, the `X-Forwarded-Country/-ASN` ingress strip, and the
per-request order (trust evaluation precedes WAF/rate-limit). The Rust implementation in
[`rust/`](rust/) tracks the same contract or records a divergence.

[TLS SNI fallback memory]: the proxy serves a self-signed fallback on an SNI miss
when the live cert table loses `GetCertificate`; the `GetConfigForClient` self-test
above exists to prevent re-introducing that class of bug during a trust reload.
