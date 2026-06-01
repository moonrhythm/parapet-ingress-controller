# Auto-trust edge proxy (data-plane trust without a restart)

> **Status: DRAFT / design-only — not implemented.** This proposes how the
> in-cluster **core** proxy (`cmd/parapet-ingress-controller`, "parapet") comes to
> trust a newly-deployed **edge** proxy (`cmd/edge-proxy` + [`edge/`](edge/))
> automatically — without an operator editing `TRUST_PROXY` and restarting the
> core. It builds on the edge architecture in [`EDGE.md`](EDGE.md). Per
> [`CLAUDE.md`](CLAUDE.md), the behavior contract changes in [`SPEC.md`](SPEC.md)
> first; on acceptance, the contract bits (the trust predicate, the new env vars,
> the new `POST /v1/edge-cert` endpoint, the per-request order) fold into `SPEC.md`
> and the architecture into `EDGE.md`.

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

1. **A dedicated, single-purpose edge CA.** Created once. It signs **nothing else**,
   so "chains to this CA" means exactly "is a sanctioned-edge credential." Under
   `EDGE_CA_MODE=direct` (the Docker-friendly default) the CA key **lives with the
   control plane** (its own RBAC-locked Secret); under `EDGE_CA_MODE=cert-manager`
   it stays inside cert-manager. Either way the key never reaches an edge — only
   leaf certs do. See [Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert).

2. **Each edge gets a short-lived client cert with a stable URI SAN
   `spiffe://parapet.moonrhythm.io/edge/<id>`.** By default the **control plane
   issues it** over the edge's existing bearer-authenticated HTTPS channel — the
   edge sends a CSR to `POST /v1/edge-cert`, the CP signs it with the in-cluster
   edge CA and returns only the cert chain; the **private key never leaves the
   edge**, and the **CP decides the SAN from the token identity** (ignoring any SAN
   in the CSR), so a compromised edge cannot request a SAN it isn't entitled to.
   cert-manager (a per-edge `Certificate`, `usages: [client auth]`) is a
   **k8s-only alternative** for operators who already run it. Renewal is generous
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
   existing keep-alive / HTTP-2 connections. That is the fast revocation lever, and
   (per the security model) the *only* bound on a cert minted from a leaked token.

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
**both** with the same onboarding gesture ("provision one token"). The mechanism
that makes the cert *arrive* differs:

**k8s edge.** The edge runs as a Deployment in some cluster (its own or the core's).
cert-manager is available, so a per-edge `Certificate` (issuer `parapet-edge-ca`,
`usages: [client auth]`, URI SAN `spiffe://parapet.moonrhythm.io/edge/<id>`) is
minted into a `kubernetes.io/tls` Secret and mounted; `edge/forward.go` reads it
**live**. This is the cert-manager path — now a **k8s-only alternative**, not the
default.

**Docker edge (the motivating case).** The edge is a bare `docker run` on a VM / box
near clients (`deploy/edge/run-edge-docker.sh`). Its **only required input is
`EDGE_CP_TOKEN`** — no cert-manager, no CRDs, no file mounts, no manual renewal. It
already pulls its public cert+key (`GET /v1/certs`) and WAF rules (`GET /v1/waf`)
from the control plane on `EDGE_REFRESH_INTERVAL`, fail-static, keys in memory only.
A cert-manager-mounted client cert is **impossible** here (there is no cert-manager
and no Secret to mount), and a hand-mounted PEM re-introduces manual file management
and manual renewal — exactly what the token-pull model removed for the public cert.

**So the data-plane identity rides the SAME channel and loop the public cert already
rides.** The control plane **issues** the edge its data-plane client cert over the
existing bearer-authenticated HTTPS channel: `POST /v1/edge-cert` (see
[Control-plane wiring](#control-plane-wiring-cp-issues-the-client-cert)), CSR in,
signed chain out, on `EDGE_REFRESH_INTERVAL`, fail-static, key in memory only. This
is **the primary mechanism**; cert-manager is the alternative for operators who
already run it and want the CA key out of the CP (`EDGE_CA_MODE=cert-manager`).

| | k8s edge | Docker edge |
|---|---|---|
| Public cert+key | `GET /v1/certs` (token-pull) | `GET /v1/certs` (token-pull) |
| WAF rules | `GET /v1/waf` (token-pull) | `GET /v1/waf` (token-pull) |
| **Data-plane client cert** | cert-manager Secret **or** `POST /v1/edge-cert` | **`POST /v1/edge-cert`** (only option — no cert-manager) |
| Required edge input | token (+ optional mounted cert Secret) | **`EDGE_CP_TOKEN`, and nothing else** |
| Renewal | cert-manager `renewBefore` / CP loop | CP loop (`EDGE_REFRESH_INTERVAL`) |

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
`ClientAuth == VerifyClientCertIfGiven` (not `RequireAndVerify`, which would abort
Cloudflare/browser handshakes; not `NoClientCert`, which silently disables mTLS).
The SNI-cert reload loop and the trust reload loop write **separate** atomics and
never share a config object.

**The trust watch** (`controller.go` + a new `controller_trust.go` mirroring
`controller_waf.go`): a 6th watcher, gated by `EDGE_TRUST_SECRET != ""` (default
off ⇒ identical to today). Reuse the generic `watchResource[*v1.Secret]` for
`POD_NAMESPACE`; on change call `reloadTrustDebounced` (a 300 ms `debounce`). It
**never rebuilds `ctrl.mux`** (trust is orthogonal to routes) and is
**validate-then-swap, all-or-nothing** like WAF `SetRules`: parse `ca.crt` with
`x509.NewCertPool().AppendCertsFromPEM`; a **non-empty input that yields zero certs
is rejected** (keep last-good, log, bump `parapet_trust_reload_rejected_total`); a
*deliberately empty* `ca.crt` means "mTLS disabled." On success, atomically `Store`
**both** `clientCAs` and `trustPol` together so they can never disagree. A rejected
reload keeps last-good **and alerts loudly** — a stale allow-set silently degrades
every edge onboarded after the rejection.

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
  (metric + log) and gates readiness — never a silent half-rotated (new-key/old-chain)
  state.
- **`edge/refresh.go`** — `RefreshEdgeCertOnce(cp, ccStore)` mirroring
  `RefreshCertOnce`: generate an ephemeral key **into a local var** (not the live
  store), build the CSR, `cp.FetchEdgeCert(...)`, on success `ccStore.Update(chain,
  localKey)` as **one atomic unit**, on error fail-static (keep the in-memory cert,
  log a warning). `RunEdgeCertRefresh(ctx, cp, ccStore, ...)` mirrors
  `RunCertRefresh` but **renews on remaining-life/renew-before, not bare interval
  equality**, with **aggressive backoff retries** (faster than the 300 s tick) as
  expiry nears, adds **per-edge jitter** (the current `RunCertRefresh` has none, so
  a co-booted fleet stays phase-locked — a thundering-herd risk on a signing
  endpoint), and **honors the CP's `Retry-After`**.
- **`edge/forward.go` `NewForwarder`** gains a `*ClientCertStore` param (nil ⇒
  anonymous re-encrypt, back-compat); on `useTLS` it sets
  `tlsConfig.GetClientCertificate = ccStore.GetClientCertificate`.
  `InsecureSkipVerify` stays for now (the edge still doesn't verify the core's
  server cert — see [open questions](#open-questions)).
- **Readiness is fail-closed.** When `EDGE_DATAPLANE_MTLS=true`, the readiness gate
  (`cmd/edge-proxy/main.go:197`) becomes
  `(serveAll || store.Loaded()) && clientCert.Loaded()` — a hard AND that
  **serve-all does NOT bypass** (the headline Docker serve-all edge must not go
  ready with no client cert and silently run untrusted). First-boot issuance
  failure keeps the edge **not-ready** (503), not serving-while-untrusted, with a
  bounded background retry that flips ready when the first cert lands.

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
fresh ephemeral key each renewal means a new public key → new leaf → new chain, so a
304 could never legitimately fire and an erroneous one would silently freeze a cert
toward expiry — renewal is driven **solely** by `not_after`/renew-before. Body
capped at 16 KiB via `io.LimitReader`. Absent signer / `EDGE_CA_*` unset ⇒ the
endpoint **404s** (fully backward-compatible, mirroring `waf == nil` → 404).

**CSR flow** (reusing `edge/refresh.go` + `edge/cp.go` `CpClient`):

1. **Edge — ephemeral key in memory.** Generate `ecdsa.GenerateKey(elliptic.P256())`
   (default; `EDGE_CLIENTCERT_KEY_TYPE`) **into a local variable**. Never written to
   disk — same posture as `CertStore` keys (`edge/certstore.go:26-27`).
2. **Edge — build CSR.** `x509.CreateCertificateRequest` with a minimal template;
   any hint SAN/CN is **irrelevant** (the CP overrides it). PEM-encode.
3. **Edge — POST over the bearer channel.** New `CpClient.FetchEdgeCert(csrPEM)`
   mirroring `FetchCert`/`FetchWaf`: POSTs `{"csr_pem":…}`, sets `Authorization:
   Bearer <token>`, body-capped read, returns chain+not_after+serial on 200 / error
   otherwise (caller is fail-static). `do()` is generalized to take method+body
   (today it is GET-only).
4. **CP — verify + sign** (`handleEdgeCert`, new): `bearer(r)` + `authz.Known(token)`
   → 401; `authz.Identity(token)` → 403 if no grant; decode CSR; **whitelist the key
   type/curve BEFORE verifying** (ECDSA P-256/P-384 or Ed25519 only; reject RSA →
   400) so a `CheckSignature` DoS on an oversized key is impossible;
   `csr.CheckSignature()` (mandatory, unconditional — an unsupported sig alg is a
   hard 400, never a silent pass) → 400 on failure; then `Signer.Sign(csr.PublicKey,
   authorizedSAN)`.
5. **CP — return chain only.** 200 with `chain_pem` + `not_after` + `serial`.
6. **Edge — assemble + hold atomically.** Pair the returned chain with the in-memory
   key into a `tls.Certificate` (`tls.X509KeyPair`) and atomically store the
   **complete** keypair+chain in `ClientCertStore`.
7. **Edge — present via `GetClientCertificate`** per handshake — no restart, no file.

### Signing: template, custody, rate-limiting

All in `edgecp/` + `cmd/edge-controlplane`, reusing existing primitives.

**`edgecp/server.go`.** New `handleEdgeCert` + `mux.HandleFunc("POST /v1/edge-cert",
…)`. New `signer *Signer` field (nil ⇒ 404), wired by a `WithSigner(*Signer)`
chaining method like `WithWAF`. **Absent signer ⇒ backward-compatible.**

**`edgecp/signer.go` (new).** `Signer` holds the parsed edge CA cert + key; `Sign`
builds the `x509.Certificate` template **from a zero value — never from the parsed
CSR** — setting ONLY:

- `SerialNumber`: a fresh 128-bit CSPRNG serial (`crypto/rand`), surfaced as `serial`.
- `NotBefore = now - EDGE_CLIENTCERT_SKEW` (default 10m), `NotAfter = now + EDGE_CLIENTCERT_TTL`.
- `KeyUsage = DigitalSignature`; `ExtKeyUsage = [x509.ExtKeyUsageClientAuth]` ONLY.
- `URIs = [authorizedSAN]` derived from the token (the shared-derivation package).
  **No DNSNames, no IPAddresses, no Subject/CN of significance.**
- `BasicConstraintsValid = true, IsCA = false`.

The CSR contributes **exactly one thing: `csr.PublicKey`**. The template
**explicitly never** assigns `Subject`/`DNSNames`/`IPAddresses`/`EmailAddresses`/
`URIs`/`Extensions`/`ExtraExtensions` from the CSR — getting this exactly right is
the single highest-value invariant (a verifier matching a smuggled CN, a copied
rogue SAN, or a carried-over `basicConstraints CA:true` would defeat the model).
**Post-sign self-check:** re-parse the issued leaf and assert `IsCA==false`,
`KeyUsage==DigitalSignature`, `ExtKeyUsage==[ClientAuth]`, `URIs==[authorizedSAN]`,
`len(DNSNames)==len(IPAddresses)==0`; **refuse to return** a cert that fails any
check (mirrors the `GetConfigForClient` self-test discipline). A conformance test
feeds a CSR carrying `CA:true`, a rogue URI/DNS SAN, and a malicious CN and asserts
none appear in the leaf.

**`edgecp/authz.go` — per-edge identity (explicit opt-in).** Extend `Authz` with
`identities map[string]string` (token → id) populated alongside `tokens` in
`NewAuthz`, plus `Identity(token) (string, bool)`. The grant is **explicit and
separate**, NOT auto-derived from the token's presence or its domains; `Identity`
returns `("",false)` (→ 403) unless the operator set it. A serve-all (`"*"`) token
**MUST NOT** get a default identity. Migration defaults every token to NO identity.

**CA custody — `EDGE_CA_MODE`:**

- **`direct` (default — Docker-friendly).** In-process `x509.CreateCertificate` with
  the edge CA key from `EDGE_CA_CERT`/`EDGE_CA_KEY`. **No cert-manager dependency** —
  the whole point for a bare Docker edge. The CA key is the new crown jewel and
  **now lives with the CP**: store it in its **own** Secret in `POD_NAMESPACE` (NOT
  co-located with tenant TLS keys), tightest RBAC (only the CP ServiceAccount),
  behind the CP's edge-sources-only `NetworkPolicy`. **Hot-reload** the key/cert
  from the watched Secret (validate-then-swap, fail-closed) — NOT load-once — so CA
  rotation needs no CP restart. Constrain the edge CA with **NameConstraints**
  limiting URI SANs to `spiffe://parapet.moonrhythm.io/edge/*` (and EKU clientAuth),
  so even a stolen CA key can mint less. Emit a **loud startup log** that the CP now
  holds a fleet-minting key.
- **`cert-manager` (k8s-only alternative).** The CP proxies a cert-manager
  `CertificateRequest` to an `Issuer`/`ClusterIssuer` and polls. The CA key stays
  inside cert-manager (smaller CP blast radius) but adds a hard CRD dependency and an
  async round trip, and does **not** work without cert-manager. **Strongly preferred
  wherever cert-manager is present.**

**`cmd/edge-controlplane/main.go`.** Load `EDGE_CA_CERT`/`EDGE_CA_KEY` (or
cert-manager mode), build `Signer`, `server.WithSigner(signer)`. Gated on the env
being set (absent ⇒ no signer ⇒ 404 ⇒ back-compat).

**Rate-limiting + DoS.** A **per-token** token-bucket (`EDGE_CLIENTCERT_RATE`,
default 10/min → 429) blunts a single-token forged-CSR flood. It does **nothing**
against a fleet-wide restart storm (N different tokens), so add a **global signing
concurrency cap** (a bounded worker pool / semaphore around `Signer.Sign`) returning
**429/503 + `Retry-After`** when saturated. The authz reject and the **key-type
whitelist run before** any signing, so an unauthorized or oversized-key flood costs
no CA work. Keep the endpoint behind the CP's existing edge-sources-only
`NetworkPolicy`.

## Security model

**Trust boundary.** Exactly the edges holding a private key whose cert chains to the
dedicated edge CA **and** whose URI SAN is in the live allow-set. The CA signs
nothing else. Trust is **operator-asserted**: only an operator editing the registry
Secret moves the boundary — never an edge action, never a token-writable
self-registration. mTLS trust is conferred **only on `:443`**.

**Spoofing.** A non-edge reaching `:443` **cannot forge trust**:
`VerifiedChains` is populated only after the Go stack cryptographically verifies the
presented cert against `ClientCAs`; forging requires the in-cluster CA key. And a
compromised edge **cannot request a SAN it isn't entitled to** — the CP stamps the
SAN from the bearer token's registry identity and ignores the CSR's SAN entirely.

> **Honest scoping (read this).** mTLS authenticates the **connection, not the
> headers.** A trusted edge — or anything wielding a stolen edge key — can still
> set `X-Forwarded-For` to whatever it likes *for its own requests*, because
> parapet honors a trusted hop's XFF verbatim. The claim is **"an unauthenticated
> peer is never trusted,"** not "XFF can never be spoofed." Second caveat: with the
> shipped `TRUST_PROXY: cloudflare` default, a non-edge from a Cloudflare CIDR
> reaching `:443` is CIDR-trusted with no cert. So **never add edge egress CIDRs to
> `TRUST_PROXY`** (mTLS is the edge path), and lock **both** core data-plane ports
> with a `NetworkPolicy` to the edge/Cloudflare source set.

**Replay.** None on the data plane — the cert is proven inside a live mTLS handshake
(ephemeral keys, transcript signing), not a replayable bearer credential.

> **Token-minted certs outlive token revocation.** A leaked-but-not-yet-revoked
> token POSTed to `/v1/edge-cert` mints a self-contained TLS credential the core
> verifies cryptographically for its full TTL. Revoking the token stops *future*
> issuance but does **not** revoke an already-minted cert — only **dropping the
> registry entry** (which drops its SAN from the live allow-set, re-checked per
> request) revokes it, within ~300 ms. Therefore: (1) the leaked-token runbook is
> **"delete the registry entry,"** never "rotate only the token"; (2)
> `EDGE_CLIENTCERT_TTL` is kept short to shrink the window; (3) **CP-issuance is
> INCOMPATIBLE with `EDGE_TRUST_REQUIRE_SAN=false`** (CA-only mode) — the per-request
> SAN check is the *only* bound on such a cert, so the CP MUST refuse to issue
> and/or the core MUST refuse CA-only when the same edge CA backs issuance.

**Blast radius.** A leaked edge client key lets the holder spoof XFF **as that one
edge** until its SAN is dropped (~300 ms) or its cert expires. It leaks **no** server
TLS private key. The **crown jewel is the edge CA key** (mints any edge). Under
`EDGE_CA_MODE=direct` it **lives with the control plane** — a deliberate,
design-acknowledged escalation from the CP's prior posture (it distributed tenant
*leaf* keys; it now holds a *CA* that forges fleet-wide edge trust). Mitigated by: a
**single-purpose** CA, **NameConstraints** capping URI SANs to
`spiffe://parapet.moonrhythm.io/edge/*`, the key in its **own** tightly-RBAC'd
in-cluster Secret (never the tenant-cert Secret, never shipped — only the chain
leaves the cluster), **hot-reload** for restart-free rotation, short
`EDGE_CLIENTCERT_TTL`, per-request SAN revocation, and the
`EDGE_CA_MODE=cert-manager` alternative that keeps the CA key out of the CP. A
future HSM/KMS signer interface can keep the raw key out of pod memory. CA-key
compromise is handled by the overlap rotation runbook with a metric interlock.

**Fail-default: fail-closed, degrading to the static CIDR branch.** A missing trust
Secret ⇒ `trustPol` nil ⇒ mTLS branch always false ⇒ edges distrusted (degraded but
safe — identical to the pre-mechanism world), Cloudflare CIDR unaffected, startup
warning logged. An empty/garbage `ca.crt` on reload ⇒ validate-then-swap **rejects**
and keeps last-good. First-boot issuance failure ⇒ edge **not-ready** (never
serve-while-untrusted). **No path fails open.**

**The explicit tradeoff.** This forces re-encrypt TLS (`EDGE_UPSTREAM_TLS=true`), a
PKI lifecycle, and the CA key living with the CP (direct mode). An **expired edge
cert hard-fails the handshake** (502s); the CP-outage budget (= `TTL` ×
renew-before-fraction) must exceed the operator's CP recovery SLO. Accepted: a
cryptographic, IP-independent, per-edge-revocable identity that makes a bare Docker
edge work with nothing but a token is worth the discipline.

## Fail modes

| Failure | Behavior |
|---|---|
| Trust Secret absent / never created | mTLS branch false for all (`trustPol` nil); edges distrusted (XFF overwritten → WAF/limits/GeoIP see edge IP); core serves; Cloudflare CIDR unaffected. **Fail-closed, degraded-not-down.** Startup warning + `parapet_trust_source{none}`. |
| `ca.crt` edited to empty/garbage on reload | Validate-then-swap: non-empty input yielding zero certs **rejected**, last-good kept, `parapet_trust_reload_rejected_total++`, **loud alert** (a stale allow-set silently degrades edges onboarded after). A *deliberately* empty `ca.crt` = "mTLS disabled." Never fails open. |
| Edge client cert expired / not yet renewed | `VerifyClientCertIfGiven` **aborts the handshake** → edge `:443` connection 502s. Mitigated by short-TTL + generous renew-before, live `GetClientCertificate` reload, NTP sync, alerting on `parapet_edge_clientcert_not_after`. |
| Edge on plaintext `:80` but operator expected trust | No client cert on `:80`; `r.TLS == nil`; edge distrusted (CIDR-only). Made loud: edge errors if `EDGE_DATAPLANE_MTLS` set with TLS off; `parapet_trust_source{none}` alerts. |
| Per-edge revocation (registry-entry delete) | **Fast path.** SAN re-checked per request against the live atomic allow-set → distrusts within ~300 ms even on existing connections. The routine revocation lever. |
| CA-drop revocation latency | `VerifiedChains`/`ClientCAs` are consulted only at **handshake**. Dropping a CA takes effect on **new** handshakes only; existing connections keep their verified chain until they close. Mitigate: prefer SAN-drop; cap `:443` connection age; reserve CA-drop for CA-key compromise. |
| Edge CA private key leaked (direct mode) | Attacker mints trusted edges until CA rotation. **Highest severity.** Mitigated by the own-Secret + tightest-RBAC custody, NameConstraints, the cert-manager alternative (key out of CP), and the overlap rotation runbook with a metric interlock. |
| `GetConfigForClient` returns nil / omits `ClientAuth`/`GetCertificate` | Guarded: base config built non-nil before `Serve()`; callback returns last-good, never nil; startup self-test asserts the three properties. |
| CP-issuance endpoint unreachable / CP down | Edge keeps its last-good in-memory client cert (**fail static**); core `:443` handshakes keep succeeding. Renewal retries with aggressive backoff as expiry nears. Only if the CP stays down PAST `NotAfter` does the handshake hard-502. Outage budget = `TTL` × renew-before-fraction. |
| Leaked-but-not-yet-revoked token replayed to `/v1/edge-cert` | Mints a cert for ITS OWN SAN, cryptographically valid for the full TTL. Token revocation does NOT revoke it — **only deleting the registry entry** drops its SAN (re-checked per request → distrusted ~300 ms). Runbook: delete the registry entry. Bounded by short `EDGE_CLIENTCERT_TTL`. |
| CP-issuance enabled with `EDGE_TRUST_REQUIRE_SAN=false` (CA-only) | **Refused — fail-closed.** CA-only trusts any chain to the edge CA with no per-request SAN check, so a leaked-token-minted cert would stay trusted for the full TTL. The CP refuses to issue and/or the core refuses CA-only; startup error names the conflict. |
| Malformed / oversized-key / unsupported-alg CSR (DoS probe) | 16 KiB body cap (413) bounds bytes; the **key-type/curve whitelist rejects (400) BEFORE `CheckSignature`** so an oversized-RSA verify-DoS is impossible. `CheckSignature` is mandatory; an unsupported sig alg is a hard 400. authz + reject precede any CA signing. |
| Fleet-wide re-issue storm (rollout / node drain / CP recovery) | Per-token rate limit does NOT help (N tokens). A **global signing concurrency cap** returns 429/503 + `Retry-After`; the edge honors it with backoff; the edge refresh loop adds **jitter** (unlike the public-cert loop) so a co-booted fleet does not stay phase-locked. |
| CP signs with a CA the core's `ClientCAs` does not yet trust (rotation skew) | Freshly-issued certs fail verification at the core → 502s. Prevented by the overlap invariant: the new CA must be in the core's `ClientCAs` bundle (concatenated CAs allowed) BEFORE the CP signs with it; the old CA stays until the metric interlock confirms every edge re-issued. CP hot-reloads the CA so rotation needs no restart. |
| Clock skew: core clock behind the CP by > `EDGE_CLIENTCERT_SKEW` | A fresh cert is "not yet valid" at the core → handshake aborts → 502s, self-healing once skew elapses. The validator is the **core** clock. Mitigated by the configurable NotBefore backdating (default 10m), a hard NTP-sync prerequisite between CP and core pods, and a distinct notBefore/notAfter handshake-failure metric. |
| First-boot issuance fails under `EDGE_DATAPLANE_MTLS=on` (CP down at startup) | **Fail-CLOSED on readiness:** edge stays not-ready (503), is NOT routed to, does not serve-while-untrusted. Bounded background retry flips ready when the first cert lands. Readiness `= (serveAll || store.Loaded()) && clientCert.Loaded()` — serve-all does NOT bypass. Availability tradeoff documented; CP HA recommended. |
| `ClientCertStore.Update` gets an unparseable / mismatched chain | All-or-nothing: `tls.X509KeyPair(chain, heldKey)` failing keeps the PRIOR complete pair (never clears the pointer, never swaps in a broken cert), logs + bumps a rejection metric. Never a silent half-rotated state. |

## Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `TRUST_PROXY` | core | `cloudflare` | **Unchanged.** Static CIDR list / `cloudflare`/`true`/`false`. Becomes the `cidrTrust` OR-branch. **Never add edge egress CIDRs here.** |
| `EDGE_TRUST_SECRET` | core | `""` (feature **off**) | Name of the Secret in `POD_NAMESPACE` carrying `ca.crt` (edge CA PEM bundle). `edge-controlplane-tokens` (single-source) or a dedicated `parapet-edge-trust` (separation). Unset ⇒ mTLS disabled, identical to today. |
| `EDGE_TRUST_REQUIRE_SAN` | core | `true` | Trust requires the verified leaf's URI SAN ∈ the live allow-set (enables per-edge revocation). When false (CA-only), any chain to the edge CA is trusted. **Incompatible with CP-issuance: the per-request SAN check is the ONLY bound on a cert minted from a leaked bearer token (token revocation does not revoke a minted cert). When the same edge CA backs issuance, the CP MUST refuse to issue and/or the core MUST refuse CA-only — fail-closed.** |
| `EDGE_DATAPLANE_MTLS` | edge | `false` | Enable the CP-issued data-plane client cert (CSR → `POST /v1/edge-cert`, presented via `GetClientCertificate`). Off ⇒ anonymous re-encrypt, identical to today. Requires `EDGE_UPSTREAM_TLS=true` (loud error otherwise). When on, readiness is gated on the client cert (fail-closed). |
| `EDGE_CLIENTCERT_KEY_TYPE` | edge | `ecdsa-p256` | Key type for the in-memory ephemeral keypair (the key that never leaves the edge). `ecdsa-p256`/`p384`/`ed25519` — matches the CP's accepted-key whitelist. RSA is not offered (bounds the CP's CSR-verify DoS surface). |
| `EDGE_CA_CERT` | CP | `""` | PEM path to the edge CA certificate (its OWN Secret, not the tenant-cert Secret). The same CA the core loads as `ClientCAs`. Hot-reloaded. Unset ⇒ no signer ⇒ `POST /v1/edge-cert` 404 (feature off). |
| `EDGE_CA_KEY` | CP | `""` | PEM path to the edge CA **private** key (direct mode). The new crown jewel living with the CP — its OWN tightly-RBAC'd Secret, never shipped. Hot-reloaded. A loud startup log warns the CP holds a fleet-minting key. Ideally NameConstrained. |
| `EDGE_CA_MODE` | CP | `direct` | `direct` = in-process `x509.CreateCertificate` (no cert-manager — the Docker-friendly default). `cert-manager` = proxy a `CertificateRequest` (k8s-only; CA key stays in cert-manager; CRD dependency + async). Prefer `cert-manager` where present. |
| `EDGE_CLIENTCERT_TTL` | CP | `1h` | Issued cert lifetime. Short — renewal is free over the loop — to bound a leaked-token-minted cert. Outage budget = `TTL` × renew-before-fraction; raise (e.g. 24–72h) if outage tolerance matters more than mint-window shrinkage (call out the tension). |
| `EDGE_CLIENTCERT_SKEW` | CP | `10m` | NotBefore backdating slack. The cert is minted on the CP clock but **validated on the core clock** at the handshake. NTP sync between CP and core pods is a hard prerequisite. A distinct core-side notBefore/notAfter failure metric surfaces a skew regression. |
| `EDGE_CLIENTCERT_RATE` | CP | `10/min` | Per-token issuance rate limit (429 over cap). A **global** signing concurrency cap (worker pool around `Signer.Sign`, 429/503 + `Retry-After`) is separate and necessary — the per-token limit does nothing against a fleet-wide restart storm. |
| `EDGE_UPSTREAM_CLIENT_CERT` / `EDGE_UPSTREAM_CLIENT_KEY` | edge | `""` / `""` | **cert-manager / mounted-Secret (k8s-only) path**, superseded as the default by `EDGE_DATAPLANE_MTLS` + CP-issuance. PEM paths to a mounted client cert+key, live-reloaded from disk. Use for the k8s-edge mount case. |
| `EDGE_UPSTREAM_TLS` | edge | `false` | **Unchanged.** Must be `true` for mTLS trust. Selects the re-encrypt path. |
| `EDGE_UPSTREAM_SNI` | edge | `""` | **Unchanged.** SNI/`ServerName` presented to the core on re-encrypt. |

Metrics: `parapet_trust_source{mtls|cidr|none}` and `parapet_trust_reload_rejected_total`
(core); `parapet_edge_clientcert_loaded` (0/1) and `parapet_edge_clientcert_not_after`
(edge). Both planes also expose the registry generation/hash they last applied, so an
operator can confirm convergence before declaring an edge trusted.

## Onboarding flow (the payoff)

1. **One-time:** create the dedicated edge CA. Under `EDGE_CA_MODE=direct`, put its
   cert + key in their **own** RBAC-locked Secret for the CP (`EDGE_CA_CERT` /
   `EDGE_CA_KEY`) and its cert in the core's trust Secret (`ca.crt`); under
   `cert-manager`, create the `Issuer`. Roll the core and CP **once** to pick up the
   new code. *This is the only restart, ever — never again per-edge.*
2. **Per edge — grant a data-plane identity (one registry edit, no cert-manager).**
   Add the edge's entry to `edge-controlplane-tokens` with an explicit `id` (its
   SPIFFE identity opt-in). This single edit (a) authorizes its cert/WAF fetch, (b)
   makes the CP **issue** its data-plane client cert on `POST /v1/edge-cert` over the
   existing bearer channel — key generated in the edge's memory, never mounted, never
   renewed by hand — and (c) adds its SAN `spiffe://…/edge/<id>` to the core's live
   allow-set. *(k8s-only alternative: mint a cert-manager `Certificate`, mount the
   Secret, set `EDGE_CA_MODE=cert-manager` + `EDGE_UPSTREAM_CLIENT_CERT`.)*
3. **Configure the edge:** `EDGE_DATAPLANE_MTLS=true`, `EDGE_UPSTREAM_TLS=true`,
   `EDGE_UPSTREAM_ADDR` → core `:443`. For a Docker edge that's it — **no client-cert
   file mounts**; its only input across all of this stays `EDGE_CP_TOKEN`.
4. **Deploy.** The edge generates a keypair in memory, fetches its cert from the CP,
   re-encrypts to `:443` presenting it; the core verifies the chain + SAN and
   **immediately honors its `X-Forwarded-*`** — no `TRUST_PROXY` edit, no core
   restart. Confirm via `parapet_trust_source{mtls}` and `parapet_edge_clientcert_loaded`.
5. **Revoke:** **delete the edge's registry entry** → its SAN leaves the allow-set →
   distrusted within ~300 ms, even on live connections (deleting only the token does
   NOT revoke an already-minted cert). For a leaked **CA** key, use the overlap
   rotation runbook.

## Phasing

1. **Phase 1 — the primary mechanism (makes a bare Docker edge work, no cert-manager).**
   Core: the per-request closure, `GetConfigForClient` hot-swap over a **separate**
   atomic from the SNI cert table, the `EDGE_TRUST_SECRET` watch
   (validate-then-swap, keep-last-good, alert-on-reject), `EDGE_TRUST_REQUIRE_SAN=true`
   single-sourced, the unconditional `X-Forwarded-Country/-ASN` strip, the metrics.
   **Plus CP-issuance:** `POST /v1/edge-cert`, `edgecp/signer.go` (zero-value template
   + post-sign self-check + key-type whitelist), `Authz.Identity`, the **shared SAN
   derivation package** imported by both binaries, `EDGE_DATAPLANE_MTLS` edge wiring
   with atomic key+chain swap, jitter, fail-closed readiness, the global signing
   concurrency cap. The cert-manager mount path
   (`EDGE_CA_MODE=cert-manager` / `EDGE_UPSTREAM_CLIENT_CERT`) ships **alongside** as
   the k8s-only alternative. `NetworkPolicy` locking core `:80`/`:443` to
   edge/Cloudflare sources.
2. **Phase 2 — stronger hardening.** Mutual auth of the hop (edge pins the core CA,
   drop `InsecureSkipVerify`); CRL/OCSP via `tls.Config.VerifyConnection` if
   revocation must beat TTL + SAN-drop; an HSM/KMS `Signer` interface so the raw edge
   CA key need not sit in CP pod memory; real SPIRE SVID migration (the SAN naming
   already aligns).
3. **Phase 3 — optional companion.** A `TRUST_PROXY_DYNAMIC=true` ConfigMap-of-CIDRs
   OR-branch for callers that genuinely cannot present a client cert (a known
   in-cluster plaintext `:80` caller) — same atomic + validate-then-swap discipline,
   never panic on the watch path.

## Alternatives considered

- **CP mints key+cert and ships both (vs CSR-based).** Simpler on the edge (no
  in-process keygen/CSR), and the only viable fallback if some edge runtime cannot do
  x509 keygen. **Rejected as the default — strictly weaker:** it puts a *private key
  on the wire*, re-introducing exactly the key-transits-the-channel exposure the cert
  path otherwise avoids. The CSR form keeps the key edge-local (generated in memory;
  only the public key + returned chain transit) for **no** added operator burden, and
  the CP-decides-SAN property holds in both forms.
- **Token-gated `TrustProxy` (HMAC-over-timestamp header).** A near-tie co-leader on
  operational single-source-of-truth — which is why we **grafted** that strength (the
  SAN allow-set comes from the same registry). Rejected as the *primary* mechanism on
  security: the credential is a request **header** whose placement the attacker
  controls; it is replayable for the skew window; the strip-before-upstream middleware
  is order-fragile; HMAC verification is an O(N) CPU-amplification vector; and it adds
  a clock-skew failure mode. mTLS has none of these.
- **Dynamic IP trust list (ConfigMap of CIDRs).** Lowest effort; we graft its
  operator-asserted-trust principle and keep-last-good discipline. Rejected as primary:
  it does **not raise the security bar** — anything sharing a trusted CIDR can spoof
  XFF — and for NAT'd/dynamic edges the natural pattern widens the spoof surface. Kept
  as the optional Phase 3 companion for the `:80` gap.
- **SPIFFE/SPIRE workload identity (mTLS SVID).** Strongest in theory, operationally
  disqualifying now: an out-of-cluster edge can't use in-cluster attestation, so it
  needs SPIRE federation — a hard runtime dependency and a second rotating CA bundle
  whose staleness breaks the data plane. We graft only its **URI-SAN naming** and
  leave a Phase 2 migration path.
- **CA-only mTLS (`EDGE_TRUST_REQUIRE_SAN=false`).** Supported for **non-issuance**
  deployments (issuing the cert is the whole onboarding) but **forbidden in
  combination with CP-issuance**: CA-only trusts any chain to the edge CA, so a cert
  minted from a leaked token before revocation would stay trusted for the full TTL
  with no per-request revocation lever — resurrecting exactly the split-brain
  single-sourcing closes.

## Open questions

- **`EDGE_CLIENTCERT_TTL` default — the mint-window vs CP-outage-budget tension:** a
  short TTL (1h) shrinks a leaked-token-minted cert's life but cuts the outage budget
  (= `TTL` × renew-before-fraction) before an expired cert hard-502s the edge. Pin a
  default that exceeds the operator's CP recovery SLO, or expose `TTL` + renew-before
  as paired knobs with a guard that renew-before < `TTL` by a safe margin?
- **`EDGE_CA_MODE=cert-manager` async issuance:** the CP proxies a `CertificateRequest`
  and polls — what poll timeout / failure handling keeps `POST /v1/edge-cert`
  responsive (503 + `Retry-After` and let the edge fail-static, or block up to a
  bound)? Does it also need the global signing concurrency cap, or does cert-manager's
  own queue suffice?
- **HSM/KMS signer interface for direct mode:** should `Signer.Sign` be an interface so
  the raw edge CA key need not sit in CP pod memory (the highest-severity blast
  radius), and is a KMS round-trip per issuance acceptable against the
  fleet-restart-storm concurrency budget?
- **Key reuse across a graceful restart:** should the edge re-use a surviving
  in-memory key across a restart, or accept that every restart = one fresh
  keygen+CSR+sign (given keys are never written to disk)? Is the per-restart signature
  cost acceptable at fleet scale once the global cap + jitter are in place?
- **Mutual auth of the hop:** should the edge verify the core's server cert (pin the
  core CA, drop `InsecureSkipVerify` in `forward.go`)? Today only edge→core is
  authenticated.
- **Connection-age cap on `:443`:** what max lifetime balances draining stale-CA
  connections (for CA-drop revocation) against handshake churn? The default
  `IdleTimeout` 320 s lets a busy connection outlive a CA drop without an explicit cap.
- **Multi-CA `ca.crt` parsing:** confirm `AppendCertsFromPEM` over a concatenated
  bundle adds every valid block and that one malformed block doesn't silently drop the
  good CAs — validate-then-swap must treat a partially-bad bundle as a **rejected**
  reload.

## Conformance / contract

On acceptance, fold into [`SPEC.md`](SPEC.md): the trust predicate
(`cidrTrust OR (verified-edge-CA-chain AND SAN ∈ allow-set)`), the new
`POST /v1/edge-cert` endpoint (CSR in, chain out; CP-decided SAN; no key on the
wire), the new env vars (`EDGE_TRUST_SECRET`, `EDGE_TRUST_REQUIRE_SAN`,
`EDGE_DATAPLANE_MTLS`, `EDGE_CLIENTCERT_*`, `EDGE_CA_*`), the shared SAN-derivation
package + its CP-SAN == core-allow-set conformance test, the `X-Forwarded-Country/-ASN`
ingress strip, and the per-request order (trust evaluation precedes WAF/rate-limit,
as today). The Rust implementation in [`rust/`](rust/) tracks the same contract or
records a divergence.

[TLS SNI fallback memory]: the proxy serves a self-signed fallback on an SNI miss
when the live cert table loses `GetCertificate`; the `GetConfigForClient` self-test
above exists to prevent re-introducing that class of bug during a trust reload.
