# Auto-trust edge proxy (data-plane trust without a restart)

> **Status: DRAFT / design-only — not implemented.** This proposes how the
> in-cluster **core** proxy (`cmd/parapet-ingress-controller`, "parapet") comes to
> trust a newly-deployed **edge** proxy (`cmd/edge-proxy` + [`edge/`](edge/))
> automatically — without an operator editing `TRUST_PROXY` and restarting the
> core. It builds on the edge architecture in [`EDGE.md`](EDGE.md). Per
> [`CLAUDE.md`](CLAUDE.md), the behavior contract changes in [`SPEC.md`](SPEC.md)
> first; on acceptance, the contract bits (the trust predicate, the new env vars,
> the per-request order) fold into `SPEC.md` and the architecture into `EDGE.md`.

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

1. **A dedicated, single-purpose edge CA.** Created once (cert-manager self-signed
   `Issuer` + CA `Certificate` `parapet-edge-ca`, or an operator-managed
   self-signed CA). It signs **nothing else**, so "chains to this CA" means exactly
   "is a sanctioned-edge credential." Its private key stays in-cluster; only leaf
   cert+key ever reach an edge.

2. **Each edge gets a short-lived client cert** from that CA (cert-manager
   `Certificate`, `usages: [client auth]`, with a stable SPIFFE-style URI SAN
   `spiffe://parapet.moonrhythm.io/edge/<name>` — a free, greppable per-edge
   identity and a clean future SPIRE migration path). `renewBefore` is generous
   (renew at ~⅓ lifetime) so renewal never races expiry.

3. **The edge presents it** on the re-encrypt hop. `edge/forward.go`'s
   `EDGE_UPSTREAM_TLS=true` path gets a client cert via
   `tls.Config.GetClientCertificate` — a **live disk-reading callback** (mtime
   cached), *not* a one-shot `tls.X509KeyPair` at startup — so a cert-manager
   renewal is picked up with **no edge restart**. A client cert can only ride TLS,
   so edge trust is conferred **only on the core's `:443` listener**; the plaintext
   `:80` listener can present none and is never mTLS-trusted.

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
   existing keep-alive / HTTP-2 connections. That is the fast revocation lever.

### Single source of truth (onboard in one place)

The SAN allow-set is derived from the **same `edge-controlplane-tokens` Secret the
control plane already authorizes against** (`edgecp.Authz`, `edgecp/authz.go`).
Each edge's token entry carries (or deterministically derives) its SPIFFE SAN.
**Onboarding/offboarding touches one registry:**

- Adding a token → the control plane issues that edge its certs/WAF **and** the
  core adds its SAN to the data-plane allow-set. Both planes converge from one
  object, in ~300 ms, with no restart of either.
- **Deleting a token = data-plane revoke**, closing the split-brain where revoking
  only the control-plane token left the edge trusted on the data plane until its
  cert expired.

Operators who prefer separation may instead keep the SAN list in a standalone
`parapet-edge-trust` Secret (`allowed-sans` key); the default wiring reads the
token registry. `ca.crt` always lives in the trust Secret (it can hold several
concatenated CAs to support rotation overlap).

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
**both** `clientCAs` and `trustPol` together so they can never disagree.

**Header hardening (a real gap today, not just for mTLS):** mount a middleware
**first** in `main.go`'s `m` chain (before `ctrl`) that **unconditionally deletes**
client-supplied `X-Forwarded-Country` / `X-Forwarded-ASN` at ingress.
`forwardGeoHeaders` (`main.go:329`) only *overwrites* them when a DB is loaded — so
a core with no GeoIP DB currently passes a **client-forged** `X-Forwarded-Country`
straight upstream. Treat both as edge-set-only. (`X-Real-Ip` / `X-Forwarded-For`
stay governed by parapet's trust/distrust.)

## Edge wiring

In `edge/forward.go` `NewForwarder`, on the re-encrypt path (`useTLS == true`),
wire a client cert into the transport's `tls.Config`:

- New `EDGE_UPSTREAM_CLIENT_CERT` / `EDGE_UPSTREAM_CLIENT_KEY` (PEM paths). When
  both are set, set `tls.Config.GetClientCertificate` to a callback that reads the
  cert+key from disk **live** (mtime-cached), so a cert-manager renewal on the
  mounted Secret is picked up with no restart. Both unset ⇒ no client cert
  (anonymous re-encrypt — back-compat with today).
- `tls.Config.InsecureSkipVerify` stays for now (the edge does not yet verify the
  core's server cert — see [open questions](#open-questions)).

In `cmd/edge-proxy/main.go` startup, emit a **loud** error if
`EDGE_UPSTREAM_CLIENT_CERT` is set with `EDGE_UPSTREAM_TLS=false` (a client cert
needs TLS), and a warning if the upstream is core `:443` with no client cert
configured (a silent untrusted downgrade). The edge remains the first hop and sets
**no** `TrustProxy`, so it keeps overwriting incoming `X-Forwarded-*` with the true
client peer before forwarding — the **transitive-trust invariant** the core relies
on.

## Security model

**Trust boundary.** Exactly the edges holding a private key whose cert chains to
the dedicated edge CA **and** whose URI SAN is in the live allow-set. The CA signs
nothing else, so chain-to-CA = sanctioned-edge credential. Trust is
**operator-asserted**: only an operator editing the registry Secret moves the
boundary — never an edge action, never a token-writable self-registration. mTLS
trust is conferred **only on `:443`**.

**Spoofing.** A non-edge reaching `:443` **cannot forge trust**:
`VerifiedChains` is populated only after the Go stack cryptographically verifies
the presented cert against `ClientCAs`; forging requires the in-cluster CA key.

> **Honest scoping (read this).** mTLS authenticates the **connection, not the
> headers.** A trusted edge — or anything wielding a stolen edge key — can still
> set `X-Forwarded-For` to whatever it likes *for its own requests*, because
> parapet honors a trusted hop's XFF verbatim. The claim is **"an unauthenticated
> peer is never trusted,"** not "XFF can never be spoofed." Second caveat: with the
> shipped `TRUST_PROXY: cloudflare` default, a non-edge from a Cloudflare CIDR
> reaching `:443` is CIDR-trusted with no cert. So **never add edge egress CIDRs to
> `TRUST_PROXY`** (mTLS is the edge path), and lock **both** core data-plane ports
> with a `NetworkPolicy` to the edge/Cloudflare source set (today only the control
> plane has one — `deploy/edge/controlplane.yaml`). Defense-in-depth so a stolen
> edge key isn't usable from the open internet, and so "just add a CIDR" is never
> the operational fix.

**Replay.** None on the data plane — the cert is proven inside a live mTLS
handshake (ephemeral keys, transcript signing), not a replayable bearer credential.
Residual risk is **key theft**, bounded by short cert lifetime + per-request SAN
revocation.

**Blast radius.** A leaked edge client key lets the holder spoof XFF **as that one
edge** until its SAN is dropped (~300 ms) or its cert expires. It leaks **no**
server TLS private key (a separate control-plane credential). The **crown jewel is
the edge CA key** (mints any edge) — kept in-cluster only, never shipped,
single-purpose, rotated only on CA compromise.

**Fail-default: fail-closed, degrading to the static CIDR branch.** A missing trust
Secret ⇒ `trustPol` nil ⇒ mTLS branch always false ⇒ edges distrusted (degraded but
safe — identical to the pre-mechanism world), Cloudflare CIDR unaffected, startup
warning logged. An empty/garbage `ca.crt` on reload ⇒ validate-then-swap **rejects**
and keeps last-good, so a fat-fingered edit can't silently distrust the whole fleet.
**No path fails open.**

**The explicit tradeoff.** This forces re-encrypt TLS (`EDGE_UPSTREAM_TLS=true`) and
a PKI lifecycle (CA, per-edge certs, renewal) the plaintext `:80` default avoided,
and an **expired edge cert hard-fails the handshake** (502s) rather than degrading.
Accepted: a cryptographic, IP-independent, per-edge-revocable identity is worth the
`renewBefore` discipline and the network backstop.

## Fail modes

| Failure | Behavior |
|---|---|
| Trust Secret absent / never created | mTLS branch false for all (`trustPol` nil); edges distrusted (XFF overwritten → WAF/limits/GeoIP see edge IP); core serves; Cloudflare CIDR unaffected. **Fail-closed, degraded-not-down.** Startup warning + `parapet_trust_source{none}`. |
| `ca.crt` edited to empty/garbage on reload | Validate-then-swap: non-empty input yielding zero certs **rejected**, last-good kept, `parapet_trust_reload_rejected_total++`, error logged. A *deliberately* empty `ca.crt` = "mTLS disabled." Never fails open. |
| Edge client cert expired / not yet renewed | `VerifyClientCertIfGiven` **aborts the handshake** → edge `:443` connection fails (502s), harsher than a missing cert. Mitigated by generous `renewBefore`, live `GetClientCertificate` reload (no restart), NTP sync, alerting on edge 502s + cert `notAfter`. |
| Edge on plaintext `:80` but operator expected trust | No client cert on `:80`; `r.TLS == nil`; edge distrusted (CIDR-only, and edges have no stable CIDR). Made loud: edge errors if `EDGE_UPSTREAM_CLIENT_CERT` set with TLS off; `parapet_trust_source{none}` alerts. |
| Per-edge revocation (SAN-drop) | **Fast path.** SAN re-checked per request against the live atomic allow-set → distrusts within ~300 ms even on existing keep-alive/HTTP-2 connections. The routine revocation lever. |
| CA-drop revocation latency | `VerifiedChains`/`ClientCAs` are consulted only at **handshake**. Dropping a CA takes effect on **new** handshakes only; existing connections keep their verified chain until they close. True bound = max connection lifetime, not 300 ms. Mitigate: prefer SAN-drop for routine revoke; cap `:443` connection age; reserve CA-drop for CA-key compromise. |
| Split-brain: token revoked but trust lingers | Closed by single-sourcing the SAN allow-set from `edge-controlplane-tokens` — deleting a token removes its SAN. In *separation* mode (standalone `allowed-sans`), revoking only the CP token leaves the edge trusted until its cert expires (documented). |
| Edge CA private key leaked | Attacker mints trusted edges until CA rotation. Highest severity. Mitigated by in-cluster-only key, single-purpose CA, and the overlap rotation runbook with a metric interlock (confirm every expected SAN is trusted under the new CA before dropping the old). |
| `GetConfigForClient` returns nil / omits `ClientAuth`/`GetCertificate` | Guarded: base config built non-nil before `Serve()`; callback returns last-good on error, never nil; startup self-test asserts `GetCertificate` + `ClientCAs` + `ClientAuth==VerifyClientCertIfGiven`. Prevents a self-inflicted cert-serving break or silent mTLS disable. |
| Forged-cert flood on `:443` | Each forged cert is rejected at the TLS handshake before reaching a handler; the per-request trust check is a cheap slice-len + map lookup behind an already-verified chain — no per-request crypto amplification. `NetworkPolicy` bounds who can attempt handshakes at all. |

## Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `TRUST_PROXY` | core | `cloudflare` (per `deploy/deployment.yaml`) | **Unchanged.** Static CIDR list / `cloudflare`/`true`/`false`. Becomes the `cidrTrust` OR-branch; coexists with mTLS trust. **Never add edge egress CIDRs here.** |
| `EDGE_TRUST_SECRET` | core | `""` (feature **off**, fully backward-compatible) | Name of the Secret in `POD_NAMESPACE` carrying `ca.crt` (edge CA PEM bundle). `edge-controlplane-tokens` for single-source mode, or a dedicated `parapet-edge-trust` for separation mode. Unset ⇒ no trust watch, mTLS disabled, identical to today. |
| `EDGE_TRUST_REQUIRE_SAN` | core | `true` | When true, trust requires the verified leaf's URI SAN to be in the live allow-set — enables per-edge revocation. When false, any cert chaining to the dedicated edge CA is trusted (CA-only mode, zero per-edge core edits, but single-edge revocation needs a CA rotation). |
| `EDGE_UPSTREAM_TLS` | edge | `false` | **Unchanged.** Must be `true` for mTLS trust (a client cert needs TLS); selects `edge/forward.go`'s re-encrypt path. mTLS trust is opt-in per edge. |
| `EDGE_UPSTREAM_CLIENT_CERT` / `EDGE_UPSTREAM_CLIENT_KEY` | edge | `""` / `""` | PEM paths to the edge's client cert+key, loaded **live** via `GetClientCertificate` (disk reload on renewal, no restart). Both unset ⇒ anonymous re-encrypt (back-compat). Set with `EDGE_UPSTREAM_TLS=false` ⇒ loud startup error. |
| `EDGE_UPSTREAM_SNI` | edge | `""` | **Unchanged.** SNI/`ServerName` presented to the core on re-encrypt. |

New metrics: `parapet_trust_source{mtls|cidr|none}` (per request, so an operator can
confirm an edge is trusted via `mtls` and catch a silent CIDR/none fallback) and
`parapet_trust_reload_rejected_total`.

## Onboarding flow (the payoff)

1. **One-time:** create the dedicated edge CA; put its PEM in the trust Secret
   (`ca.crt`) in `POD_NAMESPACE`. Roll the core **once** to pick up the new code.
   *This is the only restart, ever — never again per-edge.*
2. **Per edge — mint identity:** a cert-manager `Certificate` (issuer
   `parapet-edge-ca`, `usages: [client auth]`, URI SAN
   `spiffe://parapet.moonrhythm.io/edge/<name>`) → a `kubernetes.io/tls` Secret in
   the edge's namespace.
3. **Per edge — register once:** add the edge's entry to
   `edge-controlplane-tokens` (token → domains, plus its SPIFFE SAN). This single
   edit makes the control plane authorize the edge **and** adds the SAN to the
   core's allow-set — both planes converge, ~300 ms, no restart.
4. **Configure the edge Deployment:** `EDGE_UPSTREAM_TLS=true`, `EDGE_UPSTREAM_ADDR`
   → core `:443`, `EDGE_UPSTREAM_CLIENT_CERT`/`KEY` mounted from the cert Secret.
5. **Deploy.** The edge re-encrypts to `:443` with its client cert; the core
   verifies the chain + SAN and **immediately honors its `X-Forwarded-*`** — no
   `TRUST_PROXY` edit, no core restart. Confirm via `parapet_trust_source{mtls}`.
6. **Revoke (fast):** drop the edge's entry (and SAN) from the registry → distrusted
   within ~300 ms, even on live connections. For a leaked **CA** key, use the
   overlap rotation runbook.

## Phasing

1. **Phase 1 — ship fast, reuse existing machinery.** cert-manager dedicated edge
   CA + per-edge `Certificate`s mounted as Secrets. Core: the per-request closure,
   `GetConfigForClient` hot-swapping `ClientCAs` over a **separate** atomic from the
   SNI cert table, the `EDGE_TRUST_SECRET` watch (validate-then-swap, keep-last-good),
   `EDGE_TRUST_REQUIRE_SAN=true` with SANs single-sourced from
   `edge-controlplane-tokens`, the unconditional `X-Forwarded-Country/-ASN` strip,
   and the new metrics. Edge: `EDGE_UPSTREAM_CLIENT_CERT/KEY` via live
   `GetClientCertificate` + startup guards. `NetworkPolicy` locking core `:80`/`:443`
   to edge/Cloudflare sources. **No parapet-framework changes, no control-plane
   changes.**
2. **Phase 2 — stronger, optional drop-in** (mirrors EDGE.md's bearer→mTLS framing):
   the control plane **mints** the edge client cert and serves it over the existing
   bearer channel (`GET /v1/edge-cert`, signed by the in-cluster edge CA, authorized
   by the same token) so onboarding becomes "the CP issues the edge its identity"
   with one fewer operator-managed Secret. Optionally make the hop **mutually**
   authenticated (edge pins the core CA, drop `InsecureSkipVerify`). Optionally add
   CRL/OCSP via `tls.Config.VerifyConnection` if revocation must beat
   cert-lifetime + SAN-drop. Optionally migrate the SPIFFE-style SANs to real SPIRE
   SVIDs (naming already aligns).
3. **Phase 3 — optional companion.** A `TRUST_PROXY_DYNAMIC=true` ConfigMap-of-CIDRs
   OR-branch for callers that genuinely cannot present a client cert (a known
   in-cluster plaintext `:80` caller), covering the `EDGE_UPSTREAM_TLS=false` gap
   with an operator-asserted CIDR — same atomic + validate-then-swap discipline,
   never panic on the watch path.

## Alternatives considered

- **Token-gated `TrustProxy` (HMAC-over-timestamp header, single-sourced from the
  token registry).** The judge panel's narrow co-leader, and the strongest on
  operational single-source-of-truth — which is why we **grafted** that strength
  (the SAN allow-set comes from the same `edge-controlplane-tokens` Secret).
  Rejected as the *primary* mechanism on security: the credential is a request
  **header** whose placement the attacker controls (vs a TLS-layer property they
  cannot synthesize); on a sniffable private path a captured token is replayable for
  the skew window; the **strip-before-upstream** middleware is order-fragile and
  load-bearing; HMAC verification is an O(N) CPU-amplification vector under a forged
  header flood; and it adds a **clock-skew** failure mode. mTLS has none of these.
  *If the operator prefers the lower-PKI-overhead path, this is the fallback —
  reopen the decision here.*
- **Dynamic IP trust list (ConfigMap of CIDRs, hot-reloaded).** Lowest effort; we
  graft its **operator-asserted-trust** principle, its rejection of token-writable
  self-registration, its never-panic/keep-last-good discipline, and its
  trust-source observability. Rejected as primary: it does **not raise the security
  bar** — anything sharing a trusted CIDR can spoof XFF, and for NAT'd/dynamic edges
  the natural pattern (trust the whole egress CIDR) *widens* the spoof surface. Kept
  as the optional Phase 3 companion for the `:80` gap.
- **SPIFFE/SPIRE workload identity (mTLS SVID).** Strongest in theory, operationally
  disqualifying now: an out-of-cluster edge can't use in-cluster `k8s_psat`
  attestation, so it needs SPIRE federation / nested SPIRE — a hard runtime
  dependency, a concentrated CA-compromise target, and a *second* continuously
  rotating CA bundle whose staleness breaks the data plane. Onboarding would touch
  three systems. We graft only its **URI-SAN naming** (free, future-proof) and leave
  a Phase 2 migration path.
- **CA-only mTLS (no SAN check, `EDGE_TRUST_REQUIRE_SAN=false`).** The "gold
  standard" for zero core-side edits — issuing the cert is the whole onboarding.
  **Kept as a supported mode** but not the default: it makes single-edge revocation
  impossible without a whole-CA rotation. Defaulting `require-SAN=true` restores
  ~300 ms per-edge revocation for a one-line registry edit, which single-sourcing
  makes free.

## Open questions

- **Registry shape:** single-source mode couples the data-plane trust schema to the
  CP token-registry JSON (it must carry a per-token SPIFFE SAN). Store the SAN
  explicitly, or derive it deterministically from the token/edge name?
- **Phase 2 issuance:** CP-minted client certs (collapses onboarding, keeps the key
  off persistent storage, but expands the CP's role and couples the two channels)
  vs cert-manager-mounted Secrets — worth the coupling?
- **Plaintext `:80` for edges:** forbid edge traffic on `:80` entirely (route edges
  only to `:443`, eliminating the silent `EDGE_UPSTREAM_TLS=false` → untrusted
  downgrade), or keep `:80` purely for known CIDR-trusted in-cluster callers via the
  Phase 3 companion?
- **Mutual auth of the hop:** should the edge verify the core's server cert (pin the
  core CA, drop `InsecureSkipVerify` in `forward.go`)? Today only edge→core is
  authenticated.
- **Revocation target:** is SAN-drop (~300 ms) + short cert lifetimes enough, or does
  the deployment need CRL/OCSP via `VerifyConnection`?
- **Connection-age cap on `:443`:** what max lifetime balances draining stale-CA
  connections (for CA-drop revocation) against handshake churn? The default
  `IdleTimeout` 320 s lets a busy connection outlive a CA drop indefinitely without
  an explicit cap.
- **Multi-CA `ca.crt` parsing:** confirm `AppendCertsFromPEM` over a concatenated
  bundle adds every valid block and that one malformed block doesn't silently drop
  the good CAs — validate-then-swap must treat a partially-bad bundle as a **rejected**
  reload, not a partial install.

## Conformance / contract

On acceptance, fold into [`SPEC.md`](SPEC.md): the trust predicate
(`cidrTrust OR (verified-edge-CA-chain AND SAN ∈ allow-set)`), the new env vars
(`EDGE_TRUST_SECRET`, `EDGE_TRUST_REQUIRE_SAN`, `EDGE_UPSTREAM_CLIENT_CERT/KEY`),
the `X-Forwarded-Country/-ASN` ingress strip, and the per-request order (trust
evaluation precedes WAF/rate-limit, as today). The Rust implementation in
[`rust/`](rust/) tracks the same contract or records a divergence.

[TLS SNI fallback memory]: the proxy serves a self-signed fallback on an SNI miss
when the live cert table loses `GetCertificate`; the `GetConfigForClient` self-test
above exists to prevent re-introducing that class of bug during a trust reload.
