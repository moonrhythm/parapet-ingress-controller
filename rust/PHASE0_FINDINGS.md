# Phase 0 — Pingora de-risk spikes

Goal: prove Pingora can do the features that don't map obviously from the Go/parapet
implementation, **before** committing to the full rewrite. Each item ends in either
"proven in this environment" or "documented fallback".

## VERDICT: ✅ GO on Pingora.

Every risky capability was proven **end-to-end in this environment** by a single throwaway
proxy (`spike/`), verified by `spike/verify.sh` — **13/13 checks pass**. No blockers; one
architectural lesson (two services, not one — see §0).

Status legend: ✅ proven e2e · 🟡 confirmed from source · ⛔ blocked

| # | Spike | Status |
|---|---|---|
| go/no-go | h2c **upstream** (TLS-terminate in front of cleartext-h2 pods) | ✅ |
| 2 | build pingora+openssl in this env | ✅ |
| 3 | h2c upstream end-to-end | ✅ |
| 4 | dynamic SNI cert from hot-swappable store (exact/wildcard/fallback) | ✅ |
| 5 | hot route reload via ArcSwap (under a swap loop) | ✅ |
| 6 | retry + bad-addr via fail_to_connect (dead pod → live pod) | ✅ |
| 7 | h2c frontend (prior-knowledge) + websocket Upgrade passthrough | ✅ |
| 8 | per-host ConcurrentQueue rate-limit parity | ✅ design (§8) |

Pinned versions: **pingora 0.8.0** (latest on crates.io), rustc 1.95.0, TLS backend = **openssl**
feature (BoringSSL/OpenSSL share the same `TlsAccept`/`ext::ssl_use_*` API, so swapping to
boringssl for the production Linux image is a feature-flag change, not a code change).

To reproduce: `cd rust && cargo run -p spike` then `bash spike/verify.sh` (needs `curl`,
`openssl`, `python3`).

---

## 0. Architectural lesson: model the two listeners as TWO services

The Go code runs two `parapet.Server`s (`:80` plaintext+H2C, `:443` TLS). The faithful Pingora
mapping is **two `http_proxy_service`s sharing one proxy impl** (cheap — the app holds `Arc`s).

This isn't just cosmetic. `server_options.h2c` is **per-app**, and a TLS stream **cannot peek**
for the H2 preface (`apps/mod.rs::process_new`: `try_peek` returns "not peeked", so `h2c` stays
`true` and Pingora forces HTTP/2 onto the TLS connection). Symptom when h2c+TLS share one
service: TLS clients that don't negotiate ALPN get raw H2 frames and curl reports
*"Received HTTP/0.9 when not allowed"*. Fix, confirmed here:

- **plaintext service** → `server_options.h2c = true`, `add_tcp(...)`
- **TLS service** → `server_options` unset; `TlsSettings::with_callbacks(resolver)` + `enable_h2()`
  (advertises h2+http/1.1 via ALPN), `add_tls_with_settings(...)`

After the split, all TLS/h2c/h1 cases pass.

---

## 1. h2c upstream — the go/no-go (confirmed from 0.8.0 source)

`pingora-core-0.8.0/src/connectors/http/v2.rs` selects cleartext HTTP/2 to an upstream when the
peer is plaintext, advertises no ALPN, and its `alpn` option's min HTTP version is 2:

```text
// else: min http version=H2 over plaintext, there is no ALPN anyways, we trust
// the caller that the server speaks h2c
```

So the recipe is: `HttpPeer::new(addr, /*tls*/ false, String::new())` then set
`peer.options.alpn = ALPN::H2` (`ALPN::get_min_http_version()` returns 2 only for `H2`).
`ALPN::{H1, H2, H2H1}` live in `pingora-core/src/protocols/tls/mod.rs`.

Mapping for our `upstream-protocol` annotation / Service `appProtocol`:
- `http`  → `HttpPeer::new(addr, false, "")`, `alpn = H1`
- `https` → `HttpPeer::new(addr, true, sni)`, `alpn = H2H1`, verify_cert/verify_hostname off (InsecureSkipVerify parity)
- `h2c`   → `HttpPeer::new(addr, false, "")`, `alpn = H2`

## 2. h2c frontend (confirmed from source)

`pingora-core-0.8.0/src/apps/mod.rs` has `HttpServerOptions { h2c: bool, .. }` with H2-preface
sniffing. Enable per proxy service via the app's `server_options`:
`http_proxy_service(...)` → set `service.app_logic_mut().unwrap().server_options = Some(HttpServerOptions { h2c: true, .. })`.

## 3. dynamic SNI (confirmed from source — in-tree example)

`TlsAccept::certificate_callback(&self, ssl: &mut TlsRef)` (in `pingora-core/src/listeners/mod.rs`,
`TlsRef = openssl SslRef`). In-tree example (`protocols/tls/boringssl_openssl/server.rs`):

```rust
let sni = ssl.servername(pingora::tls::ssl::NameType::HOST_NAME); // Option<&str>
let cert = pingora::tls::x509::X509::from_pem(&cert_pem)?;
let key  = pingora::tls::pkey::PKey::private_key_from_pem(&key_pem)?;
pingora::tls::ext::ssl_use_certificate(ssl, &cert)?;
pingora::tls::ext::ssl_use_private_key(ssl, &key)?;
```

Attach via `TlsSettings::with_callbacks(Box<dyn TlsAccept>)` →
`service.add_tls_with_settings(addr, None, settings)`. The store behind the resolver is an
`ArcSwap<CertStore>`, so reloads are lock-free. Exact→wildcard→fallback lookup mirrors
`cert/table.go`.

## 6. retry / bad-addr (confirmed from source)

`pingora-error-0.8.0/src/lib.rs`: `Error::set_retry(&mut self, bool)`, `Error::retry() -> bool`,
`RetryType::decide_reuse(reused)`. `ProxyHttp::fail_to_connect(session, peer, ctx, e) -> Box<Error>`
is the hook: mark the dialed addr bad (so RRLB skips it), bump an attempt counter in CTX, and
`e.set_retry(true)` while attempts < 5 and the request body hasn't been read. Pingora then re-invokes
`upstream_peer`, which picks the next live IP. Caps + backoff are ours to enforce in `fail_to_connect`.

---

## 8. per-host ConcurrentQueue rate-limit parity (design — impl deferred to Phase 2)

parapet has two per-host concurrency strategies (main.go `hostRateLimit` / `hostCountryRateLimit`):

- **ConcurrentStrategy{Capacity}** — cap N in-flight per key, reject (503) above N. No queue.
- **ConcurrentQueueStrategy{Capacity, Size}** — cap N in-flight; up to `Size` extra requests *wait*;
  reject (503) only when the queue is also full. `ReleaseOnWriteHeader` + `ReleaseOnHijacked`:
  the slot frees when the response header is written (so slow body streaming / websockets don't
  pin a slot).

Rust mapping:
- **No queue** → `pingora_limits::inflight::Inflight` per key. `let (guard, n) = inflight.incr(key, 1);`
  if `n > capacity` → drop guard, return 503; else stash `guard` in CTX, drop it in `response_filter`
  (= header written) for `ReleaseOnWriteHeader` parity.
- **With queue** → per-key `tokio::sync::Semaphore` (capacity permits) in a sharded map keyed by host
  (or host|country). Keep an atomic in-flight+waiting counter per key; if it would exceed
  `capacity + size` → 503 immediately; otherwise `acquire_owned().await`, stash the
  `OwnedSemaphorePermit` in CTX, release in `response_filter`. Websocket/Upgrade also surfaces a
  response header → released the same way (`ReleaseOnHijacked` parity).
- Key = `r.Host` (and `Host|Country` from the configured header, default `XX`), lowercased.
- On rejection, increment `parapet_host_ratelimit_requests{host}`.

No spike required — both primitives exist; this is a Phase-2 implementation note.

Per-ingress window limits (`ratelimit-s/m/h`) map to `pingora_limits::rate::Rate` (sliding window).

---

## 7b. websocket / Upgrade passthrough

Proven e2e: a raw client sends an HTTP/1.1 `Upgrade: websocket` request through the proxy to a
101-then-echo upstream; the proxy relays `101 Switching Protocols` and pipes bytes bidirectionally
(client sends `PINGPING`, gets `PINGPING` back). No special config — Pingora detects the upgrade
and switches to byte-piping. `serve_connection(...).with_upgrades()` is needed on the *test
upstream* (hyper), not on Pingora.

## Build / env notes

- `cmake` and `pkg-config` were missing. Installed via Homebrew: `pkg-config`, `openssl@3`
  (for the `openssl` TLS backend), and `cmake` (required by `libz-ng-sys`, pulled in transitively
  for compression). OpenSSL itself compiled fine; the first build failure was `libz-ng-sys` → cmake.
- `rust/.cargo/config.toml` sets `OPENSSL_DIR=/opt/homebrew/opt/openssl@3` so `openssl-sys`
  finds Homebrew's keg-only openssl. Machine-specific; only for this throwaway spike. The
  production Linux image will get these from the base image / `boringssl` vendoring instead.

## Carry into Phase 1/2 (from spike experience)

- Two proxy services sharing one `Arc`-backed app (see §0).
- Routing state: `Arc<ArcSwap<RouteTable>>`; cert state: `Arc<ArcSwap<CertStore>>`. Both swap
  lock-free; reload = build new + `store()`.
- `upstream_peer` does the RRLB pick (so a retry re-picks); `fail_to_connect` marks the addr bad
  + `set_retry` under a CTX attempt cap. Per-request state lives in the typed `CTX` (replaces the
  Go `state.State` string map).
- Per-upstream protocol via `HttpPeer` + `PeerOptions.alpn` (H1 / H2 / H2H1) and `verify_cert`/
  `verify_hostname=false` for the `https` InsecureSkipVerify parity.
- Open perf question for Phase 5: per-addr backend connection/byte metrics under Pingora's pooled
  upstream connections (Go wraps the dialed conn directly; Pingora manages the pool).
