# WebSocket over HTTP/2 on the internal hops (RFC 8441 extended CONNECT)

Status: **all three phases implemented** (core acceptance, edge tunnel —
default on, `EDGE_UPSTREAM_WS_H2` opt-out — and core→pod extended CONNECT —
default on, `UPSTREAM_WS_H2C` kill switch), **plus edge public acceptance**:
the edge's own `:443` listener accepts WS-over-h2 from clients (browsers) and
relays it stream-to-stream. SPEC.md / EDGE.md carry the contract rows.

## Problem

Every WebSocket client today costs one dedicated TCP connection on the
edge→core hop. `edge/forward.go` deliberately routes Upgrade requests onto an
HTTP/1.1 transport (`h2TLSTransport.RoundTrip` on the re-encrypt path,
`upstream.H2CTransport`'s own downgrade on the plaintext path) because
`httputil.ReverseProxy` has no HTTP/2 upgrade path and an h2 connection rejects
the `Connection`/`Upgrade` request headers.

That per-socket connection is the scaling wall: one edge IP talking to one core
VIP:443 exhausts the ephemeral source-port space at roughly 28k–64k concurrent
tuples — long before file descriptors or memory matter. `EDGE_UPSTREAM_MAX_CONNS_PER_HOST`
bounds the damage but doesn't lift the ceiling; regular request/response
traffic already multiplexes over a handful of h2/h2c connections and is
unaffected.

RFC 8441 ("Bootstrapping WebSockets with HTTP/2") is the standard fix: a
WebSocket session rides a single h2 **stream** via the extended CONNECT method
(`:method: CONNECT` + `:protocol: websocket`), so tens of thousands of sockets
multiplex over a few TCP connections. This document specifies extended CONNECT
on the **internal hops only** — client→edge and (by default) core→pod stay
plain HTTP/1.1 WebSocket.

```
client ──(h1 WS, or h2 extended CONNECT)──▶ edge ──(h2/h2c extended CONNECT)──▶ core ──(h1 WS)──▶ pod
                                                                                  └─(phase 3: h2c extended CONNECT when the pod advertises it)
```

Every hop degrades to HTTP/1.1 independently, so any mix of old/new
components keeps working.

## Protocol background (verified against Go 1.26.5 / x/net v0.56.0)

Facts the design leans on, checked in the shipped toolchain and module — not
from documentation:

- **Support is advertised in-band.** A server that accepts extended CONNECT
  sends `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` in its first SETTINGS frame
  (RFC 8441 §3). There is no probing heuristic; capability detection is exact.
- **Go's server side is gated, client side is not.** In `x/net/http2` (and the
  identical `net/http` h2 bundle), `disableExtendedConnectProtocol` guards only
  the server paths (advertising the setting; rejecting `:protocol`). The gate
  default is off because browsers immediately use WS-over-h2 against any server
  that advertises it, breaking apps whose websocket libraries only speak the h1
  handshake (golang/go#71128). The **client** transport is ungated: it sends
  extended CONNECT whenever the request is `CONNECT` + `Header[":protocol"]`
  and the peer advertised support.
- **A failed attempt is free.** `clientStream.writeRequest` blocks until the
  peer's first SETTINGS frame and returns `errExtendedConnectNotSupported`
  **before writing any request bytes**. Nothing goes on the wire, so falling
  back to HTTP/1.1 is always safe — there is no replay hazard (contrast with
  auto-h2c's "only bodyless requests probe" rule; a WS handshake is a bodyless
  GET anyway). The error is unexported; callers match its message
  (`"net/http: extended connect not supported by peer"`). A missed match
  degrades gracefully to "always fall back".
- **The gate is the real `GODEBUG` env var, not `//go:debug`.** Both the bundle
  and `x/net/http2` read `os.Getenv("GODEBUG")` directly in package `init()`.
  The `//go:debug` directive only affects `internal/godebug` consumers, so it
  does **not** enable this. The core must run with the environment variable
  `GODEBUG=http2xconnect=1` set at process start.
- **Handshake mapping (RFC 8441 §4–5):** the h2 handshake carries `:authority`,
  `:path`, `:scheme` and the regular `Sec-WebSocket-Version` /
  `Sec-WebSocket-Protocol` / `Sec-WebSocket-Extensions` headers, but **omits
  `Sec-WebSocket-Key` / `Sec-WebSocket-Accept`** (stream setup replaces the
  key/accept proof). Acceptance is a 2xx response on the stream; the stream
  body is then the raw WebSocket framing, full duplex.

## Design overview

Three phases, independently shippable, each with an unconditional HTTP/1.1
fallback so version skew is order-free:

1. **Core accepts extended CONNECT** (server side): advertise the setting,
   normalize the request so the existing chain is oblivious, tunnel to the pod
   over the h1 upgrade it already speaks.
2. **Edge tunnels WS over the upstream hop** (client side, opt-in
   `EDGE_UPSTREAM_WS_H2`): translate the client's h1 upgrade into extended
   CONNECT on a dedicated multiplexed transport; fall back to the current h1
   path when the core doesn't advertise.
3. **Core→pod extended CONNECT** (`UPSTREAM_WS_H2C`, default true): when a
   pod's h2c connection advertises the setting, tunnel over h2c instead of
   dialing an h1 upgrade.

Phase 1 ships first; phase 2 is the payoff (the edge falls back cleanly against
an old core, so rollout order doesn't matter). Phase 3 is a nicety — the
core→pod hop dials many distinct pod IPs, each with its own source-port space,
so it has no exhaustion problem; see its section below.

## Core: accepting extended CONNECT

### Enabling

- The controller image sets `ENV GODEBUG=http2xconnect=1` in `Dockerfile`.
- **Footgun:** `GODEBUG` is a comma-list and a user-supplied `GODEBUG` in a pod
  spec **replaces** the Dockerfile value entirely, silently disabling the
  feature. `main.go` therefore verifies at startup that
  `os.Getenv("GODEBUG")` contains `http2xconnect=1` and logs a prominent
  warning when it doesn't (not fatal — the core is still correct, it just
  can't accept WS-over-h2, and edges fall back to h1).
- Both core listeners get it for free: `:443` (ALPN h2) and `:80` (`H2C: true`)
  share the same bundled/x-net server code. There is no per-server opt-out in
  Go today; when the env var is set, **every** h2 client of the core may send
  extended CONNECT — which is exactly why normalization (below) must sit in
  front of everything, not inside the proxy.

### Normalization middleware (first in the `m` chain)

A new middleware, mounted in `cmd/parapet-ingress-controller/main.go` **before
host normalization** (i.e. before everything in SPEC.md's per-request order),
rewrites an extended CONNECT into the h1-upgrade shape the rest of the chain
already understands:

- Match: `r.Method == "CONNECT"` and `r.Header.Get(":protocol") != ""` (Go's
  h2 server surfaces the pseudo-header there; an h1 client cannot produce it —
  colon-prefixed field names are invalid HTTP/1.1 tokens and net/http rejects
  them, so the match is inherently h2-only and not client-spoofable over h1).
- `:protocol` values other than `websocket` → **501 Not Implemented**. We
  bridge WebSocket only.
- Rewrite in place: `Method = "GET"`, set `Connection: Upgrade` and
  `Upgrade: websocket`, delete `:protocol` and `Accept-Encoding` (the spliced
  200 must never be compress-wrapped), **detach the live stream** — park
  `r.Body` in an immutable context value and set `r.Body = http.NoBody` — so
  WAF/Coraza body inspection sees the same empty body an h1 handshake has
  (both do a blocking body read otherwise), and `retry.go` keeps treating the
  handshake as retryable-before-send. (A context value, not the per-request
  `state` map: normalization runs before `state.Middleware`, and the pooled
  map must not hold a live stream.) `Sec-WebSocket-Version/Protocol/
  Extensions` ride through untouched.
- Everything downstream — host normalization, logging, metrics, **global/zone
  CEL WAF** (`request.method` rules see `GET`, matching what an h1 WS handshake
  already looks like), Coraza, rate limits, routing, plugins — behaves
  identically for an h1 and an h2 WebSocket handshake. No rule breakage, no
  SPEC.md order change; SPEC.md gains one sentence stating the equivalence.

### Tunnel response path (in `proxy/`)

The proxy cannot use `httputil.ReverseProxy`'s upgrade path for a normalized
request: that path hijacks the downstream connection, and an h2 stream's
`ResponseWriter` has no `Hijacker`. Instead, for requests flagged `wsTunnel`:

1. Resolve and dial the pod exactly like today: `route.Table.Lookup`, the
   shared dialer, bad-addr marking. A **dial error before the handshake** is
   retryable exactly like today's dial errors (bodyless GET, nothing sent) and
   follows the existing retry/bad-addr semantics.
2. Send the h1 upgrade handshake to the pod. The pod requires a
   `Sec-WebSocket-Key` (the h2 side has none): the core **generates a random
   key**, validates the pod's `Sec-WebSocket-Accept` against it (cheap
   correctness check; mismatch → 502), and **strips `Sec-WebSocket-Accept`**
   from the response — it is meaningless on the h2 side and the edge
   synthesizes its own toward the client.
3. Pod answers `101` → respond **200** on the h2 stream (copying
   `Sec-WebSocket-Protocol`/`Extensions` back), flush, then splice bytes both
   ways between the pod connection and the stream (`r.Body` for reads, the
   `ResponseWriter` for writes — h2 handlers are natively full duplex; reuse
   `proxy/buffer.go`'s pool).
4. Pod answers anything else (401 from the app, 404, …) → forward status,
   headers, and body as a normal response on the stream. The edge translates a
   non-200 back into a non-101 for the client.

`:protocol` never reaches the pod (deleted at normalization) and never appears
in an upstream header.

## Edge: tunneling client WS over the upstream hop

### Config

`EDGE_UPSTREAM_WS_H2` (bool, **default true** — opt-out; safe at any version
skew because the attempt against a non-advertising core fails pre-flight with
zero wire cost and falls back per request). Only meaningful when the upstream
hop is multiplexed (`EDGE_UPSTREAM_HTTP2=true`, the default); with h2 disabled
the flag is a no-op and WS rides h1 as today.

### Behavior (`edge/forward.go` + new tunnel code)

On a client request with `Upgrade: websocket` (other `Upgrade` values keep the
h1 path unconditionally):

1. Complete the client-side h1 handshake ourselves: validate
   `Sec-WebSocket-Key` presence, then **translate** — `Method = "CONNECT"`,
   `Header[":protocol"] = "websocket"`, drop `Connection`, `Upgrade`, and
   `Sec-WebSocket-Key`, keep `Sec-WebSocket-Version/Protocol/Extensions`,
   preserve `:authority`/path (the core routes on Host + path as usual).
   Stripping `Connection`/`Upgrade` also means the existing transports'
   downgrade checks (`h2TLSTransport.RoundTrip`, `H2CTransport`) never trigger.
2. RoundTrip on the **dedicated tunnel transport** (below) with a pipe as the
   request body (client→core frames) and read core→client frames from the
   response body.
3. Core answers **200** → write the `101 Switching Protocols` handshake to the
   client (computing `Sec-WebSocket-Accept` from the client's original key,
   echoing negotiated subprotocol/extensions), hijack the client connection,
   splice.
4. Core answers non-200 → translate to a plain h1 response (the handshake was
   refused by WAF/auth/the app; status and body pass through).
5. RoundTrip fails with the **not-supported error** (old core, or `GODEBUG`
   lost from the core's environment) → **fall back to the existing h1 upgrade
   path** for this request. Log once (rate-limited), count it (metrics below).
   No negative cache is required for correctness — the check is pre-flight and
   free on a live connection — but the implementation may remember the verdict
   briefly to avoid re-attempt latency when no tunnel connection exists yet.

### Dedicated tunnel transports (not the RPC transports)

WS tunnels get their **own** transports, separate from the request/response
transports in `NewForwarder`, for three reasons:

- **Stream-slot starvation.** Long-lived tunnel streams would otherwise pin the
  stream budget (`SETTINGS_MAX_CONCURRENT_STREAMS`) of the connections regular
  traffic multiplexes on.
- **Deterministic protocol.** On the re-encrypt hop the RPC transport is
  `ForceAttemptHTTP2` `http.Transport`, which may ALPN-negotiate HTTP/1.1 — an
  extended CONNECT serialized onto an h1 connection is garbage. The tunnel
  transport is an `x/net http2.Transport` offering **ALPN `h2` only**
  (handshake fails cleanly against an h1-only peer → h1 fallback), sharing the
  same `tls.Config` (SNI, data-plane mTLS client cert) as the RPC transport.
  On the plaintext hop it is a prior-knowledge h2c `http2.Transport`, matching
  what `upstream.H2CTransport` wraps.
- **Liveness.** A NAT/middlebox silently dropping one TCP connection kills
  every stream on it with no FIN. The tunnel transports set `ReadIdleTimeout`
  (h2 PING keepalive, ~30s) + `PingTimeout` so a dead connection is detected
  and its sessions closed promptly instead of hanging.

`EDGE_UPSTREAM_MAX_CONNS_PER_HOST` keeps bounding only the h1 fallback path,
unchanged; the multiplexed tunnel path needs few connections by construction
(the transport opens additional connections as stream limits fill —
`StrictMaxConcurrentStreams` stays false).

### Version-skew matrix

| Edge | Core | Result |
|---|---|---|
| old | any | h1 per-socket connections (today's behavior) |
| new, flag off | any | today's behavior |
| new, flag on | old / `GODEBUG` missing | pre-flight local error → h1 fallback; zero wire cost |
| new, flag on | new + `GODEBUG` set | WS multiplexed over h2/h2c streams |

Rollout is order-free; core first is natural (edges fall back until upgraded).

## Phase 3: core→pod extended CONNECT (implemented; `UPSTREAM_WS_H2C` default true)

When the pod itself speaks WS-over-h2c, the core skips the h1 dial and tunnels
stream-to-stream (`proxy/wsh2c.go`, attempted by `serveWSTunnel` before the h1
path). Detection is exact and layered on what already exists:

1. **Is the Service h2c at all?** Explicit `appProtocol: h2c` (scheme `h2c`)
   is always eligible; plain `http` is eligible only with a **fresh positive**
   `UPSTREAM_AUTO_H2C` verdict (read-only accessor — WS requests still never
   establish or refresh that verdict, preserving the auto-h2c contract);
   `https` never (h1-over-TLS as before).
2. **Does the h2c peer advertise `ENABLE_CONNECT_PROTOCOL`?** Attempt the
   extended CONNECT on a **dedicated** prior-knowledge h2c transport (dialing
   through the shared dialer so bad-addr marking works; PING keepalive; never
   the RPC h2c transport, whose stream budget long-lived tunnels must not
   pin). The not-supported error is pre-flight — nothing written, the parked
   client stream untouched — so the request falls back to the h1 upgrade dial
   and the negative verdict is cached per-Service (`upstreamKey`, or the pod
   `host:port` when auto-h2c is off; 10m TTL, expired entries pruned on read;
   only negatives are cached).

Failure semantics mirror phase 1: a **dial** failure cannot have consumed the
request body, so it panics into `retryMiddleware` exactly like the h1 path
(the dial error is captured at the `DialTLSContext` seam because x/net wraps
RoundTrip errors); any other post-dial failure is a 502 with **no fallback and
no retry** (the stream may be partially consumed — a replay could duplicate
frames). Attempt outcomes count in `parapet_ws_upstream_h2c{result}`
(`ok|not_supported|error`); the tunnel-vs-refusal distinction stays in
`parapet_ws_tunnels`.

Scope note: this path serves **tunneled** (h2-inbound / edge-tunneled)
WebSockets. A legacy h1-inbound WebSocket at the core still rides the
ReverseProxy hijack path to the pod over h1, unchanged — with the edge
tunneling by default, edge-fronted traffic gets the stream-to-stream path
end-to-end.

Expectation-setting: almost no upstream advertises this by default — a Go pod
needs the same `GODEBUG=http2xconnect=1`, Node needs
`http2.createServer({settings: {enableConnectProtocol: true}})`, and gRPC
servers don't do WebSocket. Negatives are free and cached; positives are
per-app opt-ins. The core→pod hop has no port-exhaustion problem (distinct pod
IPs each carry their own tuple space), so this phase is about per-pod
connection reduction and native-h2 apps.

## Failure semantics & blast radius

- **Before acceptance** (dial error, refused handshake): unchanged semantics —
  dial errors retry per `retry.go`, HTTP refusals pass through.
- **After acceptance**: a WebSocket session is stateful; no layer retries or
  resumes it. Mid-stream failure closes both sides, the client reconnects
  (standard WS client behavior).
- **Blast radius**: one edge→core TCP connection now carries up to
  `MAX_CONCURRENT_STREAMS` sessions (Go server default ~250); a connection
  reset kills all of them at once, where today it kills one. This is the
  accepted trade against port exhaustion (which kills *new* connections for
  everyone). The PING keepalive bounds how long a dead connection can hold
  sessions hostage. If finer control is needed, the core's
  `net/http.Server.HTTP2.MaxConcurrentStreams` is the sizing knob (a possible
  `HTTP_SERVER_MAX_CONCURRENT_STREAMS` env var — decide at implementation).

## Metrics

Following existing naming (`parapet_waf_matches`, `parapet_ratelimit_total`):

- Core (`metric/ws.go`):
  - `parapet_ws_tunnels{result}` counter — `result ∈ tunneled | refused |
    upstream_error | bad_protocol` (extended-CONNECT handshakes and their
    outcome).
  - `parapet_ws_tunnel_active` gauge — live spliced sessions.
- Edge (via `metric/observe` leaf, like the edge rate limiter):
  - `parapet_edge_ws_upstream{protocol, result}` counter — `protocol ∈ h2 |
    http1`, `result ∈ ok | fallback | error`; `fallback` counts not-supported
    downgrades (the "core lost its GODEBUG" alarm).

## Security considerations

- `:protocol` is deleted at normalization and cannot arrive over h1 (invalid
  h1 field name, rejected by net/http) — it never reaches WAF rules, the
  claim-header logic, or the upstream.
- WAF/Coraza/rate-limit posture is **identical** to an h1 WebSocket handshake
  today: request-phase inspection of the handshake, no frame inspection
  (already true — neither WAF sees post-upgrade bytes on the h1 path either).
  The `X-Parapet-Waf` claim flow is untouched (the edge stamps after its WAF
  ran; the handshake is a normal request to the WAF).
- Stream exhaustion replaces connection exhaustion as the DoS surface on the
  core listener; `MAX_CONCURRENT_STREAMS` (per conn) and existing host/country
  concurrency limits (which see the normalized handshake) bound it.
- The core advertising `ENABLE_CONNECT_PROTOCOL` publicly means any direct h2
  client may attempt WS-over-h2 — handled identically by the same
  normalization path, so this is a feature (direct clients gain WS-over-h2),
  not a hazard.

## Edge public acceptance: WS-over-h2 from clients

The edge's own `:443` (ALPN h2) accepts extended CONNECT from browsers
(`Dockerfile.edge` bakes `GODEBUG=http2xconnect=1`; startup warning when a
pod-spec `GODEBUG` clobbers it — h1 WebSocket is unaffected either way).
There is no partial rollout inside one process: once the image ships, browsers
WILL negotiate WS-over-h2, so the whole edge chain handles it unconditionally.

- **Normalization is shared with the core** (`wsh2.NormalizeHandler`, mounted
  first in the edge's `m` chain): the handshake is rewritten to the h1-upgrade
  shape with the stream detached, so edge WAF/Coraza/rate limits/cache treat
  h1 and h2 WebSocket handshakes identically, and client-supplied claim
  headers still hit `StripWAFClaim` as usual.
- **h2-inbound serving is tunnel-then-bridge, never ReverseProxy** (an h2
  response stream has no `Hijacker`): the h2 tunnel relays stream-to-stream
  (parked stream as the extended-CONNECT body, 200 answered on the client's
  own stream); the **h1-upgrade bridge** (`edge/wsbridge.go`, the reverse of
  the core's pod dial — generates the key, validates the core's accept, keeps
  the WAF claim) is constructed unconditionally so h2-inbound WebSocket works
  even with `EDGE_UPSTREAM_WS_H2` or `EDGE_UPSTREAM_HTTP2` off, or against a
  core that doesn't advertise extended CONNECT.
- **Fallback policy is strict**: only the provably pre-flight not-supported
  error falls back from tunnel to bridge (no body goroutine ever started —
  the parked stream is pristine). Any other tunnel failure may already have
  streamed client frames as DATA frames, so it is a 502 — a bridge replay
  would silently lose frames, and a stale x/net body reader could race the
  bridge for later ones. (The h1-inbound path can fall back more broadly
  because its request body is a pipe that holds nothing until the 101.)
- Accounting stays one-event-per-request on `parapet_edge_ws_upstream`:
  tunnel outcome `{h2,ok}`; not-supported→bridge `{http1,fallback}` (still
  the "core lost its GODEBUG" alarm); bridge-direct `{http1,ok}`; terminal
  failures `{…,error}`.

## Scope and non-goals
- **No QUIC / HTTP/3** — separate concern, separate document if ever.
- **No WS frame inspection** — the tunnel is byte-transparent after the
  handshake, exactly like today's h1 splice.
- **Edge response cache**: WebSocket is untouched by `parapet/pkg/cache`
  (upgrades were never cacheable); no interaction.

## Where the code will live

```
wsh2/                       # shared, pure, edge-importable (like corazawaf/):
                            #   IsExtendedConnect/Normalize/NormalizeHandler (+ stream
                            #   detach via ctx), Sec-WebSocket-Key/Accept synth+check,
                            #   splice loop
proxy/wstunnel.go           # core: tunnel path for ctx-flagged requests (phase 1)
cmd/parapet-ingress-controller/wsnormalize.go  # normalize middleware (mounted first in main.go's m chain)
cmd/parapet-ingress-controller/main.go   # middleware mount + GODEBUG startup check
Dockerfile                  # ENV GODEBUG=http2xconnect=1 (controller)
Dockerfile.edge             # ENV GODEBUG=http2xconnect=1 (edge public acceptance)
edge/wstunnel.go            # edge: translate + dedicated tunnel transports (phase 2)
                            #   + serveH2Inbound (h2-inbound stream-to-stream relay)
edge/wsbridge.go            # edge: h1-upgrade bridge to the core (unconditional
                            #   fallback for h2-inbound WebSocket)
metric/ws.go                # core counters/gauge
metric/observe/ws.go        # edge counter (leaf package — edge binaries stay off metric)
proxy/wsh2c.go              # phase 3: pod-side extended CONNECT (dedicated h2c transport,
                            #   eligibility + negative-verdict cache, dial-error retry seam)
```

## SPEC.md rows to add at implementation time

- Per-request order: one sentence — an h2 extended-CONNECT WebSocket handshake
  is normalized to the equivalent h1 upgrade before step 1 and follows the
  same order.
- Env table: `EDGE_UPSTREAM_WS_H2` (edge, default false), the core's
  `GODEBUG=http2xconnect=1` requirement, and (if added)
  `HTTP_SERVER_MAX_CONCURRENT_STREAMS`.
- Metrics table: `parapet_ws_tunnels`, `parapet_ws_tunnel_active`,
  `parapet_edge_ws_upstream`.

## Open questions

1. ~~When does `EDGE_UPSTREAM_WS_H2` default flip to true?~~ Resolved: default
   true from the start — the pre-flight fallback makes it safe at any skew.
2. Do we expose `HTTP_SERVER_MAX_CONCURRENT_STREAMS`, or defer until someone
   needs to tune session-per-connection blast radius (~250/conn at Go's
   default)?
3. ~~Phase 3: worth doing at all?~~ Built (default on, `UPSTREAM_WS_H2C` kill
   switch): detection is free-negative and cached, and edge-fronted traffic
   now rides stream-to-stream end-to-end when the pod opts in.
