# Go 1.27.0 upgrade — WS-over-h2 wrap blocker

Status: **blocked** as of 2026-08-28. Recheck before bumping `go.mod`,
`golang:*-trixie` Dockerfiles, or CI `go-test.yaml`.

Pinned today: `go 1.26.7`, `golang.org/x/net v0.58.0`,
`golang:1.26.7-trixie`. 1.26 stays supported until 1.28 (~Feb 2027).

## Recheck

Wrap is selected by the **compiler version**, not `go.mod`. Building this
module with a 1.27 toolchain is enough to hit it.

```bash
GOTOOLCHAIN=go1.27.0 go test ./proxy/ ./edge/ -count=1 -run 'WSTunnel|WSH2'
```

**Unblocked** only if that suite is green **without** `-tags http2legacy`.

Then also run the full `./proxy/` `./edge/` packages (auto-h2c / ForceAttemptHTTP2
already passed on 1.27.0; keep them in the recheck). If still red, the
control case is:

```bash
GOTOOLCHAIN=go1.27.0 go test -tags http2legacy ./proxy/ ./edge/ -count=1 -run 'WSTunnel|WSH2'
```

That was green on 1.27.0 / x/net v0.58.0 — it only proves the old x/net
client still works, not that we can ship 1.27.

## What broke (2026-08-28)

`Header.Set(":protocol", "websocket")` is how this repo builds RFC 8441
extended CONNECT (`proxy/wsh2c.go`, `edge/wstunnel.go`).

On Go ≥ 1.27, `golang.org/x/net/http2` **wraps** stdlib
(`net/http/internal/http2`) unless built with `-tags http2legacy`
([#78508](https://github.com/golang/go/issues/78508), part of moving HTTP/2
into std [#67810](https://github.com/golang/go/issues/67810)). Wrap
`http2.Transport.RoundTrip` calls `http.Transport.RoundTrip`, which runs
`validateHeaders` **without** a `:protocol` exception:

```
net/http: invalid header field name ":protocol"
```

The HTTP/2 encoder (`internal/httpcommon`) already allows `:protocol` and
emits it with the other pseudo-headers. The request never gets there.
`http.ClientConn.RoundTrip` uses the same `validateHeaders`, so
`NewClientConn` is not a way around it.

Observed on `GOTOOLCHAIN=local` (go1.27.0) with `go.mod` still `1.26.7`:

| Result | Tests |
|---|---|
| FAIL | `TestWSTunnelH2C_*`, `TestWSTunnelEndToEnd`, `TestWSTunnelRefused` (`proxy/`) |
| FAIL | `TestWSH2Inbound_*`, `TestWSTunnel_EndToEnd_H2C` (101→502), `TestWSTunnel_EndToEnd_Refused` (403→502) (`edge/`) |
| PASS | auto-h2c, `TestH2CTransport`, `TestHTTPTransport`, `./edgecp/`, `./plugin/`, `./trust/` |
| PASS | the FAIL list above, with `-tags http2legacy` |

The wrap error is **not** `extended connect not supported by peer`, so the
existing h1 fallback does not fire. Integration tests 502.

This is **not** [golang/go#70728](https://github.com/golang/go/issues/70728)
(encoder order: `:protocol` after regular headers → `PROTOCOL_ERROR`). That
was a Go 1.24 release blocker and is fixed. Confusing web hits for
“`:protocol` encoder” are that bug.

No public issue described the 1.27 wrap + `:protocol` rejection as of
2026-08-28. Closest wrap holes (fixed in x/net, same class):
[#79642](https://github.com/golang/go/issues/79642) (`ConfigureServer` ALPN),
[#79778](https://github.com/golang/go/issues/79778) (`ConfigureTransport`).
x/net's original extended-CONNECT tests live in `transport_test.go` under
`//go:build !(go1.27 && !http2legacy)`, so they never run against wrap.

Accepted client API is still `Request.Header[":protocol"]`
([#53208](https://github.com/golang/go/issues/53208)).
`HTTP2Config.EnableConnectProtocol` ([CL 776300](https://go.dev/cl/776300))
did not land in 1.27.0.

## Why not work around it

| Approach | Why not |
|---|---|
| `-tags http2legacy` | Escape hatch. Original x/net is frozen (critical/security only). Tag must hit every `go test` / image or WS-over-h2 dies. Two HTTP/2 stacks in one process (stdlib on `:443` / `ForceAttemptHTTP2`; old x/net on h2c + tunnels). Will go away when wrap is the only implementation ([#78064](https://github.com/golang/go/issues/78064), [#67810](https://github.com/golang/go/issues/67810) milestoned 1.28). |
| `replace` / downgrade x/net to pre-wrap (< v0.54) | Same stack as the tag, plus CVE lag and a fight with parapet/client-go. |
| Overlay stdlib `validateHeaders` | The real one-line fix (`k != ":protocol"`, matching `httpcommon`). Patching GOROOT/`-overlay` is a 1.27.1-fragile footgun. |
| `ForceAttemptHTTP2` / `NewClientConn` | Same `validateHeaders`. |
| `GODEBUG=http2xconnect=1` | Server advertise only. |
| Ship 1.27 with WS-over-h2 off | Not a silent fallback (502). Reopens the ephemeral-port wall in [WEBSOCKET.md](WEBSOCKET.md). |
| Custom CONNECT Framer | Throwaway once Go allows `:protocol`. |

File the wrap hole against `golang/go` (`net/http` / `x/net/http2`) rather
than carrying a local hack. Recheck after a 1.27.1 / x/net release that
mentions `:protocol` or `validateHeaders`.

## 1.27 benefits that can wait

Worth taking **after** the recheck is green, not before:

- Size-specialized malloc (~30% cheaper &lt;80B allocs, ~1% overall) — best
  free data-plane win.
- HTTP/1 `Response.Body` auto-drain — better idle-conn reuse on the reverse
  proxy client.
- HTTP/2 RFC 9218 client priority on public `:443` (old RR via
  `Server.DisableClientPriority`).
- `encoding/json` backed by v2 (faster unmarshal) — control plane only.

Treat `DefaultMaxHeaderValueCount = 500` as a public-ingress behavior change
(independent of our 16KiB `MaxHeaderBytes`), not a silent improvement.

Not useful here without extra work: generic methods, `encoding/json/v2` API,
stdlib `uuid`, `crypto/mldsa`, experimental SIMD.

`golang:1.27.0-trixie` already exists. Docker/CI availability is not the
blocker.
