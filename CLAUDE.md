# parapet-ingress-controller

A Kubernetes ingress controller, maintained as **two co-equal implementations of
one behavior contract**. Both watch Ingress/Service/Secret/ConfigMap/Endpoints
and hot-reload routing without restarting; both honor the same annotations, env
vars, and metric names.

- **[`go/`](go/)** — the parapet (Go) implementation. Guidance: [`go/CLAUDE.md`](go/CLAUDE.md).
- **[`rust/`](rust/)** — the Pingora (Rust) implementation. Guidance: [`rust/README.md`](rust/README.md).
- **[`SPEC.md`](SPEC.md)** — the shared contract (annotations, env, metrics, per-request order, Go↔Rust divergences). **Source of truth: change behavior here first.**
- **[`WAF.md`](WAF.md)** — the WAF design (shared across both).
- **[`EDGE.md`](EDGE.md)** — the out-of-cluster edge proxy (Go, parapet framework) + in-cluster control plane (Go, REST cert+key + WAF distribution). Phases 1–4 implemented.
- **[`conformance/`](conformance/)** — language-neutral fixtures both implementations must satisfy (e.g. the WAF CEL corpus).

> Neither implementation is "the migration target" anymore — they are both
> maintained. A behavior change is incomplete until it lands in `go/`, `rust/`,
> `SPEC.md`, and (where relevant) `conformance/`.

## Layout

```
SPEC.md  WAF.md  EDGE.md  README.md  CLAUDE.md  LICENSE  SKILL.md
deploy/                 # shared Kubernetes manifests + RBAC (image-agnostic)
conformance/            # shared cross-impl fixtures (waf-cel-corpus.md, …)
.github/workflows/      # go-{test,build,release}.yaml + rust-{test,build,release}.yaml
                        #   test/build are path-filtered (go/** vs rust/**) so a
                        #   change to one impl never runs the other's CI; the
                        #   tag-triggered *-release builds both
go/                     # Go implementation — module .../parapet-ingress-controller/go
  CLAUDE.md             #   Go-specific architecture guide
  go.mod  cmd/  controller*.go  plugin/  proxy/  route/  cert/  k8s/
  metric/  state/  debounce/  wafrule/  retry.go  Dockerfile  Makefile
  edgecp/               #   edge control-plane lib (cert store, authz, reload, REST server)
  cmd/edge-controlplane/ #  edge control-plane binary (see EDGE.md)
  edge/                 #   edge proxy lib (cert store, CP client, WAF, disk cache)
  cmd/edge-proxy/       #   out-of-cluster edge proxy binary (parapet framework; see EDGE.md)
rust/                   # Rust implementation
  README.md  controller/  Dockerfile  PHASE*.md  bench/  spike/
  edge/                 #   DORMANT former Pingora edge proxy (migrated to go/cmd/edge-proxy)
```

> **Edge control plane + edge.** Both are **Go**. The control plane
> (`go/cmd/edge-controlplane` + `go/edgecp`) reuses `go/cert`/`go/k8s`/`go/wafrule`
> and serves per-edge cert+key + WAF rules over an HTTPS REST + bearer-token API.
> The **edge** (`go/cmd/edge-proxy` + `go/edge`, on the parapet framework) reuses
> `go/cert`/`go/wafrule`/`go/geoip` + `parapet/pkg/waf`. They share only the
> HTTP/JSON contract on the wire. The edge was migrated off Rust/Pingora after
> recurring pingora 0.8 bugs; `rust/edge` stays in the tree but is **dormant** (not
> built/tested/shipped by CI). See [`EDGE.md`](EDGE.md).

## Working in this repo

- **Touching shared behavior?** Update [`SPEC.md`](SPEC.md) first, then mirror it
  in **both** `go/` and `rust/`, and update `conformance/` if the contract gained
  a checkable case. A PR that changes one implementation's behavior without the
  other should call out the divergence (and mark it in SPEC) or be a bug.
- **Go work** → `cd go` (module root). See [`go/CLAUDE.md`](go/CLAUDE.md).
- **Rust work** → `cd rust`. See [`rust/README.md`](rust/README.md).
- **Images**: all under one `…/parapet-ingress-controller` repo, distinguished by
  a tag prefix per module — Go controller `:<sha|tag>`, Rust controller
  `:rust-<sha>`, edge control plane `:controlplane-<sha>`, edge proxy
  `:edge-<sha>`. `deploy/` is image-agnostic — point it at whichever stream a
  cluster runs.

## Quick commands

```bash
# Go
cd go && go test ./... && go vet ./...
# Rust (fast core, then full)
cd rust && cargo test -p parapet-ingress-controller
cd rust && cargo test -p parapet-ingress-controller --features proxy,cluster
```

## Before committing

**Always run `cargo fmt --all --check` (in `rust/`) and `gofmt -l` (in `go/`)
before committing — CI's lint job fails on any unformatted file.** Run
`cargo fmt --all` / `gofmt -w .` to fix, then re-run the check until clean.
Do not commit over a red build: run the relevant `cargo build`/`go build` and
confirm it passes first — a green editor or a stale log is not proof.
