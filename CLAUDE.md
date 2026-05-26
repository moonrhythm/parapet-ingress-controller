# parapet-ingress-controller

A Kubernetes ingress controller, maintained as **two co-equal implementations of
one behavior contract**. Both watch Ingress/Service/Secret/ConfigMap/Endpoints
and hot-reload routing without restarting; both honor the same annotations, env
vars, and metric names.

- **[`go/`](go/)** — the parapet (Go) implementation. Guidance: [`go/CLAUDE.md`](go/CLAUDE.md).
- **[`rust/`](rust/)** — the Pingora (Rust) implementation. Guidance: [`rust/README.md`](rust/README.md).
- **[`SPEC.md`](SPEC.md)** — the shared contract (annotations, env, metrics, per-request order, Go↔Rust divergences). **Source of truth: change behavior here first.**
- **[`WAF.md`](WAF.md)** — the WAF design (shared across both).
- **[`conformance/`](conformance/)** — language-neutral fixtures both implementations must satisfy (e.g. the WAF CEL corpus).

> Neither implementation is "the migration target" anymore — they are both
> maintained. A behavior change is incomplete until it lands in `go/`, `rust/`,
> `SPEC.md`, and (where relevant) `conformance/`.

## Layout

```
SPEC.md  WAF.md  README.md  CLAUDE.md  LICENSE  SKILL.md
deploy/                 # shared Kubernetes manifests + RBAC (image-agnostic)
conformance/            # shared cross-impl fixtures (waf-cel-corpus.md, …)
.github/workflows/      # go-{test,build,release}.yaml + rust-{test,build}.yaml
                        #   each path-filtered (go/** vs rust/**) so a change to
                        #   one implementation never runs the other's CI
go/                     # Go implementation — module .../parapet-ingress-controller/go
  CLAUDE.md             #   Go-specific architecture guide
  go.mod  cmd/  controller*.go  plugin/  proxy/  route/  cert/  k8s/
  metric/  state/  debounce/  wafrule/  retry.go  Dockerfile  Makefile
rust/                   # Rust implementation
  README.md  controller/  Dockerfile  PHASE*.md  bench/  spike/
```

## Working in this repo

- **Touching shared behavior?** Update [`SPEC.md`](SPEC.md) first, then mirror it
  in **both** `go/` and `rust/`, and update `conformance/` if the contract gained
  a checkable case. A PR that changes one implementation's behavior without the
  other should call out the divergence (and mark it in SPEC) or be a bug.
- **Go work** → `cd go` (module root). See [`go/CLAUDE.md`](go/CLAUDE.md).
- **Rust work** → `cd rust`. See [`rust/README.md`](rust/README.md).
- **Images**: Go publishes `…/parapet-ingress-controller:<sha|tag>`; Rust publishes
  `…/parapet-ingress-controller:rust-<sha>`. `deploy/` is image-agnostic — point it
  at whichever stream a cluster runs.

## Quick commands

```bash
# Go
cd go && go test ./... && go vet ./...
# Rust (fast core, then full)
cd rust && cargo test -p parapet-ingress-controller
cd rust && cargo test -p parapet-ingress-controller --features proxy,cluster
```
