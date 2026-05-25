# Phase 5 — Load-test performance-parity gate (the cutover criterion)

> **This phase needs you.** The locked migration rule is *"not slower than the
> current implementation."* Phase 5 is the measurement that decides cutover: run
> the Rust controller **side-by-side** with the Go controller on the `lab`
> cluster, push representative load through both, and confirm Rust meets the gate
> below. The dev box has no cluster and no production-like traffic, so the run is
> yours; this doc defines *exactly* what to measure, the harness to do it, and
> the pass/fail bar. (Only ever touch the `lab` context.)

## The gate (cutover passes iff ALL hold)

Measured at the **same offered load**, **same node**, **same backend**, **same
config**, Go vs Rust:

| Metric | Bar | Why |
|---|---|---|
| Throughput (max RPS at <1% error) | Rust ≥ **0.98 ×** Go | "not slower" — parity within noise |
| Latency p50 / p95 / p99 | Rust ≤ **1.05 ×** Go (each) | tail matters most for a proxy |
| Latency p99.9 | Rust ≤ **1.10 ×** Go | catch GC-style / scheduler stalls |
| Error rate (non-2xx/3xx not produced by the backend) | Rust ≤ Go | no new failures under load |
| CPU at fixed load | Rust ≤ Go (strong preference) | efficiency; soft-fail → discuss |
| Memory RSS at fixed load | Rust ≤ Go (strong preference) | efficiency; soft-fail → discuss |
| Correctness under load | status/headers identical (Phase 3 side-by-side) | no regression masked by load |

5% / 10% bands absorb run-to-run noise. If Rust **wins** throughput/latency but
loses CPU or memory, that's a discussion, not an auto-fail — record it and decide
together.

## Fairness rules (a wrong harness fails the gate for the wrong reason)

1. **Same everything but the binary.** Identical CPU/memory limits, identical env
   (`TRUST_PROXY`, `DISABLE_LOG`, `LOAD_ALL_CERTS`, host-concurrency vars), same
   ingress objects, same backend pods. Only the controller image differs.
2. **Same thread budget.** Rust uses `available_parallelism()` per proxy service;
   Go uses `GOMAXPROCS`. With a CPU *limit* set, pin both: give the Rust pod a CPU
   limit and Go `GOMAXPROCS=<that limit>` (or `resources.limits.cpu` + the
   automaxprocs the Go image already honors). Mismatched core counts invalidate
   the comparison.
3. **Measure with production settings, not the easy ones.** Prod runs with the
   access log ON and `TRUST_PROXY` set — logging and XFF parsing cost CPU, so
   measure with them as deployed. Do one run with `DISABLE_LOG=true` too, to
   isolate log overhead, but the *gate* uses the prod config.
4. **Drive load with an open model (constant arrival rate), not a closed loop.**
   `wrk` (closed-loop, fixed connections) hides tail latency via *coordinated
   omission*. Use **`wrk2`** (`-R <rate>`) or **k6** `constant-arrival-rate`. The
   harness here uses k6's open model.
5. **Generate load off-box.** Run the generator on a *different* machine/node than
   the controllers and backend, or it steals their CPU and skews everything. The
   loopback numbers from the early spike are **not** a valid gate.
6. **Warm up, then measure.** 30 s warm-up (fills connection pools, JIT-free here
   but TLS sessions + upstream keep-alives warm), then a ≥ 3-minute measured
   window. Repeat 3× per scenario; report median of the 3.

## Traffic profiles (run each scenario against BOTH controllers)

The early indicative bench was tiny plaintext GETs — not representative. Cover
what production actually serves:

| # | Scenario | Exercises |
|---|---|---|
| S1 | HTTP/1.1, small GET (≈0 body) | baseline routing + RR + access log |
| S2 | HTTPS, HTTP/2 downstream (ALPN h2), small GET | TLS termination + SNI + h2 |
| S3 | h2c upstream (backend `appProtocol: h2c`) | the migration's risk path |
| S4 | Mixed body sizes (1 KB / 64 KB / 1 MB responses) | streaming + compression |
| S5 | redirect-https on HTTP (301) | the cheap fast-path most prod hosts hit |
| S6 | Max-throughput probe (ramp arrival rate until error >1%) | the throughput bar |

## Harness

`rust/bench/` (provided):

- `load.js` — k6 script. Parameterized by env: `TARGET` (e.g. `http://192.168.0.9:31755`),
  `HOST` (the ingress host to send, via `Host:` header / SNI), `SCENARIO` (s1…s6),
  `RATE` (req/s for the open model), `DURATION`, `VUS`. Encodes the gate as k6
  `thresholds` so a run self-reports pass/fail.
- `run.sh` — orchestrates a full comparison: for each scenario, warm up + measure
  against Go then Rust, and snapshot each controller's CPU/mem (`kubectl top pod`)
  during the measured window. Writes per-run JSON + a summary table.

```bash
cd rust/bench
# one scenario, one target:
TARGET=http://192.168.0.9:31755 HOST=echo-lab.moonrhythm.io \
  SCENARIO=s1 RATE=5000 DURATION=3m k6 run load.js

# full side-by-side sweep (edit the targets/hosts at the top of run.sh first):
./run.sh
```

`k6` install: `brew install k6` / `apt install k6` / container `grafana/k6`.
For the raw max-throughput number, `wrk2` is lighter: `wrk2 -t4 -c128 -d3m -R<rate>
--latency https://host/`.

## Side-by-side deploy on `lab`

Run both controllers at once so load hits the same node/backend:

1. **Go** (current prod image) and **Rust** (`...:rust-dev`) as two DaemonSets/
   Deployments in the `parapet-ingress-controller` namespace, **different
   NodePorts** (Rust already at HTTP `31755` / HTTPS `32546`; give Go its own,
   e.g. `31756` / `32547`).
2. Same `resources.limits`, same env, same ingresses/backend. Confirm both serve
   the test host correctly *before* loading (e.g. `echo-lab.moonrhythm.io` → 200
   through each NodePort with `curl --resolve`).
3. Drive `run.sh` from a box with network access to the NodePorts (not a cluster
   node under test).

## Results template (fill and report back)

```
Node: <cpu model / cores>   Limits: <cpu>/<mem>   Generator: <host>   k6 vX

Scenario S1 (HTTP/1.1 small GET), RATE=NNNN, 3m, median of 3:
            | Go            | Rust          | Δ
  RPS (ok)  |               |               |
  p50 (ms)  |               |               |
  p95 (ms)  |               |               |
  p99 (ms)  |               |               |
  p99.9(ms) |               |               |
  err %     |               |               |
  CPU (avg) |               |               |
  RSS (MB)  |               |               |
... S2..S6 ...
S6 max RPS @ <1% err:  Go=____   Rust=____
```

## Decision

- **All bars pass →** Phase 5 GREEN. Proceed to cutover: add `rust-release.yaml`
  (or retag), shift production to the Rust image, keep the Go image as instant
  rollback for one release cycle.
- **A latency/throughput bar fails →** profile the Rust path (`tokio-console`,
  `perf`, pingora request phases), fix, re-run. Likely suspects to check first:
  thread count vs CPU limit (fairness rule 2), access-log serialization cost,
  TLS/h2 settings, upstream keep-alive pool sizing (`TR_MAX_IDLE_CONNS_PER_HOST`).
- **Only CPU/mem worse →** record and decide together; usually acceptable if
  latency/throughput win.

## Report back

Send the filled results table per scenario (median of 3), the node/limits/
generator setup, and any correctness diffs vs Go under load. That's the data the
cutover decision rides on.
