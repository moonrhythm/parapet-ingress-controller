#!/usr/bin/env bash
# Phase 5 side-by-side perf sweep: drive each traffic scenario through the Go and
# the Rust controller, capture latency/throughput (k6) + CPU/mem (kubectl top),
# and print a Go-vs-Rust comparison. See ../PHASE5.md for the gate.
#
# Prereqs: k6, jq, kubectl (context `lab`). Run from a box that is NOT a cluster
# node under test (fairness rule 5). Edit the CONFIG block, then: ./run.sh
set -euo pipefail

# ----- CONFIG (edit me) -----------------------------------------------------
NODE="${NODE:-192.168.0.9}"            # node IP exposing the NodePorts
HOST="${HOST:-echo-lab.moonrhythm.io}" # ingress host for S1,S2,S4,S5
H2C_HOST="${H2C_HOST:-$HOST}"          # an h2c-backed ingress host for S3
RATE="${RATE:-3000}"                   # offered req/s (open model)
DURATION="${DURATION:-3m}"
WARMUP="${WARMUP:-30s}"
SCENARIOS="${SCENARIOS:-s1 s2 s3 s5 s6}" # add s4 once you have sized paths (PATHS=)

# Two controllers, each: <label> <http-nodeport> <https-nodeport> <pod-selector> <namespace>
GO_HTTP="${GO_HTTP:-31756}";  GO_HTTPS="${GO_HTTPS:-32547}"
RS_HTTP="${RS_HTTP:-31755}";  RS_HTTPS="${RS_HTTPS:-32546}"
GO_SELECTOR="${GO_SELECTOR:-app=parapet-ingress-controller-go}"
RS_SELECTOR="${RS_SELECTOR:-app=parapet-ingress-controller}"
NS="${NS:-parapet-ingress-controller}"
KCTX="${KCTX:-lab}"
# ----------------------------------------------------------------------------

OUT="${OUT:-results-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
TREND="med,p(95),p(99),p(99.9),max"

command -v k6 >/dev/null  || { echo "need k6 (brew/apt install k6)"; exit 1; }
command -v jq >/dev/null  || { echo "need jq"; exit 1; }
HAVE_TOP=1; kubectl --context="$KCTX" top pod -n "$NS" >/dev/null 2>&1 || { echo "WARN: kubectl top unavailable (no metrics-server?) — CPU/mem skipped"; HAVE_TOP=0; }

# Sample `kubectl top` for a selector into a file until a sentinel file is removed.
sample_top() { # $1=selector $2=outfile $3=stopflag
  while [ -f "$3" ]; do
    kubectl --context="$KCTX" top pod -n "$NS" -l "$1" --no-headers 2>/dev/null \
      | awk '{gsub("m","",$2); gsub("Mi","",$3); print $2, $3}' >> "$2" || true
    sleep 3
  done
}

# Run one (scenario,target). Echoes: rps p50 p95 p99 p999 err cpu_m mem_mi
run_one() { # $1=scenario $2=label $3=http $4=https $5=selector
  local sc="$1" label="$2" httpp="$3" httpsp="$4" sel="$5"
  local host="$HOST"; [ "$sc" = "s3" ] && host="$H2C_HOST"
  local sumj="$OUT/${sc}-${label}.summary.json"
  local topf="$OUT/${sc}-${label}.top"; : > "$topf"
  local flag; flag="$(mktemp)"

  # Warm up connection pools + TLS sessions + upstream keep-alives (discarded).
  # Skipped for s6 — its ramping arrival rate starts low and self-warms.
  if [ "$sc" != "s6" ]; then
    NODE="$NODE" HTTP_PORT="$httpp" HTTPS_PORT="$httpsp" HOST="$host" \
    SCENARIO="$sc" RATE="$RATE" DURATION="$WARMUP" \
      k6 run --quiet ../bench/load.js >/dev/null 2>&1 || true
  fi

  if [ "$HAVE_TOP" = 1 ]; then sample_top "$sel" "$topf" "$flag" & fi
  local topid=$!

  NODE="$NODE" HTTP_PORT="$httpp" HTTPS_PORT="$httpsp" HOST="$host" \
  SCENARIO="$sc" RATE="$RATE" DURATION="$DURATION" WARMUP="$WARMUP" \
    k6 run --quiet --summary-trend-stats="$TREND" --summary-export="$sumj" \
       ../bench/load.js >"$OUT/${sc}-${label}.log" 2>&1 || true

  if [ "$HAVE_TOP" = 1 ]; then rm -f "$flag"; wait "$topid" 2>/dev/null || true; fi

  local rps p50 p95 p99 p999 err cpu mem
  rps=$(jq -r '.metrics.http_reqs.rate // 0' "$sumj")
  p50=$(jq -r '.metrics.http_req_duration["med"] // .metrics.http_req_duration.med // 0' "$sumj")
  p95=$(jq -r '.metrics.http_req_duration["p(95)"] // 0' "$sumj")
  p99=$(jq -r '.metrics.http_req_duration["p(99)"] // 0' "$sumj")
  p999=$(jq -r '.metrics.http_req_duration["p(99.9)"] // 0' "$sumj")
  err=$(jq -r '(.metrics.proxy_errors.rate // .metrics.proxy_errors.value // 0)*100' "$sumj")
  cpu=$(awk '{c+=$1;n++} END{if(n)printf "%.0f",c/n; else print "NA"}' "$topf")
  mem=$(awk '{m+=$2;n++} END{if(n)printf "%.0f",m/n; else print "NA"}' "$topf")
  printf '%s %s %s %s %s %s %s %s\n' "$rps" "$p50" "$p95" "$p99" "$p999" "$err" "$cpu" "$mem"
}

printf '\nPhase 5 sweep — RATE=%s DURATION=%s  node=%s  out=%s\n' "$RATE" "$DURATION" "$NODE" "$OUT"
for sc in $SCENARIOS; do
  echo; echo "=== scenario $sc ==="
  read -r g_rps g_p50 g_p95 g_p99 g_p999 g_err g_cpu g_mem < <(run_one "$sc" go "$GO_HTTP" "$GO_HTTPS" "$GO_SELECTOR")
  read -r r_rps r_p50 r_p95 r_p99 r_p999 r_err r_cpu r_mem < <(run_one "$sc" rust "$RS_HTTP" "$RS_HTTPS" "$RS_SELECTOR")
  printf '%-10s | %-12s | %-12s\n' "metric" "Go" "Rust"
  printf '%-10s | %-12s | %-12s\n' "rps"      "$g_rps"  "$r_rps"
  printf '%-10s | %-12s | %-12s\n' "p50 ms"   "$g_p50"  "$r_p50"
  printf '%-10s | %-12s | %-12s\n' "p95 ms"   "$g_p95"  "$r_p95"
  printf '%-10s | %-12s | %-12s\n' "p99 ms"   "$g_p99"  "$r_p99"
  printf '%-10s | %-12s | %-12s\n' "p99.9 ms" "$g_p999" "$r_p999"
  printf '%-10s | %-12s | %-12s\n' "err %"    "$g_err"  "$r_err"
  printf '%-10s | %-12s | %-12s\n' "cpu m"    "$g_cpu"  "$r_cpu"
  printf '%-10s | %-12s | %-12s\n' "mem Mi"   "$g_mem"  "$r_mem"
done
echo; echo "raw per-run JSON + logs in $OUT/  — apply the gate from PHASE5.md (median of 3 runs)."
