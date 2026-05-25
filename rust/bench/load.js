// k6 load script for the Phase 5 perf-parity gate (see ../PHASE5.md).
//
// Open-model (constant arrival rate) load so tail latency is honest — a
// closed-loop tool like `wrk` hides p99 via coordinated omission.
//
// One SCENARIO per run; run.sh drives all of them against Go then Rust. The URL
// always uses the real ingress HOST (so SNI + Host header are correct), and
// `options.hosts` redirects that hostname to the node IP:NodePort — the k6
// equivalent of `curl --resolve`.
//
// Env knobs:
//   NODE        node IP exposing the NodePorts            (e.g. 192.168.0.9)
//   HTTP_PORT   HTTP NodePort                              (e.g. 31755)
//   HTTPS_PORT  HTTPS NodePort                             (e.g. 32546)
//   HOST        ingress host to send                       (e.g. echo-lab.moonrhythm.io)
//   SCENARIO    s1|s2|s3|s4|s5|s6                          (default s1)
//   RATE        target req/s for the open model            (default 2000)
//   DURATION    measured window                            (default 3m)
//   MAX_VUS     VU pool ceiling                            (default 800)
//   PATHS       comma-sep paths for s4 (sized responses)   (default "/")
//   INSECURE    skip TLS verify (lab self-signed fallback) (default true)

import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const NODE = __ENV.NODE || '127.0.0.1';
const HTTP_PORT = __ENV.HTTP_PORT || '80';
const HTTPS_PORT = __ENV.HTTPS_PORT || '443';
const HOST = __ENV.HOST || 'localhost';
const SCENARIO = (__ENV.SCENARIO || 's1').toLowerCase();
const RATE = parseInt(__ENV.RATE || '2000', 10);
const DURATION = __ENV.DURATION || '3m';
const MAX_VUS = parseInt(__ENV.MAX_VUS || '800', 10);
const PATHS = (__ENV.PATHS || '/').split(',');

const httpBase = `http://${HOST}:${HTTP_PORT}`;
const httpsBase = `https://${HOST}:${HTTPS_PORT}`;

// Map the real hostname:port to the node IP:NodePort (preserves SNI + Host).
const hosts = {};
hosts[`${HOST}:${HTTP_PORT}`] = `${NODE}:${HTTP_PORT}`;
hosts[`${HOST}:${HTTPS_PORT}`] = `${NODE}:${HTTPS_PORT}`;

// Custom rate of "good" responses (backend-produced 5xx are not our errors).
const proxyErrors = new Rate('proxy_errors');

// A scenario is { exec, expect }: how to send, and what status is "ok".
function smallHTTP() {
  return http.get(httpBase + '/', { headers: { Host: HOST }, tags: { s: SCENARIO } });
}
function smallHTTPS() {
  // https + ALPN → k6 negotiates HTTP/2 automatically.
  return http.get(httpsBase + '/', { tags: { s: SCENARIO } });
}

export const options = {
  insecureSkipTLSVerify: (__ENV.INSECURE || 'true') === 'true',
  hosts: hosts,
  discardResponseBodies: SCENARIO !== 's4', // keep bodies only when size matters
  scenarios: {
    run: {
      executor: SCENARIO === 's6' ? 'ramping-arrival-rate' : 'constant-arrival-rate',
      // constant: hold RATE. ramping (s6): climb past RATE to find the ceiling.
      ...(SCENARIO === 's6'
        ? {
            startRate: Math.max(1, Math.floor(RATE / 4)),
            timeUnit: '1s',
            preAllocatedVUs: Math.min(MAX_VUS, 200),
            maxVUs: MAX_VUS,
            stages: [
              { target: RATE, duration: '1m' },
              { target: RATE * 2, duration: '2m' },
              { target: RATE * 4, duration: '2m' },
            ],
          }
        : {
            rate: RATE,
            timeUnit: '1s',
            duration: DURATION,
            preAllocatedVUs: Math.min(MAX_VUS, Math.max(50, Math.ceil(RATE / 10))),
            maxVUs: MAX_VUS,
            gracefulStop: '10s',
          }),
    },
  },
  // Absolute sanity gates (the RELATIVE Go-vs-Rust comparison is done by run.sh
  // across both runs' JSON — k6 can't compare across processes). s6 aborts when
  // errors exceed 1% so the last good arrival rate is the throughput ceiling.
  thresholds: {
    proxy_errors: SCENARIO === 's6'
      ? [{ threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '10s' }]
      : ['rate<0.01'],
    http_req_duration: ['p(99)<5000'], // generous; the gate is relative, in run.sh
  },
};

export default function () {
  let res;
  let okStatus;
  switch (SCENARIO) {
    case 's2': // HTTPS, HTTP/2 downstream
    case 's3': // h2c upstream (point HOST at the h2c-backed ingress; client side identical)
      res = smallHTTPS();
      okStatus = res.status >= 200 && res.status < 400;
      break;
    case 's4': { // mixed body sizes — rotate over sized paths on the backend
      const p = PATHS[Math.floor(Math.random() * PATHS.length)];
      res = http.get(httpsBase + p, { tags: { s: SCENARIO } });
      okStatus = res.status >= 200 && res.status < 400;
      break;
    }
    case 's5': // redirect-https: expect a 301 and do NOT follow it
      res = http.get(httpBase + '/', { headers: { Host: HOST }, redirects: 0, tags: { s: SCENARIO } });
      okStatus = res.status === 301 || res.status === 308;
      break;
    case 's1': // HTTP/1.1 small GET
    default:
      res = smallHTTP();
      okStatus = res.status >= 200 && res.status < 400;
      break;
  }
  // "Error" = not the status we expect AND not a backend 5xx (backend faults are
  // the backend's, not the proxy's — but a proxy-generated 502/503 counts).
  const ok = check(res, { 'status ok': () => okStatus });
  proxyErrors.add(!ok);
}
