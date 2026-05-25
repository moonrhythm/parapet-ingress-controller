#!/usr/bin/env bash
# Phase-0 spike verification. Assumes ./target/debug/spike is already running.
set -u
P=http://127.0.0.1:6190
pass=0; fail=0
check() { # desc, expected_substr, actual
  if echo "$3" | grep -q "$2"; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1 -- expected '$2' in: $3"; fail=$((fail+1)); fi
}

echo "## plaintext frontend"
check "h1 upstream (h1->h1)"        "upstream=h1 version=HTTP/1.1"  "$(curl -s -H 'Host: h1.test' $P/a)"
check "h2c UPSTREAM (h1->h2c)"      "upstream=h2c version=HTTP/2.0" "$(curl -s -H 'Host: h2c.test' $P/b)"
check "retry+badaddr (dead->live)" "upstream=h1"                    "$(curl -s -H 'Host: flaky.test' $P/c)"

echo "## h2c FRONTEND (client prior-knowledge HTTP/2)"
check "h2c frontend -> h1 upstream" "upstream=h1"                   "$(curl -s --http2-prior-knowledge -H 'Host: h1.test' $P/d)"
check "h2c frontend -> h2c upstream" "upstream=h2c"                 "$(curl -s --http2-prior-knowledge -H 'Host: h2c.test' $P/e)"

echo "## hot route reload (late.test added ~1.5s after start)"
check "late.test now routes"        "upstream=h1"                   "$(curl -s -H 'Host: late.test' $P/f)"

echo "## dynamic SNI cert selection (TLS 6443)"
sni() { echo | openssl s_client -connect 127.0.0.1:6443 -servername "$1" 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr -d ' '; }
check "SNI foo.test -> foo cert"    "DNS:foo.test"      "$(sni foo.test)"
check "SNI bar.test -> bar cert"    "DNS:bar.test"      "$(sni bar.test)"
check "SNI a.wild.test -> wildcard" "DNS:\*.wild.test"  "$(sni a.wild.test)"
check "SNI unknown -> fallback"     "DNS:fallback.local" "$(sni nope.test)"

echo "## TLS termination + routing end-to-end"
check "https -> h1 upstream"        "upstream=h1"  "$(curl -sk -H 'Host: h1.test' https://127.0.0.1:6443/g)"

echo "## websocket / Upgrade passthrough (raw 101 + echo through proxy)"
WS_OUT=$(python3 - <<'PY'
import socket
s=socket.create_connection(("127.0.0.1",6190),timeout=3)
s.sendall(b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
          b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n\r\n")
import time; time.sleep(0.3)
s.sendall(b"PINGPING")
time.sleep(0.3)
try: data=s.recv(4096)
except Exception as e: data=str(e).encode()
print(repr(data))
PY
)
check "ws upgrade 101 returned"  "101 Switching Protocols" "$WS_OUT"
check "ws bytes echoed back"     "PINGPING"                "$WS_OUT"

echo
echo "RESULT: $pass passed, $fail failed"
exit $fail
