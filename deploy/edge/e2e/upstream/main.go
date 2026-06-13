// Command upstream is the dummy origin for the edge e2e smoke test (deploy/edge/e2e/run.sh).
// It stands in for the in-cluster parapet: a plaintext listener that accepts BOTH
// HTTP/1.1 and h2c (unencrypted HTTP/2) — exactly what parapet's :80 server runs
// with H2C=true — so the test exercises the edge's default h2c upstream hop.
//
// It echoes two things the test asserts on:
//   - X-Seen-Forwarded-Proto: the inbound X-Forwarded-Proto (client scheme the edge tagged).
//   - X-Seen-Proto-Major: the HTTP major version the request arrived as (2 ⇒ h2c worked).
//
// Pure stdlib, no module deps beyond the repo. Addr comes from UPSTREAM_ADDR.
package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	addr := os.Getenv("UPSTREAM_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18090"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Seen-Proto-Major", strconv.Itoa(r.ProtoMajor))
		if r.URL.Path == "/cacheme" {
			body := []byte("cacheable-body")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		body := []byte("hello-from-upstream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	// Accept HTTP/1.1 and h2c on the same plaintext listener (parapet's H2C=true).
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{Handler: mux, Protocols: protocols}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("upstream: listen %s: %v", addr, err)
	}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("upstream: serve: %v", err)
	}
}
