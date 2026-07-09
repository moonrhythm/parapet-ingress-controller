package edge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// protoHandler reports the HTTP major version the upstream actually saw — the wire
// outcome of the edge→core hop (2 = h2c/h2, 1 = HTTP/1.1).
func protoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%d", r.ProtoMajor)
	})
}

// forwardThrough drives one request through the forwarder and returns the response
// body (which carries proto=N from protoHandler).
func forwardThrough(t *testing.T, f *Forwarder) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://core.example/", nil)
	f.ServeHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func addrOf(t *testing.T, rawURL string) string {
	t.Helper()
	return strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
}

// Plaintext hop: enableHTTP2=true must negotiate h2c to the core's H2C listener;
// enableHTTP2=false must stay on HTTP/1.1.
func TestForwarder_Plaintext_H2COptOut(t *testing.T) {
	// Plaintext listener that accepts both HTTP/1.1 and h2c (unencrypted HTTP/2) —
	// exactly what parapet's :80 server runs with H2C=true.
	srv := httptest.NewUnstartedServer(protoHandler())
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = p
	srv.Start()
	defer srv.Close()
	addr := addrOf(t, srv.URL)

	if got := forwardThrough(t, NewForwarder(addr, false, true, "", ForwarderTuning{}, nil, nil, false)); got != "proto=2" {
		t.Errorf("h2c default: want proto=2, got %q", got)
	}
	if got := forwardThrough(t, NewForwarder(addr, false, false, "", ForwarderTuning{}, nil, nil, false)); got != "proto=1" {
		t.Errorf("opt-out: want proto=1 (HTTP/1.1), got %q", got)
	}
}

// Re-encrypt hop: enableHTTP2=true must ALPN-negotiate h2 to an h2-capable core;
// enableHTTP2=false must stay on HTTP/1.1 over TLS. (InsecureSkipVerify makes the
// edge accept the httptest cert, matching the cluster-internal posture.)
func TestForwarder_TLS_H2OptOut(t *testing.T) {
	srv := httptest.NewUnstartedServer(protoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	addr := addrOf(t, srv.URL)

	if got := forwardThrough(t, NewForwarder(addr, true, true, "", ForwarderTuning{}, nil, nil, false)); got != "proto=2" {
		t.Errorf("h2 default: want proto=2, got %q", got)
	}
	if got := forwardThrough(t, NewForwarder(addr, true, false, "", ForwarderTuning{}, nil, nil, false)); got != "proto=1" {
		t.Errorf("opt-out: want proto=1 (HTTP/1.1 over TLS), got %q", got)
	}
}

// A core that only offers HTTP/1.1 over TLS (no h2 ALPN) must still work with
// enableHTTP2=true — ForceAttemptHTTP2 offers h2 but falls back to HTTP/1.1.
func TestForwarder_TLS_H2FallsBackToHTTP1(t *testing.T) {
	srv := httptest.NewUnstartedServer(protoHandler())
	srv.EnableHTTP2 = false // server offers only http/1.1 in ALPN
	srv.StartTLS()
	defer srv.Close()
	addr := addrOf(t, srv.URL)

	if got := forwardThrough(t, NewForwarder(addr, true, true, "", ForwarderTuning{}, nil, nil, false)); got != "proto=1" {
		t.Errorf("h2 requested, http/1.1-only core: want graceful proto=1, got %q", got)
	}
}

// recordRT records that it was used and returns a trivial 200.
type recordRT struct{ used bool }

func (r *recordRT) RoundTrip(*http.Request) (*http.Response, error) {
	r.used = true
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
}

// The re-encrypt h2 transport must route Upgrade/WebSocket requests to the HTTP/1.1
// transport (an h2 connection rejects Connection/Upgrade headers) and everything
// else to the h2-preferring transport.
func TestH2TLSTransport_UpgradeRoutesToHTTP1(t *testing.T) {
	h1, h2 := &recordRT{}, &recordRT{}
	tr := &h2TLSTransport{h1: h1, h2: h2}

	up := httptest.NewRequest(http.MethodGet, "https://core/", nil)
	up.Header.Set("Connection", "Upgrade")
	up.Header.Set("Upgrade", "websocket")
	if _, err := tr.RoundTrip(up); err != nil {
		t.Fatal(err)
	}
	if !h1.used || h2.used {
		t.Errorf("upgrade request: want h1, got h1=%v h2=%v", h1.used, h2.used)
	}

	h1.used, h2.used = false, false
	normal := httptest.NewRequest(http.MethodGet, "https://core/", nil)
	if _, err := tr.RoundTrip(normal); err != nil {
		t.Fatal(err)
	}
	if h1.used || !h2.used {
		t.Errorf("normal request: want h2, got h1=%v h2=%v", h1.used, h2.used)
	}
}
