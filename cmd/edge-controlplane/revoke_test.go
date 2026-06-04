package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
	"github.com/moonrhythm/parapet-ingress-controller/edgecp/converge"
)

// pemDER decodes the first PEM block and returns its DER bytes.
func pemDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

func TestIDDisabled(t *testing.T) {
	tokens := map[string]edgecp.Entry{
		"tok-a": {ID: "edge-a", Disabled: false},
		"tok-b": {ID: "edge-b", Disabled: true},
		"tok-c": {ID: "Edge-C", Disabled: true}, // case-folded match
	}
	cases := []struct {
		id   string
		want bool
	}{
		{"edge-b", true},  // present + disabled
		{"edge-c", true},  // case-insensitive
		{"edge-a", false}, // present but still enabled
		{"edge-z", false}, // absent (typo guard)
		{"", false},
	}
	for _, tc := range cases {
		if got := idDisabled(tokens, tc.id); got != tc.want {
			t.Errorf("idDisabled(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestLastCertFP(t *testing.T) {
	old, _, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCert, _, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append([]byte(nil), old...), newCert...)

	got, err := lastCertFP(bundle)
	if err != nil {
		t.Fatal(err)
	}
	// The NEW (last) cert's fp is the sha256 of its DER (decode the second block).
	want := fpOfLastCert(t, newCert)
	if got != want {
		t.Errorf("lastCertFP picked the wrong block: got %s, want the NEW (last) %s", got, want)
	}
	// Sanity: the OLD cert alone has a different fp (proves we didn't pick the first).
	if got == fpOfLastCert(t, old) {
		t.Error("lastCertFP returned the OLD fp — must be the LAST block")
	}
}

func TestLastCertFPEmpty(t *testing.T) {
	if _, err := lastCertFP([]byte("not a cert")); err == nil {
		t.Error("a bundle with no CERTIFICATE block must error")
	}
}

// fpOfLastCert sha256s the single CERTIFICATE block in certPEM.
func fpOfLastCert(t *testing.T, certPEM []byte) string {
	t.Helper()
	fp, err := lastCertFP(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// emptyQuerier returns no series for any query, so Snapshot yields empty Observations and
// Evaluate never converges — exercising the wait loop's deadline (fail) path.
type emptyQuerier struct{}

func (emptyQuerier) Query(_ context.Context, _ string, _ time.Time) (model.Vector, error) {
	return model.Vector{}, nil
}

func TestPollUntilConvergedTimesOut(t *testing.T) {
	// A fast probe server (returns 401, like a rejected revoked token) so readStable's live
	// probe doesn't stall the test on a real dial.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := converge.Config{ExpectedCP: 2, ExpectedCore: 1, MinEdges: 1, Freshness: time.Minute}
	probe := revokedProbe{token: "tok", cpURL: srv.URL}

	start := time.Now()
	err := pollUntilConverged(context.Background(), "test", emptyQuerier{}, cfg, probe,
		2, 5*time.Millisecond, 20*time.Millisecond)
	if err == nil {
		t.Fatal("an empty (never-converging) snapshot must time out with an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the deadline must bound the wait")
	}
}

func TestFingerprintHelpersStable(t *testing.T) {
	// lastCertFP must equal a hand-rolled sha256-of-DER for a single cert.
	cert, _, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der := pemDER(t, cert)
	sum := sha256.Sum256(der)
	if got, _ := lastCertFP(cert); got != hex.EncodeToString(sum[:]) {
		t.Errorf("lastCertFP = %s, want sha256(DER) %s", got, hex.EncodeToString(sum[:]))
	}
}
