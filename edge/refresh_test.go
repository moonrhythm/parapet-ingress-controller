package edge

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

// fakeEdgeCP signs the posted CSR with a real edgecp signer, so RefreshEdgeCertOnce's
// happy path (ok) and its ca_id derivation run end-to-end.
func fakeEdgeCP(t *testing.T) (*httptest.Server, *edgecp.Signer) {
	t.Helper()
	certPEM, keyPEM := testCA(t)
	signer, _, err := edgecp.NewProvidedSigner(certPEM, keyPEM, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge-cert" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		block, _ := pem.Decode([]byte(body.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		chain, notAfter, serial, err := signer.Sign(csr.PublicKey, "test-edge")
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"chain_pem": string(chain), "not_after": notAfter.UTC().String(), "serial": serial,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, signer
}

func TestRefreshEdgeCertOnceOK(t *testing.T) {
	srv, signer := fakeEdgeCP(t)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewClientCertStore()

	before := testutil.ToFloat64(edgeRemint.WithLabelValues("ok", "timer", "unknown"))
	if got, _ := RefreshEdgeCertOnce(cp, store, "timer"); got != "ok" {
		t.Fatalf("result = %q, want ok", got)
	}
	if testutil.ToFloat64(edgeRemint.WithLabelValues("ok", "timer", "unknown")) != before+1 {
		t.Error("ok remint counter not incremented")
	}
	if !store.Loaded() {
		t.Error("store should hold a cert after a successful re-mint")
	}
	// The edge-derived ca_id must equal the CP signer's CAID (same CA set, via caid).
	if v := testutil.ToFloat64(edgeClientCertCAID.WithLabelValues(signer.CAID(), "unknown")); v != 1 {
		t.Errorf("edge ca_id series for %q not set to 1", signer.CAID())
	}
}

func TestRefreshEdgeCertOnceFetchFail(t *testing.T) {
	// A CP that 500s every request → fetch_fail, prior cert kept (none here).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewClientCertStore()

	before := testutil.ToFloat64(edgeRemint.WithLabelValues("fetch_fail", "timer", "unknown"))
	if got, _ := RefreshEdgeCertOnce(cp, store, "timer"); got != "fetch_fail" {
		t.Fatalf("result = %q, want fetch_fail", got)
	}
	if testutil.ToFloat64(edgeRemint.WithLabelValues("fetch_fail", "timer", "unknown")) != before+1 {
		t.Error("fetch_fail remint counter not incremented")
	}
	if store.Loaded() {
		t.Error("a failed fetch must not load a cert")
	}
}
