package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// isClientCertRejected must fire ONLY on a peer-sent (core) cert-verify TLS alert — a
// false positive turns an unrelated core outage into a fleet-wide re-mint storm.
func TestIsClientCertRejected(t *testing.T) {
	// SHOULD re-mint: the core rejected our client cert (a received alert).
	remint := []error{
		errors.New("remote error: tls: bad certificate"),
		errors.New("remote error: tls: unknown certificate authority"),
		errors.New("remote error: tls: certificate required"),
		errors.New("remote error: tls: certificate unknown"),
		errors.New("remote error: tls: certificate revoked"),
		fmt.Errorf("Get \"https://core\": %w", errors.New("remote error: tls: bad certificate")),
	}
	for _, e := range remint {
		if !isClientCertRejected(e) {
			t.Errorf("want re-mint for %q", e)
		}
	}

	// MUST NOT re-mint: transient / unrelated / locally-raised — re-minting can't fix
	// these and would storm.
	noRemint := []error{
		nil,
		errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
		errors.New("context deadline exceeded"),
		errors.New("net/http: timeout awaiting response headers"),
		errors.New("remote error: tls: handshake failure"), // not a cert-trust alert
		errors.New("remote error: tls: protocol version not supported"),
		errors.New("remote error: tls: certificate expired"), // expiry is the renewal floor's job, not reactive
		errors.New("EOF"),
		tls.AlertError(42), // a LOCALLY-raised bad_certificate (the edge rejecting the core) — excluded
	}
	for _, e := range noRemint {
		if isClientCertRejected(e) {
			t.Errorf("must NOT re-mint for %v", e)
		}
	}
}

// TestClassifierMatchesRealGoAlert pins the classifier against the ACTUAL error string
// Go produces when a TLS server rejects the client's cert — the exact reactive scenario
// (core's ClientCAs no longer trusts the edge's OLD leaf after a trim). A future Go
// rename of the TLS-alert text would break the classifier silently; this catches it in CI
// (the string-literal unit test above cannot — it asserts against strings WE wrote).
func TestClassifierMatchesRealGoAlert(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// Require + verify a client cert against an EMPTY pool → any presented cert is rejected.
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	srv.StartTLS()
	defer srv.Close()

	// A self-signed client cert the server won't trust (stands in for the OLD-CA leaf).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	clientCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	c := srv.Client()
	c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("handshake should have failed (server rejects the client cert)")
	}
	if !isClientCertRejected(err) {
		t.Errorf("classifier must match the REAL Go cert-reject alert, got: %v", err)
	}
}
