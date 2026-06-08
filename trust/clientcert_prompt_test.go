package trust

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

// recordCertRequest stands up the core's real ServerTLSConfig and performs one TLS
// handshake from a client that records (a) whether the server asked for a client cert
// — the client's GetClientCertificate fires iff the server sent a CertificateRequest —
// and (b) which CA subjects the server advertised (req.AcceptableCAs). AcceptableCAs is
// exactly the list a browser filters its offered client certs against: a server that
// requests a cert with an EMPTY AcceptableCAs is what makes a Windows browser (whose
// CryptoAPI store often holds client certs) pop the certificate-selection modal.
func recordCertRequest(t *testing.T, m *Manager) (requested bool, acceptableCAs [][]byte) {
	t.Helper()
	serverCert := genServerCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := m.ServerTLSConfig(nil, []tls.Certificate{serverCert})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tc := tls.Server(conn, cfg)
		_ = tc.Handshake() // outcome is observed via the client callback below
	}()

	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // this test inspects the CertificateRequest, not the server cert
		GetClientCertificate: func(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			requested = true
			acceptableCAs = req.AcceptableCAs
			return &tls.Certificate{}, nil // present no client cert
		},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.CloseWrite()
	conn.Close()
	return requested, acceptableCAs
}

// TestServerTLSConfig_NoCertPromptBeforeCALoaded asserts the cold-start window does not
// prompt: with no edge CA loaded yet (CIDR-only), nobody can be mTLS-trusted, so the
// core must not send a CertificateRequest at all — otherwise every directly-connecting
// browser is prompted for a certificate it can never usefully provide.
func TestServerTLSConfig_NoCertPromptBeforeCALoaded(t *testing.T) {
	m := NewManager() // never applied: ClientCAs() == nil
	requested, _ := recordCertRequest(t, m)
	if requested {
		t.Error("cold start (no edge CA loaded) sent a CertificateRequest — a directly-connecting " +
			"browser would be prompted to select a client certificate")
	}
}

// TestServerTLSConfig_AdvertisesEdgeCAFilter asserts that once an edge CA is loaded the
// core still requests the edge's client cert, but advertises the edge CA's subject in the
// CertificateRequest. Browsers offer only client certs chaining to an advertised CA, so a
// user with no cert under the (internal) edge CA is offered nothing and never prompts;
// the edge's CP-issued cert still chains and is presented + trusted per request.
func TestServerTLSConfig_AdvertisesEdgeCAFilter(t *testing.T) {
	m := NewManager()
	caPEM, _ := caPEMFor(t)
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatal(err)
	}

	requested, cas := recordCertRequest(t, m)
	if !requested {
		t.Fatal("with an edge CA loaded the core must still request the edge's client cert")
	}
	if len(cas) == 0 {
		t.Fatal("CertificateRequest advertised an EMPTY acceptable-CA list — browsers offer ALL " +
			"client certs and prompt; the edge CA subject must be advertised so they can filter")
	}

	blk, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range cas {
		if bytes.Equal(s, caCert.RawSubject) {
			found = true
			break
		}
	}
	if !found {
		t.Error("advertised acceptable-CA list does not include the edge CA subject")
	}
}
