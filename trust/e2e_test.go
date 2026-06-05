package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edge"
	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

// TestAutoTrustEndToEnd wires the three real components together over real TLS:
//
//	edge (CP-issued client cert) --mTLS--> core (ServerTLSConfig)
//	                                         ^ ClientCAs from the trust bundle
//	core --GET /v1/trust-bundle (verified server-TLS)--> control plane (Signer)
//
// It proves the CA-only trust path the unit tests can't: the live handshake where
// the edge presents a CP-issued leaf and the core verifies it against the CA it
// pulled from the control plane — and the negative + cold-start behaviors.
func TestAutoTrustEndToEnd(t *testing.T) {
	// --- control plane: a real edgecp server (with a provided edge CA) over TLS ---
	edgeCACert, edgeCAKey := genEdgeCA(t)
	signer, _, err := edgecp.NewProvidedSigner(edgeCACert, edgeCAKey, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authz := edgecp.NewAuthzEntries(map[string]edgecp.Entry{
		"edge-tok": {ID: "edge-1", Domains: []string{"acme.com"}},
	})
	cp := httptest.NewTLSServer(edgecp.NewServer(edgecp.NewCertStore(), authz).WithSigner(signer, 100).Handler())
	defer cp.Close()
	cpServerCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw})

	// --- core: pull the trust bundle, build the :443 TLS config from it ---
	tc, err := NewClient(cp.URL, cpServerCA)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager()
	pullInto(t, tc, mgr) // applies the bundle (edge CA) into the manager's ClientCAs

	// Cross-plane: the core consumes the CP's exact (resourceVersion-derived) generation.
	if got := mgr.Generation(); got != 100 {
		t.Errorf("core generation = %d, want 100 (the CP's served generation)", got)
	}

	coreURL, coreClose := startCore(t, mgr)
	defer coreClose()

	// --- edge: fetch a CP-issued client cert through the real edge client ---
	edgeCP, err := edge.NewCpClient(cp.URL, "edge-tok", cpServerCA)
	if err != nil {
		t.Fatal(err)
	}
	ccStore := edge.NewClientCertStore()
	edge.RefreshEdgeCertOnce(edgeCP, ccStore, "timer")
	if !ccStore.Loaded() {
		t.Fatal("edge did not obtain a data-plane client cert from the CP")
	}
	edgeCert, _ := ccStore.GetClientCertificate(nil)

	// (1) A request presenting the CP-issued edge cert is TRUSTED by the core
	// (VerifyClientCert chains it to the pulled edge CA).
	if n := getTrust(t, coreURL, edgeCert); n == 0 {
		t.Error("edge with a CP-issued cert should be trusted, got untrusted")
	}

	// (2) A request with NO client cert completes but is UNTRUSTED —
	// Cloudflare-direct / browser traffic must still work, just CIDR-only.
	if n := getTrust(t, coreURL, nil); n != 0 {
		t.Errorf("no-cert request should be untrusted, got %d", n)
	}

	// (3) A leaf from a DIFFERENT (rogue) CA — the Cloudflare-AOP coexistence case:
	// the handshake MUST complete (ClientAuth is RequestClientCert, never verified at
	// the TLS layer) and the request is simply UNTRUSTED (VerifyClientCert false).
	rogue := genRogueLeaf(t)
	rn, rerr := tryGet(coreURL, rogue)
	if rerr != nil {
		t.Errorf("a non-edge client cert must NOT abort the handshake (Cloudflare AOP coexistence), got: %v", rerr)
	}
	if rn != 0 {
		t.Error("a rogue-CA client cert was TRUSTED — must never be")
	}

	// (4) Cold start: a core whose trust bundle hasn't loaded (nil pool) must
	// request-but-not-verify — a presented cert (even rogue) does NOT abort the
	// handshake; it's simply untrusted. This keeps edges from being cut off before
	// the first bundle pull.
	coldURL, coldClose := startCore(t, NewManager()) // never applied
	defer coldClose()
	if n, err := tryGet(coldURL, rogue); err != nil {
		t.Errorf("cold-start must not abort a presented cert, got error: %v", err)
	} else if n != 0 {
		t.Errorf("cold-start must be untrusted, got %d", n)
	}
}

// --- helpers ---

func pullInto(t *testing.T, c *Client, m *Manager) {
	t.Helper()
	b, unchanged, err := c.Fetch(0, false)
	if err != nil || unchanged {
		t.Fatalf("trust fetch: err=%v unchanged=%v", err, unchanged)
	}
	if _, err := m.apply(b); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// startCore runs an http.Server whose TLS config is the core's real ServerTLSConfig
// (built from the trust manager). The handler reports the real per-request trust
// decision — 1 if m.VerifyClientCert trusts the presented client cert, else 0 —
// exactly as the core's TrustProxy predicate does. Returns the base URL and a closer.
func startCore(t *testing.T, m *Manager) (string, func()) {
	t.Helper()
	serverCert := genServerCert(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		if m.VerifyClientCert(r.TLS) {
			n = 1
		}
		_, _ = io.WriteString(w, strconv.Itoa(n))
	})
	srv := &http.Server{
		Handler:   h,
		TLSConfig: m.ServerTLSConfig(nil, []tls.Certificate{serverCert}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	return "https://" + ln.Addr().String() + "/", func() { _ = srv.Close() }
}

func getTrust(t *testing.T, url string, clientCert *tls.Certificate) int {
	t.Helper()
	n, err := tryGet(url, clientCert)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return n
}

func tryGet(url string, clientCert *tls.Certificate) (int, error) {
	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test verifies the CLIENT cert path, not the server cert
	if clientCert != nil {
		tlsConf.Certificates = []tls.Certificate{*clientCert}
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32))
	n, _ := strconv.Atoi(string(body))
	return n, nil
}

func genEdgeCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "parapet-edge-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		PermittedURIDomains:   []string{edgecp.SANTrustDomain},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func genServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "core.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"core.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// genRogueLeaf returns a client cert signed by a CA the core does NOT trust.
func genRogueLeaf(t *testing.T) *tls.Certificate {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rogue-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "rogue-edge"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}
