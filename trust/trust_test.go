package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

func caPEMFor(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edge-ca"},
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

func TestManagerForwardOnlyAndFailStatic(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	m := NewManager()

	if m.ClientCAs() != nil {
		t.Fatal("pool should be nil before first apply")
	}
	if _, err := m.apply(Bundle{Generation: 5, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if m.Generation() != 5 || m.ClientCAs() == nil {
		t.Fatal("first apply did not take")
	}

	// A lower generation is rejected (rollback) and an equal one is a no-op
	// (unchanged); neither is applied, so the live pool stays put.
	if _, err := m.apply(Bundle{Generation: 3, CAPEM: caPEM}); err == nil {
		t.Error("rollback to lower generation must not apply")
	}
	if _, err := m.apply(Bundle{Generation: 5, CAPEM: caPEM}); err == nil {
		t.Error("replay of equal generation must not apply")
	}
	if m.Generation() != 5 {
		t.Error("a rejected bundle must not change generation")
	}

	// Strict parse: a non-empty but cert-less ca_pem is rejected, last-good kept.
	prev := m.ClientCAs()
	if _, err := m.apply(Bundle{Generation: 6, CAPEM: []byte("garbage")}); err == nil {
		t.Error("ca_pem with no certs must be rejected")
	}
	if m.Generation() != 5 || m.ClientCAs() != prev {
		t.Error("a rejected reload must keep last-good")
	}

	// A higher generation applies.
	if _, err := m.apply(Bundle{Generation: 6, CAPEM: caPEM, CAID: "b"}); err != nil {
		t.Fatalf("forward apply: %v", err)
	}
	if m.Generation() != 6 || m.CAID() != "b" {
		t.Error("forward apply did not take")
	}
}

// TestVerifyClientCert is the Cloudflare-coexistence contract: only a client cert that
// chains to the live edge CA confers mTLS trust; no cert / a foreign cert (Cloudflare
// AOP) returns false (never aborts), and a CA rotation re-verifies (the per-generation
// cache is invalidated).
func TestVerifyClientCert(t *testing.T) {
	caCertPEM, caKeyPEM := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caCertPEM, caKeyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leafFor := func(sg *edgecp.Signer, id string) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		chainPEM, _, _, err := sg.Sign(key.Public(), id)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(chainPEM)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	csFor := func(leaf *x509.Certificate) *tls.ConnectionState {
		if leaf == nil {
			return &tls.ConnectionState{}
		}
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	}

	m := NewManager()
	edge := leafFor(signer, "edge-1")

	// No bundle loaded yet → no mTLS trust (cold start degrades to CIDR-only).
	if m.VerifyClientCert(csFor(edge)) {
		t.Fatal("no loaded pool must not confer mTLS trust")
	}

	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caCertPEM, CAID: "a"}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Edge leaf verifies (second call exercises the memo cache).
	if !m.VerifyClientCert(csFor(edge)) || !m.VerifyClientCert(csFor(edge)) {
		t.Fatal("edge leaf must verify against the loaded edge CA")
	}

	// Absent client cert (nil and empty) → not trusted; never aborts.
	if m.VerifyClientCert(nil) || m.VerifyClientCert(csFor(nil)) {
		t.Fatal("absent client cert must not confer mTLS trust")
	}

	// A cert from a DIFFERENT CA (the Cloudflare-AOP case) → not trusted.
	otherCertPEM, otherKeyPEM := caPEMFor(t)
	otherSigner, _, _ := edgecp.NewProvidedSigner(otherCertPEM, otherKeyPEM, time.Hour, time.Minute)
	other := leafFor(otherSigner, "intruder")
	if m.VerifyClientCert(csFor(other)) {
		t.Fatal("a cert not chaining to the edge CA must not be trusted")
	}

	// Rotate to the other CA: the cache is invalidated by the generation bump, so the
	// old-CA leaf is now rejected and the other leaf accepted.
	if _, err := m.apply(Bundle{Generation: 2, CAPEM: otherCertPEM, CAID: "b"}); err != nil {
		t.Fatalf("rotate apply: %v", err)
	}
	if m.VerifyClientCert(csFor(edge)) {
		t.Fatal("after rotating CAs, the old-CA leaf must no longer verify")
	}
	if !m.VerifyClientCert(csFor(other)) {
		t.Fatal("the new-CA leaf must verify after rotation")
	}
}

// TestApplyResultEnum pins the typed applyResult each branch returns — the label fed
// to metric.TrustApply. parse_rejected (a valid CERTIFICATE block with non-cert DER)
// is otherwise unexercised; the others back the rejection/apply metric counts.
func TestApplyResultEnum(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	m := NewManager()

	if res, err := m.apply(Bundle{Generation: 5, CAPEM: caPEM, CAID: "a"}); err != nil || res != resultApplied {
		t.Fatalf("apply: res=%v err=%v, want resultApplied", res, err)
	}
	// Equal generation is a benign replay → resultUnchanged (NOT a rollback, so it
	// won't WARN); a strictly-lower generation is the real rollback.
	if res, err := m.apply(Bundle{Generation: 5, CAPEM: caPEM}); err == nil || res != resultUnchanged {
		t.Errorf("replay (equal gen): res=%v err=%v, want resultUnchanged", res, err)
	}
	if res, err := m.apply(Bundle{Generation: 4, CAPEM: caPEM}); err == nil || res != resultRollbackRejected {
		t.Errorf("rollback (lower gen): res=%v err=%v, want resultRollbackRejected", res, err)
	}
	// No CERTIFICATE block at all → empty_rejected.
	if res, err := m.apply(Bundle{Generation: 6, CAPEM: []byte("garbage")}); err == nil || res != resultEmptyRejected {
		t.Errorf("no certs: res=%v err=%v, want resultEmptyRejected", res, err)
	}
	// A well-formed CERTIFICATE block whose DER body is not a cert → parse_rejected.
	badDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x01, 0x02, 0x03}})
	if res, err := m.apply(Bundle{Generation: 6, CAPEM: badDER}); err == nil || res != resultParseRejected {
		t.Errorf("bad DER: res=%v err=%v, want resultParseRejected", res, err)
	}
	// Every rejection kept last-good.
	if m.Generation() != 5 || m.CAID() != "a" {
		t.Errorf("rejections must keep last-good, got gen=%d ca_id=%q", m.Generation(), m.CAID())
	}
}

// TestTrustBundleOverTLSEndToEnd runs the real edgecp trust-bundle handler over a
// TLS httptest server, has the core's trust Client fetch it with MANDATORY server
// verification, applies it, and confirms the resulting pool verifies an edge leaf
// the same CA signs — i.e. the full core↔CP trust path with no token.
func TestTrustBundleOverTLSEndToEnd(t *testing.T) {
	caCertPEM, caKeyPEM := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caCertPEM, caKeyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h := edgecp.NewServer(edgecp.NewCertStore(), edgecp.NewAuthz(nil)).WithSigner(signer, 1).Handler()
	srv := httptest.NewTLSServer(h)
	defer srv.Close()

	// The httptest server cert is self-signed; use it as the mandatory CP server CA.
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := NewClient(srv.URL, serverCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, unchanged, err := c.Fetch(0, false)
	if err != nil || unchanged {
		t.Fatalf("fetch: err=%v unchanged=%v", err, unchanged)
	}
	if b.CAID != signer.CAID() {
		t.Errorf("ca_id mismatch: %q vs %q", b.CAID, signer.CAID())
	}

	m := NewManager()
	if _, err := m.apply(b); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// An edge leaf the CA signs must verify against the applied pool.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chainPEM, _, _, err := signer.Sign(leafKey.Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chainPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     m.ClientCAs(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("edge leaf does not verify against the pulled trust bundle: %v", err)
	}
}

func TestClassifyEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     EndpointMode
		wantErr  bool
	}{
		{"https is verified TLS", "https://cp:8443", ModeHTTPS, false},
		{"http is plaintext (no flag needed)", "http://cp:8080", ModeInsecureHTTP, false},
		{"no scheme is rejected", "cp:8443", 0, true},
		{"other scheme is rejected", "ftp://cp", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ClassifyEndpoint(c.endpoint)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", c.endpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("mode = %v, want %v", got, c.want)
			}
		})
	}
}

// EDGE_TRUST_CP_CA unset falls back to the system trust store, but verification stays
// ON (no InsecureSkipVerify): a CP cert not anchored in the system store is rejected,
// unlike a pinned NewClient handed that cert as its CA.
func TestSystemRootsClientVerifiesAndRejectsUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // self-signed, not in system roots
	defer srv.Close()

	c := NewSystemRootsClient(srv.URL)
	if _, _, err := c.Fetch(0, false); err == nil {
		t.Fatal("system-roots client must reject a CP cert not anchored in the system trust store")
	}
}

// The plaintext client pulls the bundle over an http:// endpoint with no server-TLS
// and no CA — the http:// use-case. Integrity is assumed to come from the transport
// (mesh/tunnel); the plaintext test server stands in for it.
func TestInsecureHTTPClientFetchesOverPlaintext(t *testing.T) {
	caCertPEM, caKeyPEM := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caCertPEM, caKeyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h := edgecp.NewServer(edgecp.NewCertStore(), edgecp.NewAuthz(nil)).WithSigner(signer, 1).Handler()
	srv := httptest.NewServer(h) // PLAINTEXT http://, unlike NewTLSServer above
	defer srv.Close()

	c := NewInsecureHTTPClient(srv.URL)
	b, unchanged, err := c.Fetch(0, false)
	if err != nil || unchanged {
		t.Fatalf("plaintext fetch: err=%v unchanged=%v", err, unchanged)
	}
	if b.CAID != signer.CAID() {
		t.Errorf("ca_id mismatch: %q vs %q", b.CAID, signer.CAID())
	}
}

// ---- warm-start cache ----

// The full warm-start cycle: apply -> persist -> a fresh manager loads the floor ->
// rejects a stale (rotated-out) bundle, ACCEPTS the revalidating equal generation (must
// not brick), then resumes forward-only.
func TestWarmStartFloorRoundTrip(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	path := t.TempDir() + "/trust-cache.json"

	// Manager A applies gen 7 and persists it.
	a := NewManager()
	a.cachePath = path
	if _, err := a.apply(Bundle{Generation: 7, CAPEM: caPEM, CAID: "ca7"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	a.writeCache(cacheEntry{Generation: 7, CAPEM: string(caPEM), CAID: "ca7"})

	// Manager B (a "restart") loads the floor — but must NOT trust anything yet.
	b := NewManager()
	b.EnableWarmStart(path, time.Hour)
	if b.WarmStartFloor() != 7 {
		t.Fatalf("floor = %d, want 7", b.WarmStartFloor())
	}
	if b.ClientCAs() != nil {
		t.Fatal("warm-start must NOT load ClientCAs from the cache (trust stays CIDR-only until revalidated)")
	}
	// lastGood is seeded from the cache so a 304 before the first apply still refreshes the
	// liveness timestamp — but it grants NO trust (ClientCAs stayed nil above, floor unchanged).
	if b.lastGood == nil || b.lastGood.Generation != 7 {
		t.Fatalf("EnableWarmStart must seed lastGood from the cache for the liveness refresh, got %+v", b.lastGood)
	}

	// A stale CP replica serving gen 6 (< floor) is rejected — anti-resurrection.
	if res, err := b.apply(Bundle{Generation: 6, CAPEM: caPEM, CAID: "old"}); err == nil || res != resultFloorRejected {
		t.Errorf("stale-below-floor: res=%v err=%v, want resultFloorRejected", res, err)
	}
	if b.ClientCAs() != nil {
		t.Fatal("a floor-rejected bundle must not establish trust")
	}

	// The revalidating LIVE fetch at the SAME generation (7 == floor) MUST apply — the
	// floor must not brick the current bundle.
	if res, err := b.apply(Bundle{Generation: 7, CAPEM: caPEM, CAID: "ca7"}); err != nil || res != resultApplied {
		t.Fatalf("revalidate at floor: res=%v err=%v, want resultApplied", res, err)
	}
	if b.ClientCAs() == nil || b.Generation() != 7 {
		t.Fatal("revalidation must flip on mTLS trust (pool loaded, gen=7)")
	}

	// Forward-only resumes: replay of 7 is a no-op (unchanged), 8 advances.
	if res, _ := b.apply(Bundle{Generation: 7, CAPEM: caPEM}); res != resultUnchanged {
		t.Errorf("post-revalidation replay: res=%v, want resultUnchanged", res)
	}
	if res, err := b.apply(Bundle{Generation: 8, CAPEM: caPEM, CAID: "ca8"}); err != nil || res != resultApplied {
		t.Errorf("forward apply: res=%v err=%v, want resultApplied", res, err)
	}
}

// A cache older than maxStale is discarded (cold-start, no floor) so a long outage resyncs
// cleanly rather than being pinned to an ancient floor.
func TestWarmStartMaxStaleDiscards(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	path := t.TempDir() + "/trust-cache.json"
	stale := cacheEntry{Generation: 9, CAID: "x", CAPEM: string(caPEM), WrittenAt: time.Now().Add(-48 * time.Hour).Unix()}
	data, _ := json.Marshal(stale)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.EnableWarmStart(path, 24*time.Hour)
	if m.WarmStartFloor() != 0 {
		t.Errorf("a too-stale cache must be discarded (floor 0), got %d", m.WarmStartFloor())
	}
	// With no floor, an older generation now applies (cold-start semantics).
	if res, err := m.apply(Bundle{Generation: 3, CAPEM: caPEM, CAID: "y"}); err != nil || res != resultApplied {
		t.Errorf("post-discard apply: res=%v err=%v, want resultApplied", res, err)
	}
}

// Missing / corrupt / zero-generation caches are quiet no-ops (cold-start, no floor) — never
// fatal, never a panic.
func TestWarmStartBadCacheIsSafeNoOp(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	dir := t.TempDir()
	cases := map[string][]byte{
		"corrupt": []byte("{ not json"),
		"zerogen": func() []byte { d, _ := json.Marshal(cacheEntry{Generation: 0, CAPEM: string(caPEM)}); return d }(),
	}
	for name, content := range cases {
		p := dir + "/" + name + ".json"
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		m := NewManager()
		m.EnableWarmStart(p, time.Hour)
		if m.WarmStartFloor() != 0 {
			t.Errorf("%s: floor = %d, want 0 (cold-start)", name, m.WarmStartFloor())
		}
	}
	// Missing file.
	m := NewManager()
	m.EnableWarmStart(dir+"/does-not-exist.json", time.Hour)
	if m.WarmStartFloor() != 0 {
		t.Errorf("missing cache: floor = %d, want 0", m.WarmStartFloor())
	}
	// Empty path disables persistence (no floor, writeCache is a no-op).
	m2 := NewManager()
	m2.EnableWarmStart("", time.Hour)
	m2.writeCache(cacheEntry{Generation: 1, CAPEM: string(caPEM)}) // must not panic / write anywhere
	if m2.WarmStartFloor() != 0 {
		t.Error("empty path must leave no floor")
	}
}

// writeCache is atomic + leaves no .tmp behind, and the re-read floor matches.
func TestWarmStartWriteAtomic(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	path := t.TempDir() + "/c.json"
	m := NewManager()
	m.cachePath = path
	// writeCache always stamps written_at=now (liveness), even if the caller passes a stale
	// timestamp — this is what makes the 304-refresh track last CP contact.
	m.writeCache(cacheEntry{Generation: 42, CAPEM: string(caPEM), CAID: "z", WrittenAt: 1})
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("writeCache must not leave a .tmp file behind")
	}
	e, err := readCache(path)
	if err != nil || e.Generation != 42 || e.CAID != "z" {
		t.Fatalf("round-trip: entry=%+v err=%v", e, err)
	}
	if time.Since(time.Unix(e.WrittenAt, 0)) > time.Minute {
		t.Errorf("writeCache must stamp a fresh written_at (liveness), got %d", e.WrittenAt)
	}
}

// TestNewClientRequiresCA proves the mandatory-CA inversion: an empty/unparseable
// CP server CA is a hard error (no system-roots fallback).
func TestNewClientRequiresCA(t *testing.T) {
	if _, err := NewClient("https://cp:8443", nil); err == nil {
		t.Error("empty CA must be rejected (no system-roots fallback)")
	}
	if _, err := NewClient("https://cp:8443", []byte("not a cert")); err == nil {
		t.Error("unparseable CA must be rejected")
	}
}

func leafSignedBy(t *testing.T, sg *edgecp.Signer, id string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chainPEM, _, _, err := sg.Sign(key.Public(), id)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chainPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func csForLeaf(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}

// TestVerifyClientCertUntrustedDoesNotBustCache is the M5 hardening: an attacker
// can't mint a cert that chains to the edge CA, so a flood of distinct UNtrusted
// certs must never enter the verify cache — otherwise they'd evict the legit
// fleet's entries and force every real edge to re-verify (cache-bust).
func TestVerifyClientCertUntrustedDoesNotBustCache(t *testing.T) {
	caPEM, caKey := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caPEM, caKey, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, otherKey := caPEMFor(t)
	otherSigner, _, _ := edgecp.NewProvidedSigner(otherPEM, otherKey, time.Hour, time.Minute)

	m := NewManager()
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatal(err)
	}

	edge := leafSignedBy(t, signer, "edge-1")
	if !m.VerifyClientCert(csForLeaf(edge)) {
		t.Fatal("edge leaf must verify")
	}
	m.verifyMu.RLock()
	n0 := len(m.verifyCache)
	m.verifyMu.RUnlock()
	if n0 != 1 {
		t.Fatalf("trusted cert should be cached; cache len = %d", n0)
	}

	for i := 0; i < 200; i++ {
		if m.VerifyClientCert(csForLeaf(leafSignedBy(t, otherSigner, "intruder-"+strconv.Itoa(i)))) {
			t.Fatal("a cert not chaining to the edge CA must not be trusted")
		}
	}
	m.verifyMu.RLock()
	n1 := len(m.verifyCache)
	m.verifyMu.RUnlock()
	if n1 != 1 {
		t.Fatalf("untrusted certs must never be cached; cache grew to %d (cache-bust)", n1)
	}

	if !m.VerifyClientCert(csForLeaf(edge)) {
		t.Fatal("the trusted cert must still verify (served from cache)")
	}
}

// TestVerifyClientCertEvictsOneAtCap: at the cap a new trusted cert drops ONE entry
// rather than wiping the whole cache (so a fleet > cap doesn't force a fleet-wide
// re-verify at once).
func TestVerifyClientCertEvictsOneAtCap(t *testing.T) {
	caPEM, caKey := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caPEM, caKey, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatal(err)
	}

	// Pre-fill to the cap for the live generation.
	m.verifyMu.Lock()
	m.verifyGen = m.gen.Load()
	m.verifyCache = make(map[string]bool, verifyCacheCap)
	for i := 0; i < verifyCacheCap; i++ {
		m.verifyCache["k"+strconv.Itoa(i)] = true
	}
	m.verifyMu.Unlock()

	if !m.VerifyClientCert(csForLeaf(leafSignedBy(t, signer, "edge-cap"))) {
		t.Fatal("trusted cert must verify")
	}
	m.verifyMu.RLock()
	n := len(m.verifyCache)
	m.verifyMu.RUnlock()
	if n != verifyCacheCap {
		t.Fatalf("at cap, expected one eviction + one insert to keep len == %d, got %d", verifyCacheCap, n)
	}
}
