package trust

import (
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

// BenchmarkVerifyClientCert_CacheHit is the steady-state edge path: a leaf that
// already verified once is re-presented on every subsequent request. It must
// resolve under the RLock memo without rebuilding the x509 chain.
func BenchmarkVerifyClientCert_CacheHit(b *testing.B) {
	caPEM, caKey := caPEMFor(b)
	signer, _, err := edgecp.NewProvidedSigner(caPEM, caKey, time.Hour, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	m := NewManager()
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		b.Fatal(err)
	}
	cs := csForLeaf(leafSignedBy(b, signer, "edge-1"))
	// Prime the memo so the loop measures the cache-hit path.
	if !m.VerifyClientCert(cs) {
		b.Fatal("edge leaf must verify")
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink bool
	for i := 0; i < b.N; i++ {
		sink = m.VerifyClientCert(cs)
	}
	_ = sink
}

// BenchmarkVerifyClientCert_CacheMiss is the cold path: a fresh generation each
// iteration forces the full x509 chain build (the work the memo elides). It
// bounds the worst case — a CA rotation invalidating the whole fleet's memo.
func BenchmarkVerifyClientCert_CacheMiss(b *testing.B) {
	caPEM, caKey := caPEMFor(b)
	signer, _, err := edgecp.NewProvidedSigner(caPEM, caKey, time.Hour, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	m := NewManager()
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		b.Fatal(err)
	}
	cs := csForLeaf(leafSignedBy(b, signer, "edge-1"))
	b.ReportAllocs()
	b.ResetTimer()
	var sink bool
	for i := 0; i < b.N; i++ {
		// Advance the generation so each call misses the memo and re-verifies.
		m.verifyMu.Lock()
		m.verifyCache = nil
		m.verifyGen = 0
		m.verifyMu.Unlock()
		sink = m.VerifyClientCert(cs)
	}
	_ = sink
}
