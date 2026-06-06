package edge

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// get resolves an SNI through the store via the GetCertificate callback,
// reporting whether a real (non-fallback) cert was returned.
func get(s *CertStore, sni string) bool {
	c, _ := s.GetCertificate(&tls.ClientHelloInfo{
		ServerName:        sni,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	})
	return c != nil
}

func TestCertStore_UpdateThenSNIMatchExactAndWildcard(t *testing.T) {
	s := NewCertStore()
	c1, k1 := genCertPEM(t, "acme.com")
	c2, k2 := genCertPEM(t, "*.acme.com")
	require.True(t, s.Update("acme.com", c1, k1, `"e1"`))
	require.True(t, s.Update("*.acme.com", c2, k2, ""))

	assert.True(t, get(s, "acme.com"), "exact match")
	assert.True(t, get(s, "www.acme.com"), "single-label wildcard")
	assert.True(t, get(s, "ACME.com"), "case-insensitive")
	assert.False(t, get(s, "a.b.acme.com"), "wildcard is one label only")
	assert.False(t, get(s, "other.com"), "no match -> fallback")
	assert.Equal(t, 2, s.Len())
}

func TestCertStore_EtagRoundtripsPerFetchKey(t *testing.T) {
	s := NewCertStore()
	c, k := genCertPEM(t, "acme.com")
	s.Update("acme.com", c, k, `"abc"`)
	assert.Equal(t, `"abc"`, s.Etag("acme.com"))
	assert.Equal(t, "", s.Etag("missing.com"))
}

func TestCertStore_UnparseablePEMKeepsOld(t *testing.T) {
	s := NewCertStore()
	c, k := genCertPEM(t, "acme.com")
	require.True(t, s.Update("acme.com", c, k, `"v1"`))
	// garbage PEM -> Update returns false, store unchanged (fail static)
	assert.False(t, s.Update("acme.com", []byte("not a cert"), []byte("nope"), `"v2"`))
	assert.True(t, get(s, "acme.com"), "old cert still served")
	assert.Equal(t, `"v1"`, s.Etag("acme.com"), "old etag retained")
}

func TestCertStore_UpdateReplacesSameKeyAndRebuildsIndex(t *testing.T) {
	s := NewCertStore()
	c1, k1 := genCertPEM(t, "acme.com")
	s.Update("acme.com", c1, k1, `"v1"`)
	c2, k2 := genCertPEM(t, "acme.com")
	require.True(t, s.Update("acme.com", c2, k2, `"v2"`))
	assert.Equal(t, 1, s.Len(), "same fetch key replaces, not duplicates")
	assert.Equal(t, `"v2"`, s.Etag("acme.com"))
	assert.True(t, get(s, "acme.com"))
}

func TestCertStore_LoadedFlag(t *testing.T) {
	s := NewCertStore()
	assert.False(t, s.Loaded())
	c, k := genCertPEM(t, "acme.com")
	s.Update("acme.com", c, k, "")
	assert.True(t, s.Loaded())
}

func TestCertStore_OnDemandFetchOnMiss(t *testing.T) {
	s := NewCertStore()
	calls := 0
	s.SetOnDemand(func(sni string) {
		calls++
		if sni == "lazy.com" {
			c, k := genCertPEM(t, "lazy.com")
			s.Update(sni, c, k, "")
		}
	})
	assert.True(t, get(s, "lazy.com"), "on-demand fetch populated the cert")
	assert.Equal(t, 1, calls)
	// a subsequent lookup is served from the store without another fetch
	assert.True(t, get(s, "lazy.com"))
	assert.Equal(t, 1, calls)
	// an SNI the on-demand fetch can't satisfy falls back (no panic / no error)
	assert.False(t, get(s, "denied.com"))
}

func TestCertStore_OnDemandNegativeCacheSuppressesRepeat(t *testing.T) {
	s := NewCertStore()
	var calls int32
	s.SetOnDemand(func(string) { atomic.AddInt32(&calls, 1) }) // never satisfies -> always a miss
	for range 5 {
		assert.False(t, get(s, "denied.com"))
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "missed SNI is fetched once, then negative-cached")
}

func TestCertStore_OnDemandNegativeCacheExpires(t *testing.T) {
	s := NewCertStore()
	s.ConfigureOnDemand(time.Millisecond, 0)
	var calls int32
	s.SetOnDemand(func(string) { atomic.AddInt32(&calls, 1) })
	assert.False(t, get(s, "denied.com"))
	time.Sleep(5 * time.Millisecond)
	assert.False(t, get(s, "denied.com"))
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "re-fetched after the negative-cache TTL expires")
}

func TestCertStore_OnDemandUpdateLiftsSuppression(t *testing.T) {
	s := NewCertStore()
	var calls int32
	deliver := false
	s.SetOnDemand(func(sni string) {
		atomic.AddInt32(&calls, 1)
		if deliver {
			c, k := genCertPEM(t, sni)
			s.Update(sni, c, k, "")
		}
	})
	assert.False(t, get(s, "lazy.com"), "first attempt misses and negative-caches")
	// Even though the fetcher would now deliver, the negative cache short-circuits it.
	deliver = true
	assert.False(t, get(s, "lazy.com"), "still suppressed within the TTL window")
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
	// A cert arriving by any path (here the periodic loop) clears the suppression.
	c, k := genCertPEM(t, "lazy.com")
	require.True(t, s.Update("lazy.com", c, k, ""))
	assert.True(t, get(s, "lazy.com"), "served from the table once a cert lands")
}

func TestCertStore_OnDemandSingleFlightCollapsesConcurrent(t *testing.T) {
	s := NewCertStore()
	var calls int32
	var once sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	s.SetOnDemand(func(sni string) {
		atomic.AddInt32(&calls, 1)
		once.Do(func() { close(started) })
		<-release // hold the leader so followers pile into single-flight
		c, k := genCertPEM(t, sni)
		s.Update(sni, c, k, "")
	})

	const n = 8
	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = get(s, "lazy.com") }(i)
	}
	<-started
	time.Sleep(20 * time.Millisecond) // give every goroutine time to join the in-flight fetch
	close(release)
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "concurrent same-SNI handshakes share one CP fetch")
	for i := range results {
		assert.True(t, results[i], "every waiter is served the fetched cert")
	}
}
