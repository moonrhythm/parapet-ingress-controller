package geoip

import (
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResultCacheGet proves get returns compute's value on a miss, the same
// value (without recomputing) on a hit, and caches negative results too.
func TestResultCacheGet(t *testing.T) {
	t.Parallel()
	c := newResultCache[string]()

	calls := map[string]int{}
	compute := func(key, ret string) func() string {
		return func() string {
			calls[key]++
			return ret
		}
	}

	cases := []struct {
		name, key, ret string
	}{
		{"placeable", "8.8.8.8", "US"},
		{"negative (unplaceable cached too)", "192.0.2.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// miss computes
			assert.Equal(t, tc.ret, c.get(tc.key, compute(tc.key, tc.ret)))
			assert.Equal(t, 1, calls[tc.key])
			// hit returns the same value without recomputing
			assert.Equal(t, tc.ret, c.get(tc.key, compute(tc.key, "SHOULD-NOT-RUN")))
			assert.Equal(t, 1, calls[tc.key], "hit must not recompute")
		})
	}
}

// TestResultCacheCapBounds proves the map is bounded: after inserting well past
// cacheCap distinct keys, the map never exceeds cacheCap entries (it clears a
// generation when full).
func TestResultCacheCapBounds(t *testing.T) {
	t.Parallel()
	c := newResultCache[int64]()

	for i := 0; i < cacheCap*3; i++ {
		k := strconv.Itoa(i)
		got := c.get(k, func() int64 { return int64(i) })
		require.Equal(t, int64(i), got)
		require.LessOrEqual(t, c.len(), cacheCap,
			"cache must stay bounded at cacheCap entries")
	}
}

// TestCachedMethodsMatchUncached proves the cached lookups are byte-for-byte
// transparent: CountryCached == Country and ASNCached == ASN for every IP, on
// both the cold (miss) and warm (hit) call.
func TestCachedMethodsMatchUncached(t *testing.T) {
	t.Parallel()

	country, err := Open(testDB)
	require.NoError(t, err)
	asn, err := OpenASN(asnTestDB)
	require.NoError(t, err)

	ips := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5", "2001:db8::1", "192.0.2.1", "10.0.0.1"}
	for _, s := range ips {
		ip := net.ParseIP(s)
		// twice each: first call is a miss, second is a hit
		assert.Equal(t, country.Country(ip), country.CountryCached(ip))
		assert.Equal(t, country.Country(ip), country.CountryCached(ip))
		assert.Equal(t, asn.ASN(ip), asn.ASNCached(ip))
		assert.Equal(t, asn.ASN(ip), asn.ASNCached(ip))
	}
}

// TestCachedMethodsNilSafe proves a nil DB / nil IP bypasses the cache and keeps
// the uncached zero-value semantics ("" / 0).
func TestCachedMethodsNilSafe(t *testing.T) {
	t.Parallel()
	var d *DB
	var a *ASNDB
	assert.Equal(t, "", d.CountryCached(net.ParseIP("8.8.8.8")))
	assert.Equal(t, int64(0), a.ASNCached(net.ParseIP("8.8.8.8")))

	// loaded DB but nil IP also bypasses cleanly.
	country, err := Open(testDB)
	require.NoError(t, err)
	assert.Equal(t, "", country.CountryCached(nil))
}

// TestResultCacheConcurrent exercises the RWMutex under concurrent readers and
// writers; run with -race it proves the cache is data-race free.
func TestResultCacheConcurrent(t *testing.T) {
	t.Parallel()
	c := newResultCache[int64]()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				k := strconv.Itoa(i % 64)
				v := c.get(k, func() int64 { return int64(i % 64) })
				assert.Equal(t, int64(i%64), v)
			}
		}()
	}
	wg.Wait()
}
