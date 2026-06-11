package geoip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDB / asnTestDB are tiny IPLocate-shaped fixtures (flat schemas) kept
// under conformance/. See conformance/geoip/README.md.
const (
	testDB    = "../conformance/geoip/iplocate-country.mmdb"
	asnTestDB = "../conformance/geoip/iplocate-asn.mmdb"
)

func TestOpenBadPath(t *testing.T) {
	t.Parallel()
	_, err := Open("/nonexistent/definitely-not-a.mmdb")
	assert.Error(t, err)
}

func TestClientIP(t *testing.T) {
	t.Parallel()

	mk := func(realIP, xff, remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if realIP != "" {
			r.Header.Set("X-Real-Ip", realIP)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	ipStr := func(ip net.IP) string {
		if ip == nil {
			return ""
		}
		return ip.String()
	}

	// X-Real-Ip wins over everything.
	assert.Equal(t, "203.0.113.7",
		ipStr(ClientIP(mk("203.0.113.7", "10.0.0.1", "192.0.2.1:5000"))))
	// else the first X-Forwarded-For entry.
	assert.Equal(t, "10.0.0.1",
		ipStr(ClientIP(mk("", "10.0.0.1, 70.0.0.2", "192.0.2.1:5000"))))
	// else RemoteAddr with the port stripped.
	assert.Equal(t, "192.0.2.1", ipStr(ClientIP(mk("", "", "192.0.2.1:5000"))))
	// no parseable IP -> nil (Country then returns "").
	assert.Nil(t, ClientIP(mk("", "", "garbage")))
}

// Country on a nil DB or nil IP is "" (safe for the no-DB / unparseable paths).
func TestCountryNilSafe(t *testing.T) {
	t.Parallel()
	var d *DB
	assert.Equal(t, "", d.Country(net.ParseIP("8.8.8.8")))
}

// TestCountryIPLocateSchema proves Country decodes IPLocate's flat country_code
// records. It would return "" for every IP if the lookup reverted to MaxMind's
// nested country.iso_code, which this DB does not carry.
func TestCountryIPLocateSchema(t *testing.T) {
	t.Parallel()
	db, err := Open(testDB)
	require.NoError(t, err)

	cases := []struct {
		name, ip, want string
	}{
		{"ipv4 US", "8.8.8.8", "US"},
		{"ipv4 AU", "1.1.1.1", "AU"},
		{"ipv4 TH (test-net-3)", "203.0.113.5", "TH"},
		{"ipv6 DE (doc range)", "2001:db8::1", "DE"},
		{"unmapped -> empty", "192.0.2.1", ""},
		{"private -> empty", "10.0.0.1", ""},
		{"nil ip -> empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, db.Country(net.ParseIP(tc.ip)))
		})
	}
}

// ASN on a nil DB or nil IP is 0 (safe for the no-DB / unparseable paths).
func TestASNNilSafe(t *testing.T) {
	t.Parallel()
	var d *ASNDB
	assert.Equal(t, int64(0), d.ASN(net.ParseIP("8.8.8.8")))
}

// TestASNIPLocate proves ASN decodes IPLocate's flat string `asn` and parses it
// to an integer; unmapped/private/nil resolve to 0.
func TestASNIPLocate(t *testing.T) {
	t.Parallel()
	db, err := OpenASN(asnTestDB)
	require.NoError(t, err)

	cases := []struct {
		name, ip string
		want     int64
	}{
		{"google", "8.8.8.8", 15169},
		{"cloudflare", "1.1.1.1", 13335},
		{"inet-th", "203.150.0.1", 4618},
		{"ipv6 (doc range)", "2001:db8::1", 64500},
		{"unmapped -> 0", "192.0.2.1", 0},
		{"private -> 0", "10.0.0.1", 0},
		{"nil ip -> 0", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, db.ASN(net.ParseIP(tc.ip)))
		})
	}
}
