package geoip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
