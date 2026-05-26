// Package geoip resolves a client IP to its ISO 3166-1 alpha-2 country code
// from a MaxMind GeoLite2/GeoIP2 .mmdb, for the WAF's request.country field.
package geoip

import (
	"net"
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet/pkg/header"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// DB is a loaded MaxMind country database.
type DB struct {
	reader *maxminddb.Reader
}

// Open reads a .mmdb file (e.g. GeoLite2-Country.mmdb) into memory.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{reader: r}, nil
}

// Country returns the ISO 3166-1 alpha-2 country code for ip, or "" if the IP
// is nil or has no country record (private range, not in the DB, lookup error).
func (d *DB) Country(ip net.IP) string {
	if d == nil || ip == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := d.reader.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

// ClientIP returns the best-known client IP, matching the precedence parapet's
// WAF uses for request.remote_ip (X-Real-IP -> first X-Forwarded-For ->
// RemoteAddr), so request.country resolves from the same address. Returns nil
// when no parseable IP is found.
func ClientIP(r *http.Request) net.IP {
	if v := header.Get(r.Header, header.XRealIP); v != "" {
		return net.ParseIP(strings.TrimSpace(v))
	}
	if v := header.Get(r.Header, header.XForwardedFor); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			v = v[:i]
		}
		return net.ParseIP(strings.TrimSpace(v))
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
