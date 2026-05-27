// Package geoip resolves a client IP from IPLocate .mmdb databases for the WAF:
// its ISO 3166-1 alpha-2 country code (request.country, from ip-to-country) and
// its autonomous system number (request.asn, from ip-to-asn).
package geoip

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/moonrhythm/parapet/pkg/header"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// DB is a loaded IPLocate ip-to-country database.
type DB struct {
	reader *maxminddb.Reader
}

// Open reads a .mmdb file (the IPLocate ip-to-country DB) into memory.
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
	// IPLocate's ip-to-country records are flat: country_code at the top level
	// (unlike MaxMind GeoIP2, which nests it under country.iso_code).
	var rec struct {
		CountryCode string `maxminddb:"country_code"`
	}
	if err := d.reader.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.CountryCode
}

// ASNDB is a loaded IPLocate ip-to-asn database.
type ASNDB struct {
	reader *maxminddb.Reader
}

// OpenASN reads a .mmdb file (the IPLocate ip-to-asn DB) into memory.
func OpenASN(path string) (*ASNDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &ASNDB{reader: r}, nil
}

// ASN returns the autonomous system number for ip, or 0 if the IP is nil or has
// no ASN record (private range, not in the DB, lookup error, unparseable value).
// IPLocate stores asn as a string (e.g. "15169"), so it is parsed to an int.
func (d *ASNDB) ASN(ip net.IP) int64 {
	if d == nil || ip == nil {
		return 0
	}
	var rec struct {
		ASN string `maxminddb:"asn"`
	}
	if err := d.reader.Lookup(ip, &rec); err != nil {
		return 0
	}
	n, err := strconv.ParseInt(rec.ASN, 10, 64)
	if err != nil {
		return 0
	}
	return n
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
