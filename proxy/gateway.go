package proxy

import (
	"net/http"
)

// gateway is a http.RoundTripper that select underlying http.RoundTripper based on scheme
type gateway struct {
	Default http.RoundTripper
	H2C     http.RoundTripper
}

func (g gateway) RoundTrip(r *http.Request) (*http.Response, error) {
	var tr http.RoundTripper
	switch r.URL.Scheme {
	default:
		tr = g.Default
	case "h2c":
		tr = g.H2C
	}
	return tr.RoundTrip(r)
}
