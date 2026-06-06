package proxy

import (
	"net/http"
)

// gateway is a http.RoundTripper that select underlying http.RoundTripper based on scheme
type gateway struct {
	Default http.RoundTripper
	H2C     http.RoundTripper
	AutoH2C http.RoundTripper // non-nil when UPSTREAM_AUTO_H2C is enabled
}

func (g *gateway) RoundTrip(r *http.Request) (*http.Response, error) {
	switch r.URL.Scheme {
	case "h2c":
		// explicit h2c (appProtocol) — no auto-detection / fallback
		return g.H2C.RoundTrip(r)
	case "https":
		return g.Default.RoundTrip(r)
	default: // http or empty
		if g.AutoH2C != nil {
			return g.AutoH2C.RoundTrip(r)
		}
		return g.Default.RoundTrip(r)
	}
}
