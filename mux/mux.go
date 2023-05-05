package mux

import (
	"net/http"
)

// Mux is a multiplexer for routing.
//
// Support hostname exact match and wildcard match.
// Mux should be read-only after initialization.
type Mux struct {
	// m holds the mapping from hostname to pathMux
	m map[string]*pathMux
}

func (m *Mux) init(host string) {
	if m.m == nil {
		m.m = map[string]*pathMux{}
	}
	if m.m[host] == nil {
		m.m[host] = &pathMux{}
	}
}

func (m *Mux) AddExact(host string, path string, handler http.Handler) bool {
	m.init(host)

	m.m[host].AddExact(path, handler)

	return true
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}
