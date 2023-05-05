package mux

import (
	"net/http"
	"strings"
	_ "unsafe"
)

type prefixEntry struct {
	path string
	h    http.Handler
}

// pathMux is a multiplexer for path-based routing.
//
// Support exact match and prefix match.
type pathMux struct {
	exact  map[string]http.Handler
	prefix map[string]http.Handler
}

func (m *pathMux) init() {
	if m.exact == nil {
		m.exact = map[string]http.Handler{}
	}
	if m.prefix == nil {
		m.prefix = map[string]http.Handler{}
	}
}

func (m *pathMux) AddExact(path string, handler http.Handler) bool {
	m.init()

	path = normalizePath(path)

	if m.exact[path] != nil {
		return false
	}
	m.exact[path] = handler
	return true
}

func (m *pathMux) AddPrefix(path string, handler http.Handler) bool {
	m.init()

	path = normalizePath(path)
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if m.prefix[path] != nil {
		return false
	}
	m.AddExact(path, handler) // also add to exact match, for faster lookup
	m.prefix[path] = handler
	return true
}

func (m *pathMux) match(path string) http.Handler {
	// exact match
	if h := m.exact[path]; h != nil {
		return h
	}

	return nil
}

func (m *pathMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := cleanPath(r.URL.Path)

	// exact match
	if h := m.exact[path]; h != nil {
		h.ServeHTTP(w, r)
		return
	}

	// exact match with trailing slash
	if h := m.exact[path+"/"]; h != nil {

	}
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

//go:linkname cleanPath net/http.cleanPath
func cleanPath(p string) string
