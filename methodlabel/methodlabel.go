// Package methodlabel collapses a client-controlled HTTP method to a bounded
// Prometheus label. net/http admits any RFC 9110 token as a method, so labeling
// — and keying a handle cache — with the raw method lets a client mint unbounded
// permanent series by sending random method tokens.
//
// Only the RFC 7231 methods, PATCH (RFC 5789), and QUERY (RFC 10008) pass
// through; anything else collapses to Other. WebDAV methods (PROPFIND, SEARCH,
// …) stay Other: they are registered at IANA but not general-purpose HTTP.
package methodlabel

import "net/http"

// Other is the sentinel for a method outside the registered set.
const Other = "other"

// Query is the HTTP QUERY method (RFC 10008). net/http.MethodQuery lands in
// Go 1.28; keep a local constant until the module's Go version includes it.
const Query = "QUERY"

// Of returns method when it is a registered HTTP method, otherwise Other.
func Of(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace, Query:
		return method
	default:
		return Other
	}
}
