package edgecp

import (
	"strings"
)

// Authz maps a per-edge bearer token to the set of domains that edge may fetch
// (certs and, in Phase 2, WAF zones). Deny by default. Phase 1 loads the table
// from static config; a later phase can source it from a k8s Secret/ConfigMap.
//
// The bearer token is the edge's credential over server-side HTTPS — see
// EDGE.md "Authorization". A leaked token exposes only that token's allowed
// domains until revoked, so tokens should be short-lived/rotated and scoped.
type Authz struct {
	// token -> allowed domain patterns (exact or single-label wildcard "*.x.com")
	tokens map[string][]string
}

// NewAuthz builds the table from a token→domains map. Domain patterns are
// lowercased; matching mirrors cert.Table (exact, then single-label wildcard),
// plus a bare "*" catch-all that authorizes the token for every host.
func NewAuthz(tokens map[string][]string) *Authz {
	t := make(map[string][]string, len(tokens))
	for tok, domains := range tokens {
		ds := make([]string, 0, len(domains))
		for _, d := range domains {
			ds = append(ds, strings.ToLower(strings.TrimSpace(d)))
		}
		t[tok] = ds
	}
	return &Authz{tokens: t}
}

// Allowed reports whether the token is known and authorized for host. An unknown
// token (or empty host) is denied. A token whose domain list contains a bare "*"
// is authorized for every (non-empty) host — the catch-all for a serve-all edge
// that may front any domain (pure anycast/failover, where per-edge sharding buys
// nothing; see EDGE.md). The returned bool is the only signal — callers must not
// distinguish "unknown token" from "known but unauthorized" to the client beyond
// 401 vs 403 (handled in the server).
func (a *Authz) Allowed(token, host string) bool {
	domains, ok := a.tokens[token]
	if !ok {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "" {
		return false
	}
	for _, d := range domains {
		if d == "*" || d == name {
			return true
		}
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		wildcard := "*" + name[i:]
		for _, d := range domains {
			if d == wildcard {
				return true
			}
		}
	}
	return false
}

// Known reports whether a token exists at all (for 401 vs 403 distinction).
func (a *Authz) Known(token string) bool {
	_, ok := a.tokens[token]
	return ok
}
