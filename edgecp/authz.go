package edgecp

import (
	"strings"
)

// Entry is one edge's registry record: its data-plane identity (id, stamped into
// the leaf SAN for audit/WAF-zone attribution — never load-bearing for trust under
// the CA-only model), the domains it may fetch certs/WAF for, and a disabled
// tombstone. A disabled (or absent) entry is treated as UNKNOWN everywhere — a full
// lockout (no mint, no /v1/certs, no /v1/waf). Blacklisting (disabled:true) stops
// FUTURE minting only; the already-minted leaf is revoked by CA rotation. See
// EDGE-AUTOTRUST.md "Revocation = CA rotation".
type Entry struct {
	ID       string
	Domains  []string
	Disabled bool
}

// Authz maps a per-edge bearer token to its registry Entry. Deny by default; a
// disabled or unknown token is denied identically (callers distinguish only
// 401 vs 403 via Known/Allowed, never disabled-vs-absent).
type Authz struct {
	entries map[string]Entry
}

// NewAuthz builds the table from the legacy token→domains shape (no id, never
// disabled). Retained for the existing cert/WAF distribution path and tests.
func NewAuthz(tokens map[string][]string) *Authz {
	entries := make(map[string]Entry, len(tokens))
	for tok, domains := range tokens {
		entries[tok] = Entry{Domains: normalizeDomains(domains)}
	}
	return NewAuthzEntries(entries)
}

// NewAuthzEntries builds the table from the richer registry shape
// ({id, domains, disabled}). Domains are lowercased/trimmed; the id is
// lowercased/trimmed for canonical SAN derivation.
func NewAuthzEntries(entries map[string]Entry) *Authz {
	t := make(map[string]Entry, len(entries))
	for tok, e := range entries {
		t[tok] = Entry{
			ID:       strings.ToLower(strings.TrimSpace(e.ID)),
			Domains:  normalizeDomains(e.Domains),
			Disabled: e.Disabled,
		}
	}
	return &Authz{entries: t}
}

func normalizeDomains(domains []string) []string {
	ds := make([]string, 0, len(domains))
	for _, d := range domains {
		ds = append(ds, strings.ToLower(strings.TrimSpace(d)))
	}
	return ds
}

// lookup is the single chokepoint: a missing OR disabled token is "not found", so
// Known/Allowed/Identity all treat a blacklisted edge as fully locked out.
func (a *Authz) lookup(token string) (Entry, bool) {
	e, ok := a.entries[token]
	if !ok || e.Disabled {
		return Entry{}, false
	}
	return e, true
}

// Known reports whether the token exists and is not disabled (for 401-vs-403).
func (a *Authz) Known(token string) bool {
	_, ok := a.lookup(token)
	return ok
}

// Allowed reports whether the token is known (non-disabled) and authorized for
// host. Matching mirrors cert.Table: exact, single-label wildcard, plus a bare "*"
// catch-all that authorizes every host.
func (a *Authz) Allowed(token, host string) bool {
	e, ok := a.lookup(token)
	if !ok {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "" {
		return false
	}
	for _, d := range e.Domains {
		if d == "*" || d == name {
			return true
		}
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		wildcard := "*" + name[i:]
		for _, d := range e.Domains {
			if d == wildcard {
				return true
			}
		}
	}
	return false
}

// Identity returns the token's edge id (for SAN stamping on /v1/edge-cert). It
// returns ok=false for an unknown/disabled token, or one with no id grant — so a
// token without an explicit identity cannot mint a data-plane leaf (403).
func (a *Authz) Identity(token string) (string, bool) {
	e, ok := a.lookup(token)
	if !ok || e.ID == "" {
		return "", false
	}
	return e.ID, true
}
