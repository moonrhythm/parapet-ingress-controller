package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet-ingress-controller/trustcidr"
	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
)

// buildWAFValidatedProxy resolves the WAF_VALIDATED_PROXY spec into the
// WAFConfig.SkipValidated predicate: requests it matches arrive from a hop that
// already ran the same global+zone WAF (the edge proxy), so the core skips
// re-evaluating them. Matching requires BOTH the per-request claim header the
// edge stamps after evaluating (wafclaim.Header) AND the peer matching the
// spec — a comma-separated list of:
//
//	edge-mtls     the peer presented a client cert chaining to the live edge CA
//	              (requires edge auto-trust, EDGE_TRUST_CP_ENDPOINT) — the
//	              cryptographic option for the TLS edge→core hop
//	CIDRs/groups  the immediate TCP peer is in the listed CIDRs / named groups
//	              (the trustcidr spec language) — for the plaintext hop; only as
//	              strong as network reachability into those ranges
//
// "" / "false" disable the skip (nil predicate — the core evaluates everything,
// the default posture). "true" is refused — as the whole spec and as a list
// token — because a blanket skip is WAF_ENABLED=false with extra steps, never a
// per-peer judgement ("false" is likewise refused inside a list, where it can
// only be a mistake). An invalid CIDR panics inside trustcidr (same fail-fast
// as TRUST_PROXY), so a typo'd token can't silently drop coverage.
//
// verifyEdgeCert is trust.Manager.VerifyClientCert (nil when edge auto-trust is
// off, which makes edge-mtls a fatal misconfiguration rather than a predicate
// that never matches).
func buildWAFValidatedProxy(spec string, verifyEdgeCert func(*tls.ConnectionState) bool) (func(*http.Request) bool, error) {
	switch strings.TrimSpace(spec) {
	case "", "false":
		return nil, nil
	case "true":
		return nil, errors.New("WAF_VALIDATED_PROXY=true would skip the WAF for ALL traffic; list the validating hops explicitly (edge-mtls and/or CIDRs), or set WAF_ENABLED=false")
	}

	useMTLS := false
	var cidrs []string
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch tok {
		case "":
			continue
		case "edge-mtls":
			if verifyEdgeCert == nil {
				return nil, errors.New("WAF_VALIDATED_PROXY: edge-mtls requires edge auto-trust (set EDGE_TRUST_CP_ENDPOINT)")
			}
			useMTLS = true
		case "true", "false":
			// Refused as list tokens too, not just as the whole spec: a lone
			// surviving "true" token would otherwise be rejoined into exactly
			// "true" below and hit trustcidr.Parse's whole-spec special case —
			// parapet.Trusted(), a match-everything predicate — turning a
			// one-character typo ("true,") into a silent blanket WAF skip.
			return nil, fmt.Errorf("WAF_VALIDATED_PROXY: %q is not a valid list entry", tok)
		default:
			cidrs = append(cidrs, tok)
		}
	}

	cidrMatch := trustcidr.Parse(strings.Join(cidrs, ","))
	var peer func(*http.Request) bool
	switch {
	case useMTLS && cidrMatch != nil:
		peer = func(r *http.Request) bool {
			return verifyEdgeCert(r.TLS) || cidrMatch(r)
		}
	case useMTLS:
		peer = func(r *http.Request) bool {
			return verifyEdgeCert(r.TLS)
		}
	case cidrMatch != nil:
		peer = cidrMatch
	default:
		return nil, nil // separator-only spec: zero tokens, same as ""
	}
	// Peer trust alone is not enough: the edge must also have CLAIMED the
	// validation per request (wafclaim.Header, stamped after its WAF evaluated
	// the request, only once a CP snapshot landed). This is what lets the core
	// tell apart an edge with EDGE_WAF_ENABLED=false, or one still on its empty
	// boot ruleset — their requests carry no claim and get the full WAF here.
	// Claim first: a cheap header miss short-circuits before the cert verify
	// for all non-edge traffic.
	return func(r *http.Request) bool {
		return r.Header.Get(wafclaim.Header) != "" && peer(r)
	}, nil
}
