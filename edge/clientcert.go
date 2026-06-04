package edge

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/caid"
)

// ClientCertStore holds the edge's data-plane mTLS client certificate in memory
// (never on disk) and serves it to the upstream TLS handshake via
// GetClientCertificate. The leaf private key is generated on the edge and never
// leaves it; only the public-key CSR and the returned chain transit the control
// plane. Update is all-or-nothing: a bad/mismatched chain keeps the prior pair, so
// the edge degrades but never presents a broken cert. See EDGE-AUTOTRUST.md
// "Edge wiring".
type ClientCertStore struct {
	cur atomic.Pointer[tls.Certificate]
	// caid is the ca_id of the CA set that issued the LIVE leaf (== the
	// edge_clientcert_ca_id gauge). It is the AUTHORITATIVE held value the force-re-mint
	// observer compares the CP target against; correct after a fail-static (it tracks
	// the cert actually in use, not a failed attempt).
	caid atomic.Pointer[string]
	// signerFP is the fingerprint of the CA in the chain that SIGNED the live leaf (OLD
	// vs NEW during an overlap). The ca_id is identical for active=OLD/NEW, so this is
	// the load-bearing signal that the leaf chains to NEW and survives the OLD-drop. ""
	// when the issuer can't be uniquely resolved (fail-closed at the interlock).
	signerFP atomic.Pointer[string]
}

func NewClientCertStore() *ClientCertStore { return &ClientCertStore{} }

// GetClientCertificate returns the live client cert for the upstream handshake, or
// an empty certificate (present no client cert) when none has loaded yet — so a
// pre-issuance edge handshakes anonymously and is simply untrusted (the core's
// VerifyClientCertIfGiven accepts no-cert), never failing the connection.
func (s *ClientCertStore) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c := s.cur.Load(); c != nil {
		return c, nil
	}
	return &tls.Certificate{}, nil
}

// Update pairs the CP-returned chain with the in-memory key and atomically swaps in
// the complete cert. On any parse/validation failure it keeps the prior pair and
// returns an error (the caller fail-statics). It never swaps in a half/broken cert.
func (s *ClientCertStore) Update(chainPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("client cert pair: %w", err)
	}
	// Parse the leaf so callers can read NotAfter (renewal) and the chain is sound.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			cert.Leaf = leaf
		}
	}
	s.cur.Store(&cert)

	// Convergence metric: derive the issuing CA-set ca_id from the chain's CA blocks
	// (Certificate[1:], the bundle Sign() appended after the leaf) — byte-identical to
	// the CP's CAID for the same set. Guard a too-short chain and a nil leaf so the
	// metric never panics the refresh goroutine.
	var caID string
	if len(cert.Certificate) >= 2 {
		caID, _ = caid.FromDER(cert.Certificate[1:])
	}
	s.caid.Store(&caID) // store even when "" (single-CA chain / too-short)
	// Derive the ISSUER fp: which CA in the chain SIGNED this leaf. This is what proves
	// the leaf chains to NEW (vs OLD) during an overlap — the ca_id can't, since both
	// append the same bundle. Republished on every successful Update, never cached.
	signerFP := deriveIssuerFP(cert.Leaf, cert.Certificate)
	s.signerFP.Store(&signerFP)
	var notAfter int64
	if cert.Leaf != nil {
		notAfter = cert.Leaf.NotAfter.Unix()
	}
	setClientCertMetrics(caID, signerFP, notAfter)
	return nil
}

// Loaded reports whether a client cert has ever been installed (readiness gate when
// EDGE_DATAPLANE_MTLS is on).
func (s *ClientCertStore) Loaded() bool { return s.cur.Load() != nil }

// CAID returns the ca_id of the CA set that issued the LIVE leaf, or "" if none is
// held yet (or the chain is too short to carry a CA block). This is the held-vs-target
// convergence comparison's authoritative "live" side.
func (s *ClientCertStore) CAID() string {
	if p := s.caid.Load(); p != nil {
		return *p
	}
	return ""
}

// SignerFP returns the fingerprint of the CA that signed the live leaf, or "" if it
// can't be uniquely resolved. The interlock requires it == the target (NEW) before the
// OLD-drop, proving the leaf survives.
func (s *ClientCertStore) SignerFP() string {
	if p := s.signerFP.Load(); p != nil {
		return *p
	}
	return ""
}

// deriveIssuerFP returns the SHA-256 (hex) of the CA cert in the chain (Certificate[1:])
// that SIGNED the leaf, matching the CP's active-signer fp (sha256 of the same CA DER).
// It matches by AuthorityKeyId == SubjectKeyId; falls back to a signature check; and
// REQUIRES EXACTLY ONE match (a 2-cert overlap bundle is order-dependent, so first-match
// is unsafe — it could false-RED a NEW-signed leaf or false-GREEN an OLD-signed one).
// Returns "" on no/ambiguous match (fail-closed: the interlock blocks on "").
func deriveIssuerFP(leaf *x509.Certificate, chain [][]byte) string {
	if leaf == nil || len(chain) < 2 {
		return ""
	}
	caDERs := chain[1:]
	cas := make([]*x509.Certificate, 0, len(caDERs))
	for _, der := range caDERs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return ""
		}
		cas = append(cas, c)
	}
	match := -1
	if len(leaf.AuthorityKeyId) > 0 {
		for i, c := range cas {
			if bytes.Equal(c.SubjectKeyId, leaf.AuthorityKeyId) {
				if match >= 0 {
					return "" // ambiguous (duplicate SKID)
				}
				match = i
			}
		}
	}
	if match < 0 { // fail-soft fallback: which CA actually verifies the leaf signature?
		for i, c := range cas {
			if leaf.CheckSignatureFrom(c) == nil {
				if match >= 0 {
					return ""
				}
				match = i
			}
		}
	}
	if match < 0 {
		return ""
	}
	sum := sha256.Sum256(caDERs[match])
	return hex.EncodeToString(sum[:])
}

// Validity returns the live leaf's NotBefore/NotAfter for remaining-life renewal (the
// renewal threshold is a fraction of the cert's OWN lifetime, so it needs no knowledge
// of the CP's configured TTL). ok=false when no cert is held or the leaf didn't parse.
func (s *ClientCertStore) Validity() (notBefore, notAfter time.Time, ok bool) {
	c := s.cur.Load()
	if c == nil || c.Leaf == nil {
		return time.Time{}, time.Time{}, false
	}
	return c.Leaf.NotBefore, c.Leaf.NotAfter, true
}
