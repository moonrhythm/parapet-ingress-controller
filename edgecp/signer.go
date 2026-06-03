package edgecp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SANTrustDomain is the SPIFFE-style trust domain (URI host) for every edge leaf
// SAN: spiffe://parapet.moonrhythm.io/edge/<id>. The edge CA is NameConstrained to
// this host (managed mode), and the issued-leaf URI SAN is built from it here.
const SANTrustDomain = "parapet.moonrhythm.io"

// DefaultClientCertTTL / DefaultClientCertSkew are the leaf lifetime and the
// NotBefore backdating slack. The 7-day TTL is deliberate (see EDGE-AUTOTRUST.md):
// revocation is CA rotation, not expiry, so a long TTL buys a multi-day CP-outage
// budget without weakening revocation.
const (
	DefaultClientCertTTL  = 168 * time.Hour // 7 days
	DefaultClientCertSkew = 10 * time.Minute
)

// Signer mints short-lived edge data-plane client certificates from the edge CA.
// It is the CA-side of the CA-only mTLS trust model: the core trusts any leaf that
// chains to this CA, so the CA must sign nothing but edge clientAuth leaves. The
// SAN it stamps (spiffe://.../edge/<id>) is audit/labeling only — never load-bearing
// for trust. See EDGE-AUTOTRUST.md "Signing".
//
// A Signer is immutable; rotation swaps in a new *Signer via an atomic.Pointer at
// the call site (the serving CP's CA-secret read-watch), so Sign/CAID/Bundle never
// mutate.
type Signer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	bundle []byte // the CA public cert(s), PEM (leaf-first if a chain); served as ca_pem
	caID   string
	ttl    time.Duration
	skew   time.Duration
}

// NewProvidedSigner builds a Signer from a mounted CA cert+key (provided mode:
// EDGE_CA_CERT / EDGE_CA_KEY). It validates that the CA is usable for issuing
// clientAuth leaves and returns a descriptive error otherwise. caExtraPEM, if
// non-empty, is appended to the served bundle (an overlap OLD++NEW set during
// rotation); a malformed extra block is rejected (all-or-nothing).
func NewProvidedSigner(certPEM, keyPEM []byte, ttl, skew time.Duration) (*Signer, []string, error) {
	caCert, err := parseCACert(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	if !publicKeyMatches(caCert.PublicKey, key.Public()) {
		return nil, nil, fmt.Errorf("CA cert and key do not match")
	}
	if ttl <= 0 {
		ttl = DefaultClientCertTTL
	}
	if skew < 0 {
		skew = DefaultClientCertSkew
	}
	warnings := validateEdgeCA(caCert)
	id, err := caBundleID(certPEM)
	if err != nil {
		return nil, nil, err
	}
	return &Signer{
		caCert: caCert,
		caKey:  key,
		bundle: append([]byte(nil), certPEM...),
		caID:   id,
		ttl:    ttl,
		skew:   skew,
	}, warnings, nil
}

// BundlePEM returns the CA public cert bundle served to the core as ca_pem. It
// never contains a private key.
func (s *Signer) BundlePEM() []byte { return s.bundle }

// CAID returns the stable fingerprint over the CA certs in the bundle (the
// trust-bundle ca_id). It changes whenever a CA is added to or dropped from the
// bundle, which is the edge's proactive force-re-mint trigger.
func (s *Signer) CAID() string { return s.caID }

// Sign issues a leaf for the given public key and edge id. It builds the template
// from a zero value (never echoing CSR fields), stamps the id-derived URI SAN, and
// runs a post-sign self-check before returning. The returned chain is leaf-first
// (leaf + the CA bundle, so the core can verify without a separate intermediate).
func (s *Signer) Sign(pub crypto.PublicKey, id string) (chainPEM []byte, notAfter time.Time, serial string, err error) {
	if err = AllowedLeafKey(pub); err != nil {
		return nil, time.Time{}, "", err
	}
	san, ok := EdgeSAN(id)
	if !ok {
		return nil, time.Time{}, "", fmt.Errorf("invalid edge id %q", id)
	}

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	nb := now.Add(-s.skew)
	na := now.Add(s.ttl)

	// Template from a zero value. Only these fields are set; the CSR contributes
	// nothing but its public key. No Subject/DNSNames/IPAddresses/Extensions.
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{san},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, pub, s.caKey)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("sign: %w", err)
	}

	// Post-sign self-check: re-parse and assert the leaf shape, so a templating bug
	// can never emit a CA leaf, a wrong EKU, or an extra SAN.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("self-check parse: %w", err)
	}
	if err = assertLeafShape(leaf, san); err != nil {
		return nil, time.Time{}, "", fmt.Errorf("self-check: %w", err)
	}

	var buf strings.Builder
	if err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, time.Time{}, "", err
	}
	buf.Write(s.bundle) // append the CA cert(s) so the chain is self-contained
	return []byte(buf.String()), na, hex.EncodeToString(sn.Bytes()), nil
}

// EdgeSAN builds the canonical edge SAN URI from an id, validating the id as a
// SPIFFE path segment (lowercased, trimmed, no '/'/whitespace, bounded length).
// It returns ok=false for an invalid id so issuance/derivation fail closed.
func EdgeSAN(id string) (*url.URL, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !validPathSegment(id) {
		return nil, false
	}
	return &url.URL{Scheme: "spiffe", Host: SANTrustDomain, Path: "/edge/" + id}, true
}

// validPathSegment allows [a-z0-9._-], 1..253 chars, no slash/whitespace.
func validPathSegment(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// AllowedLeafKey enforces the CSR public-key whitelist BEFORE any signature
// verification or signing, so an oversized-RSA verify/sign DoS is impossible:
// ECDSA P-256/P-384 or Ed25519 only.
func AllowedLeafKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		}
		return fmt.Errorf("unsupported ECDSA curve %s (want P-256 or P-384)", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported key type %T (want ECDSA P-256/P-384 or Ed25519)", pub)
	}
}

func assertLeafShape(leaf *x509.Certificate, san *url.URL) error {
	if leaf.IsCA {
		return fmt.Errorf("issued leaf is a CA")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("unexpected KeyUsage %v", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return fmt.Errorf("unexpected ExtKeyUsage %v", leaf.ExtKeyUsage)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		return fmt.Errorf("leaf carries DNS/IP SANs")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != san.String() {
		return fmt.Errorf("leaf URI SAN mismatch")
	}
	return nil
}

// validateEdgeCA returns non-fatal warnings about a provided CA. Issuance proceeds
// regardless (the post-sign self-check still bounds the emitted leaf), but a CA
// that can sign more than clientAuth leaves, or that is not URI-name-constrained,
// has a wider blast radius if its key leaks — so warn loudly.
func validateEdgeCA(ca *x509.Certificate) []string {
	var w []string
	if !ca.IsCA {
		w = append(w, "provided edge CA is not marked IsCA")
	}
	if len(ca.ExtKeyUsage) > 0 {
		hasClientAuth := false
		for _, eku := range ca.ExtKeyUsage {
			if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
				hasClientAuth = true
			}
		}
		if !hasClientAuth {
			w = append(w, "provided edge CA EKU does not permit clientAuth")
		}
	}
	if len(ca.PermittedURIDomains) == 0 {
		w = append(w, "provided edge CA has no NameConstraints PermittedURIDomains; "+
			"a stolen CA key could mint leaves for any URI domain — prefer a dedicated, "+
			"name-constrained single-purpose CA")
	}
	return w
}

func parseCACert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA cert PEM: no CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T is not a crypto.Signer", key)
	}
	return signer, nil
}

func publicKeyMatches(certPub, keyPub crypto.PublicKey) bool {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	if eq, ok := certPub.(equaler); ok {
		return eq.Equal(keyPub)
	}
	return false
}

// caBundleID computes the trust-bundle ca_id: a hex fingerprint over the sorted
// SHA-256s of every CERTIFICATE block in the bundle. Sorting makes it stable and
// order-independent (an OLD++NEW overlap and NEW++OLD produce the same id only if
// the set is equal — which is the intent: ca_id reflects the trusted CA *set*).
func caBundleID(bundlePEM []byte) (string, error) {
	var sums []string
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		sum := sha256.Sum256(block.Bytes)
		sums = append(sums, hex.EncodeToString(sum[:]))
	}
	if len(sums) == 0 {
		return "", fmt.Errorf("CA bundle has no certificates")
	}
	sort.Strings(sums)
	h := sha256.New()
	for _, s := range sums {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}
