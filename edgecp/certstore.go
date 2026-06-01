// Package edgecp implements the edge control plane: an in-cluster HTTPS REST
// service that distributes, per edge, the TLS cert+key and (Phase 2) WAF rules
// for the domains that edge is authorized to serve. See ../EDGE.md.
package edgecp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"sync"
	"sync/atomic"
)

// certEntry is the material served for one TLS secret: the raw PEM the edge
// installs verbatim, plus a strong ETag for cache revalidation. We keep the raw
// PEM (unlike go/cert.Table, which retains only the parsed *tls.Certificate)
// because the edge needs both chain and key bytes to terminate TLS locally.
type certEntry struct {
	chainPEM []byte
	keyPEM   []byte
	etag     string
}

// CertStore is an SNI-indexed, hot-swappable view of the cluster's TLS secrets.
// Lookups do exact match then a single-label wildcard climb, matching
// go/cert.Table.Get and the Rust cert::Table so all three agree on coverage.
type CertStore struct {
	mu     sync.RWMutex
	byName map[string]*certEntry // SAN (lowercased) -> entry
	// loaded flips true after the first Set (the reloader's initial cluster list
	// completed), so the control plane can report readiness via /healthz?ready=1.
	loaded atomic.Bool
}

func NewCertStore() *CertStore {
	return &CertStore{byName: map[string]*certEntry{}}
}

// Loaded reports whether the store has completed at least one load (readiness).
func (s *CertStore) Loaded() bool { return s.loaded.Load() }

// Set atomically rebuilds the index from (chainPEM, keyPEM) pairs. A pair whose
// leaf can't be parsed, or that carries no SAN dNSNames, is skipped (the leaf is
// what we index by; CN is intentionally ignored, matching the controller).
func (s *CertStore) Set(pairs []PEMPair) {
	byName := make(map[string]*certEntry, len(pairs))
	for _, p := range pairs {
		names := sanDNSNames(p.ChainPEM)
		if len(names) == 0 {
			continue
		}
		e := &certEntry{
			chainPEM: p.ChainPEM,
			keyPEM:   p.KeyPEM,
			etag:     etagOf(p.ChainPEM, p.KeyPEM),
		}
		for _, n := range names {
			byName[strings.ToLower(n)] = e
		}
	}
	s.mu.Lock()
	s.byName = byName
	s.mu.Unlock()
	s.loaded.Store(true)
}

// Get resolves an SNI to its cert material: exact, then single-label wildcard.
func (s *CertStore) Get(sni string) (*certEntry, bool) {
	name := strings.ToLower(strings.TrimSuffix(sni, "."))
	if name == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.byName[name]; ok {
		return e, true
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		if e, ok := s.byName["*"+name[i:]]; ok {
			return e, true
		}
	}
	return nil, false
}

// PEMPair is one TLS secret's raw bytes (tls.crt is a leaf-first fullchain).
type PEMPair struct {
	ChainPEM []byte
	KeyPEM   []byte
}

// sanDNSNames extracts the leaf certificate's SAN dNSNames from a fullchain PEM.
// The leaf is the first CERTIFICATE block; skip any non-cert blocks before it.
func sanDNSNames(chainPEM []byte) []string {
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return leaf.DNSNames
	}
}

// etagOf is a strong validator over the exact bytes served, so any rotation of
// either chain or key changes it and the edge refetches.
func etagOf(chainPEM, keyPEM []byte) string {
	h := sha256.New()
	h.Write(chainPEM)
	h.Write([]byte{0})
	h.Write(keyPEM)
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}
