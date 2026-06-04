// Package caid computes the edge-CA trust-bundle id: a stable, order-independent
// fingerprint over a SET of CA certificates. It is the single source of truth shared
// by the control plane (FromPEM, over the served ca_pem bundle) and the edge (FromDER,
// over its client cert's CA chain), so a CP-computed CAID and an edge-computed ca_id
// are byte-identical for the same cert set — the cross-plane join key for convergence.
//
// It is deliberately dependency-light (crypto/sha256, encoding/hex, encoding/pem, sort
// only — no k8s, no prometheus) so the k8s-free edge binary can import it without
// dragging in the control-plane's client-go dependency.
package caid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
)

// FromPEM computes the id over every CERTIFICATE block in bundlePEM. Non-CERTIFICATE
// blocks are skipped. An input with no certificates is an error.
func FromPEM(bundlePEM []byte) (string, error) {
	var ders [][]byte
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
		ders = append(ders, block.Bytes)
	}
	return FromDER(ders)
}

// FromDER computes the id over a set of raw DER certificates (e.g. a tls.Certificate's
// Certificate[1:] CA chain on the edge). It hashes each DER exactly as FromPEM hashes
// its block.Bytes, so FromPEM(pem) == FromDER(der) for the same cert set. The id is the
// truncated SHA-256 over the sorted per-cert SHA-256s, making it order-independent: it
// reflects the trusted CA *set*, not the bundle ordering.
func FromDER(ders [][]byte) (string, error) {
	if len(ders) == 0 {
		return "", fmt.Errorf("caid: no certificates")
	}
	sums := make([]string, 0, len(ders))
	for _, der := range ders {
		sum := sha256.Sum256(der)
		sums = append(sums, hex.EncodeToString(sum[:]))
	}
	sort.Strings(sums)
	h := sha256.New()
	for _, s := range sums {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}
