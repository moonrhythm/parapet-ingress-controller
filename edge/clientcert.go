package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync/atomic"
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
	return nil
}

// Loaded reports whether a client cert has ever been installed (readiness gate when
// EDGE_DATAPLANE_MTLS is on).
func (s *ClientCertStore) Loaded() bool { return s.cur.Load() != nil }
