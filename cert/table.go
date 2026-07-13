package cert

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
)

type Table struct {
	mu                sync.RWMutex
	nameToCertificate map[string][]*tls.Certificate
}

func (t *Table) Set(certs []*tls.Certificate) {
	nameToCert := buildNameToCertificate(certs)

	t.mu.Lock()
	t.nameToCertificate = nameToCert
	t.mu.Unlock()
}

func (t *Table) Get(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// from tls/common.go

	t.mu.RLock()
	certs := t.nameToCertificate
	t.mu.RUnlock()

	// RFC 6066 forbids a trailing dot in SNI, but some non-compliant clients
	// send one anyway; trim it so "example.com." still matches the SAN
	// "example.com".
	name := strings.TrimSuffix(strings.ToLower(clientHello.ServerName), ".")

	// exact name
	if cert, ok := certs[name]; ok {
		c := findSupportCert(cert, clientHello)
		if c != nil {
			return c, nil
		}
	}

	// wildcard name: replace the leftmost label with "*", e.g.
	// www.example.com -> *.example.com. TLS wildcards match exactly one label,
	// so only the first label is replaced.
	if i := strings.IndexByte(name, '.'); i >= 0 {
		wildcardName := "*" + name[i:]
		if cert, ok := certs[wildcardName]; ok {
			return findSupportCert(cert, clientHello), nil
		}
	}

	return nil, nil
}

func findSupportCert(certs []*tls.Certificate, clientHello *tls.ClientHelloInfo) *tls.Certificate {
	for _, cert := range certs {
		err := clientHello.SupportsCertificate(cert)
		if err == nil {
			return cert
		}
	}
	return nil
}

func buildNameToCertificate(certs []*tls.Certificate) map[string][]*tls.Certificate {
	m := make(map[string][]*tls.Certificate, len(certs))
	for _, cert := range certs {
		var err error
		x509Cert := cert.Leaf
		if x509Cert == nil {
			x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}
			// cache the parsed leaf so SupportsCertificate (called per TLS
			// handshake in findSupportCert) doesn't re-parse the DER each time
			cert.Leaf = x509Cert
		}
		// use only SAN, CN already deprecated
		for _, san := range x509Cert.DNSNames {
			m[san] = append(m[san], cert)
		}
	}
	return m
}
