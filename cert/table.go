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

	name := strings.ToLower(clientHello.ServerName)

	// exact name
	if cert, ok := certs[name]; ok {
		c := findSupportCert(cert, clientHello)
		if c != nil {
			return c, nil
		}
	}

	// wildcard name
	if len(name) > 0 {
		labels := strings.Split(name, ".")
		labels[0] = "*"
		wildcardName := strings.Join(labels, ".")
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
	m := make(map[string][]*tls.Certificate)
	for _, cert := range certs {
		var err error
		x509Cert := cert.Leaf
		if x509Cert == nil {
			x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}
		}
		// use only SAN, CN already deprecated
		for _, san := range x509Cert.DNSNames {
			m[san] = append(m[san], cert)
		}
	}
	return m
}
