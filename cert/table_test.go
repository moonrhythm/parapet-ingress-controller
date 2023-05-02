package cert

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTable(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		table := Table{}
		cert, err := table.Get(&tls.ClientHelloInfo{
			ServerName: "example.com",
		})
		assert.NoError(t, err)
		assert.Nil(t, cert)
	})

	t.Run("Exact", func(t *testing.T) {
		table := Table{}
		certs := []*tls.Certificate{
			{
				Leaf: &x509.Certificate{
					DNSNames: []string{
						"example.com",
					},
				},
			},
			{
				Leaf: &x509.Certificate{
					DNSNames: []string{
						"*.example.com",
					},
				},
			},
		}
		table.Set(certs)
		cert, err := table.Get(&tls.ClientHelloInfo{
			ServerName:        "example.com",
			SupportedVersions: []uint16{tls.VersionTLS13},
		})
		assert.NoError(t, err)
		if assert.NotNil(t, cert) {
			assert.Equal(t, certs[0], cert)
		}
	})

	t.Run("Wildcard", func(t *testing.T) {
		table := Table{}
		certs := []*tls.Certificate{
			{
				Leaf: &x509.Certificate{
					DNSNames: []string{
						"example.com",
					},
				},
			},
			{
				Leaf: &x509.Certificate{
					DNSNames: []string{
						"*.example.com",
					},
				},
			},
		}
		table.Set(certs)
		cert, err := table.Get(&tls.ClientHelloInfo{
			ServerName:        "www.example.com",
			SupportedVersions: []uint16{tls.VersionTLS13},
		})
		assert.NoError(t, err)
		if assert.NotNil(t, cert) {
			assert.Equal(t, certs[1], cert)
		}
	})
}
