package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("ExactTrailingDot", func(t *testing.T) {
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
		// RFC 6066 forbids a trailing dot, but non-compliant clients send one;
		// it must still resolve the exact SAN.
		cert, err := table.Get(&tls.ClientHelloInfo{
			ServerName:        "example.com.",
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

	t.Run("WildcardTrailingDot", func(t *testing.T) {
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
			ServerName:        "www.example.com.",
			SupportedVersions: []uint16{tls.VersionTLS13},
		})
		assert.NoError(t, err)
		if assert.NotNil(t, cert) {
			assert.Equal(t, certs[1], cert)
		}
	})
}

func TestTableRealCertificate(t *testing.T) {
	t.Parallel()

	// a real cert with Leaf left nil, so Set must parse Certificate[0]
	der := genCertDER(t, "secure.example.com", "*.wild.example.com")
	cert := &tls.Certificate{Certificate: [][]byte{der}}

	table := Table{}
	table.Set([]*tls.Certificate{cert})

	// Set caches the parsed leaf so SupportsCertificate doesn't re-parse per handshake
	assert.NotNil(t, cert.Leaf)

	hello := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: name, SupportedVersions: []uint16{tls.VersionTLS13}}
	}

	t.Run("exact SAN", func(t *testing.T) {
		got, err := table.Get(hello("secure.example.com"))
		assert.NoError(t, err)
		assert.Same(t, cert, got)
	})

	t.Run("wildcard SAN", func(t *testing.T) {
		got, err := table.Get(hello("foo.wild.example.com"))
		assert.NoError(t, err)
		assert.Same(t, cert, got)
	})

	t.Run("no match", func(t *testing.T) {
		got, err := table.Get(hello("other.example.com"))
		assert.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("single-label name does not panic", func(t *testing.T) {
		got, err := table.Get(hello("localhost"))
		assert.NoError(t, err)
		assert.Nil(t, got)
	})
}

func genCertDER(t testing.TB, dnsNames ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func BenchmarkGetWildcard(b *testing.B) {
	// mirror a production cert: Leaf is pre-populated (as tls.X509KeyPair does),
	// so this measures the wildcard-name lookup, not x509 re-parsing.
	der := genCertDER(b, "*.bench.example.com")
	leaf, err := x509.ParseCertificate(der)
	require.NoError(b, err)
	table := Table{}
	table.Set([]*tls.Certificate{{Certificate: [][]byte{der}, Leaf: leaf}})
	hello := &tls.ClientHelloInfo{
		ServerName:        "host.bench.example.com",
		SupportedVersions: []uint16{tls.VersionTLS13},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Get(hello)
	}
}
