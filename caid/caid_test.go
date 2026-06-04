package caid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func mkCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

// FromPEM(pem) and FromDER(der) MUST agree for the same cert set — this is what lets
// the CP (FromPEM over the bundle) and the edge (FromDER over its chain's CA blocks)
// derive a byte-identical ca_id.
func TestFromPEMEqualsFromDER(t *testing.T) {
	d1 := mkCertDER(t, "old")
	d2 := mkCertDER(t, "new")

	idPEM, err := FromPEM(pemOf(d1, d2))
	if err != nil {
		t.Fatal(err)
	}
	idDER, err := FromDER([][]byte{d1, d2})
	if err != nil {
		t.Fatal(err)
	}
	if idPEM != idDER {
		t.Errorf("FromPEM=%q != FromDER=%q", idPEM, idDER)
	}
}

// The id reflects the trusted SET, not the ordering (OLD++NEW == NEW++OLD).
func TestOrderIndependent(t *testing.T) {
	d1 := mkCertDER(t, "a")
	d2 := mkCertDER(t, "b")
	ab, _ := FromDER([][]byte{d1, d2})
	ba, _ := FromDER([][]byte{d2, d1})
	if ab != ba {
		t.Errorf("order changed the id: %q vs %q", ab, ba)
	}
	// A different set yields a different id.
	single, _ := FromDER([][]byte{d1})
	if single == ab {
		t.Error("single-cert id collided with the two-cert set id")
	}
}

func TestEmptyIsError(t *testing.T) {
	if _, err := FromDER(nil); err == nil {
		t.Error("FromDER(nil) must error")
	}
	if _, err := FromPEM([]byte("not a pem")); err == nil {
		t.Error("FromPEM with no CERTIFICATE blocks must error")
	}
}
