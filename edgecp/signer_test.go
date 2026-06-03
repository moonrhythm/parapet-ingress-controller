package edgecp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"
)

// fpOf returns the SHA-256 (hex) of the FIRST CERTIFICATE block in certPEM — the
// fingerprint NewProvidedSignerActive pins the active cert to.
func fpOf(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func mkLeafKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifiesUnder reports whether the leaf chain verifies against a pool of exactly
// the given CA cert(s) — the signed-under-which-key probe.
func verifiesUnder(t *testing.T, chainPEM []byte, cas ...[]byte) bool {
	t.Helper()
	leaf, inter := parseChain(t, chainPEM)
	roots := x509.NewCertPool()
	for _, ca := range cas {
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("append CA")
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

func TestSignerActiveKeySelectionNew(t *testing.T) {
	oldCert, _ := mustGenerateCA(t)
	newCert, newKey := mustGenerateCA(t)
	bundle := append(append([]byte(nil), oldCert...), newCert...)

	sg, warnings, err := NewProvidedSignerActive(bundle, newKey, fpOf(t, newCert), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("clean CA should warn nothing, got %v", warnings)
	}
	// BundlePEM serves BOTH certs.
	if _, n, _ := reencodeCertBundle(sg.BundlePEM()); n != 2 {
		t.Errorf("bundle should hold 2 certs, got %d", n)
	}

	chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	// Signed under NEW: verifies against NEW alone, NOT against OLD alone.
	if !verifiesUnder(t, chainPEM, newCert) {
		t.Error("leaf must verify under the NEW (active) CA")
	}
	if verifiesUnder(t, chainPEM, oldCert) {
		t.Error("leaf must NOT verify under OLD when NEW is active")
	}
}

func TestSignerActiveKeySelectionOld(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	newCert, _ := mustGenerateCA(t)
	bundle := append(append([]byte(nil), oldCert...), newCert...)

	sg, _, err := NewProvidedSignerActive(bundle, oldKey, fpOf(t, oldCert), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verifiesUnder(t, chainPEM, oldCert) {
		t.Error("leaf must verify under the OLD (active) CA")
	}
	// And of course it verifies against the full OLD++NEW bundle the core trusts.
	if !verifiesUnder(t, chainPEM, oldCert, newCert) {
		t.Error("leaf must verify under the full bundle")
	}
}

func TestSignerActiveKeyNoMatch(t *testing.T) {
	oldCert, _ := mustGenerateCA(t)
	newCert, _ := mustGenerateCA(t)
	_, strayKey := mustGenerateCA(t) // a key for neither cert in the bundle
	bundle := append(append([]byte(nil), oldCert...), newCert...)

	if _, _, err := NewProvidedSignerActive(bundle, strayKey, "", time.Hour, time.Minute); err == nil {
		t.Error("a key matching no cert in the bundle must error, not silently pick block[0]")
	}
}

func TestSignerActiveKeyAmbiguous(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	// The same cert twice → two key-matching blocks → ambiguous.
	bundle := append(append([]byte(nil), oldCert...), oldCert...)
	if _, _, err := NewProvidedSignerActive(bundle, oldKey, "", time.Hour, time.Minute); err == nil {
		t.Error("a key matching more than one block must error (ambiguous active cert)")
	}
}

func TestSignerSelfVerifyFailsClosed(t *testing.T) {
	// Hand-build a broken Signer: active cert = OLD, but the signing key = NEW, and
	// the served bundle is OLD-only (NEW not in it). The minted leaf is signed by NEW
	// and cannot chain to the OLD-only bundle → Sign must fail closed.
	oldCert, _ := mustGenerateCA(t)
	_, newKey := mustGenerateCA(t)
	caCert, err := parseCACert(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, err := parsePrivateKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(oldCert)
	sg := &Signer{
		caCert:     caCert,
		caKey:      newSigner,
		bundle:     oldCert,
		bundlePool: pool,
		caID:       "broken",
		ttl:        time.Hour,
		skew:       time.Minute,
	}
	if _, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1"); err == nil {
		t.Error("Sign must fail closed when the minted leaf can't chain to the served bundle")
	}
}

func TestSignerBackCompatSingleCert(t *testing.T) {
	certPEM, keyPEM := mustGenerateCA(t)
	sg, warnings, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("single-cert path: err=%v warnings=%v", err, warnings)
	}
	if _, n, _ := reencodeCertBundle(sg.BundlePEM()); n != 1 {
		t.Errorf("single-cert bundle should hold 1 cert, got %d", n)
	}
	chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verifiesUnder(t, chainPEM, certPEM) {
		t.Error("leaf must verify under the single CA")
	}
}
