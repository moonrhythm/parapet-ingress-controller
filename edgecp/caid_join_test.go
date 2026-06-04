package edgecp

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/caid"
)

// The whole force-re-mint convergence check (edge live ca_id == CP target) rests on a
// single equality: the ca_id the CP computes over its served bundle (caid.FromPEM /
// signer.CAID) must equal what the edge computes from its leaf chain's CA blocks
// (caid.FromDER over Certificate[1:]). Pin it for BOTH a single CA and an OLD++NEW
// overlap — a change to how Sign() appends the bundle would silently break convergence.
func TestCAIDJoinKey(t *testing.T) {
	t.Run("single-CA", func(t *testing.T) {
		certPEM, keyPEM := mustGenerateCA(t)
		sg, _, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		assertJoin(t, sg)
	})
	t.Run("OLD++NEW-overlap", func(t *testing.T) {
		oldCert, oldKey := mustGenerateCA(t)
		newCert, _ := mustGenerateCA(t)
		bundle := append(append([]byte(nil), oldCert...), newCert...)
		sg, _, err := NewProvidedSignerActive(bundle, oldKey, fpOf(t, oldCert), time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		assertJoin(t, sg)
	})
}

func assertJoin(t *testing.T, sg *Signer) {
	t.Helper()
	chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	// Decode the chain into ordered DERs; [1:] are the CA blocks the edge fingerprints.
	var ders [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	if len(ders) < 2 {
		t.Fatalf("chain must be leaf + >=1 CA, got %d certs", len(ders))
	}
	edgeID, err := caid.FromDER(ders[1:])
	if err != nil {
		t.Fatal(err)
	}
	cpFromPEM, err := caid.FromPEM(sg.BundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	if edgeID != cpFromPEM || edgeID != sg.CAID() {
		t.Errorf("ca_id join broken: edge(FromDER)=%q  cp(FromPEM)=%q  signer.CAID=%q", edgeID, cpFromPEM, sg.CAID())
	}
}
