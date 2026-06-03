package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestTrustBundleSnapshotCoherentUnderRace hammers SetSigner with two distinct CAs
// while many concurrent GET /v1/trust-bundle requests read the bundle. The
// (generation, ca_pem) pair must be coherent: a given generation must always map to
// the same ca_id, and ca_id must always equal the fingerprint of the served ca_pem.
// A torn read (separate signer + gen atomics) would let one generation report two
// different bundles.
func TestTrustBundleSnapshotCoherentUnderRace(t *testing.T) {
	certA, keyA := mustGenerateCA(t)
	certB, keyB := mustGenerateCA(t)
	sgA, _, err := NewProvidedSigner(certA, keyA, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sgB, _, err := NewProvidedSigner(certB, keyB, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	srv.SetSigner(sgA)
	h := srv.Handler()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: alternate the active signer as fast as it can.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				srv.SetSigner(sgA)
			} else {
				srv.SetSigner(sgB)
			}
		}
	}()

	var mu sync.Mutex
	genToCAID := map[uint64]string{}
	fail := ""

	// Readers: pull the bundle and check coherence.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/trust-bundle", nil))
				if rec.Code != http.StatusOK {
					continue
				}
				var resp trustBundleResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					mu.Lock()
					fail = "decode: " + err.Error()
					mu.Unlock()
					return
				}
				// ca_id must be the fingerprint of the served ca_pem.
				gotID, err := caBundleID([]byte(resp.CAPEM))
				if err != nil || gotID != resp.CAID {
					mu.Lock()
					fail = "ca_id does not match ca_pem (torn snapshot)"
					mu.Unlock()
					return
				}
				// A generation must never map to two different bundles.
				mu.Lock()
				if prev, ok := genToCAID[resp.Generation]; ok && prev != resp.CAID {
					fail = "generation maps to two ca_ids (torn snapshot)"
				} else {
					genToCAID[resp.Generation] = resp.CAID
				}
				mu.Unlock()
			}
		}()
	}

	// Let readers run, then stop the writer and drain.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if fail != "" {
		t.Fatal(fail)
	}
}
