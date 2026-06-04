package edgecp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// DefaultCATTL is the lifetime of a CP-generated edge CA. It is long-lived (the CA
// is the trust anchor; the short knob is the leaf EDGE_CLIENTCERT_TTL), but bounded
// well above the expected revoke-driven rotation interval.
const DefaultCATTL = 2 * 365 * 24 * time.Hour // ~2 years

// caGenerationAnnotation marks a CA Secret as populated by EnsureCA. Its presence
// (with empty data) is the anti-regeneration tripwire: a populated CA that was
// later blanked (GitOps prune, restored-empty stub, operator error) MUST NOT be
// regenerated — that would mint a new CA and distrust the whole fleet.
const caGenerationAnnotation = "parapet.moonrhythm.io/edge-ca-generation"

// Rotation annotations + the staged-key field. RotateCA stages a NEW CA alongside
// OLD without dropping OLD or flipping the active key (the non-destructive overlap
// phase). The destructive trim + active flip live in a later step.
const (
	// caRotationPhaseAnnotation records the rotation phase: "overlap" (OLD++NEW both
	// trusted, OLD still active). Later phases ("converged"/"trimmed") are written by
	// the destructive trim step, not here.
	caRotationPhaseAnnotation = "parapet.moonrhythm.io/edge-ca-rotation-phase"
	// caActiveAnnotation records which staged key signs new leaves: "old" (Data
	// tls.key) or "new" (Data tls-new.key). RotateCA only ever writes "old".
	caActiveAnnotation = "parapet.moonrhythm.io/edge-ca-active"

	caPhaseOverlap = "overlap"
	caActiveOld    = "old"
	caActiveNew    = "new"

	// caNewKeyField stages the NEW CA's private key during overlap. tls.key stays the
	// OLD (active) key until the active flip; the serving reloader reads this field
	// when caActiveAnnotation == "new".
	caNewKeyField = "tls-new.key"
)

// SecretRW is the minimal secret read/CAS-write surface EnsureCA needs. It is
// satisfied by the k8s package (cluster backend = real resourceVersion CAS) and by
// a fake in tests.
type SecretRW interface {
	GetSecret(ctx context.Context, namespace, name string) (*v1.Secret, error)
	UpdateSecret(ctx context.Context, namespace string, secret *v1.Secret) (*v1.Secret, error)
}

// GenerateCA mints a dedicated, single-purpose edge CA: ECDSA P-384, IsCA with
// MaxPathLen 0 (signs leaves only), KeyUsage CertSign|CRLSign, EKU clientAuth, and
// NameConstrained to the SPIFFE trust domain so even a stolen CA key can only mint
// edge clientAuth leaves under spiffe://<SANTrustDomain>/…. Returns (certPEM, keyPEM).
func GenerateCA(ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if ttl <= 0 {
		ttl = DefaultCATTL
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca keygen: %w", err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("ca serial: %w", err)
	}
	now := time.Now()
	// Explicit SubjectKeyId (SHA-256 of the SPKI). x509.CreateCertificate copies the
	// issuer's SubjectKeyId into a leaf's AuthorityKeyId, so an overlap leaf carries the
	// SKID of the CA that SIGNED it — the anchor the edge uses to derive the active
	// signer fingerprint (OLD vs NEW). Set it ourselves rather than rely on the stdlib's
	// implicit SHA-1 derivation (asserted non-empty in ca_test).
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ca spki: %w", err)
	}
	skid := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "parapet-edge-ca"},
		SubjectKeyId:          skid[:],
		NotBefore:             now.Add(-DefaultClientCertSkew),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		PermittedURIDomains:   []string{SANTrustDomain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca sign: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca key marshal: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// EnsureCA is the run-once bootstrap: adopt the CA from the pre-created Secret if
// present, else generate it once and persist it. It NEVER regenerates a CA that was
// once populated (the anti-regeneration guard). The Secret is the lock: a
// resourceVersion CAS linearizes concurrent bootstrappers (a Job is not a
// guaranteed single writer), so on a Conflict the loser re-reads and adopts the
// winner's CA. Returns the adopted-or-generated (certPEM, keyPEM).
//
// Cases on the fetched Secret:
//   - populated (tls.crt+tls.key parse to a CA keypair) → ADOPT.
//   - present-but-unparseable, or empty-with-the-guard-annotation → HARD ANOMALY,
//     error (never regenerate; a populated CA was corrupted/blanked).
//   - virgin empty stub (no guard annotation) → generate + CAS write.
//   - NotFound → fatal config error (the operator must pre-create the empty stub;
//     no fallback to a broad namespace `create` grant).
func EnsureCA(ctx context.Context, rw SecretRW, namespace, name string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sec, err := rw.GetSecret(ctx, namespace, name)
		if apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("edge CA secret %s/%s not found — pre-create the empty stub (RBAC scopes update, not create)", namespace, name)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("get edge CA secret: %w", err)
		}

		crt := sec.Data["tls.crt"]
		key := sec.Data["tls.key"]
		_, hasGuard := sec.Annotations[caGenerationAnnotation]

		if len(crt) > 0 || len(key) > 0 {
			// Data present → must be a valid CA keypair to adopt; otherwise it is a
			// corrupted/half-written CA and we refuse to regenerate over it.
			if validCAKeypair(crt, key) {
				return crt, key, nil
			}
			return nil, nil, fmt.Errorf("edge CA secret %s/%s has unparseable/mismatched material — refusing to regenerate; investigate or restore", namespace, name)
		}
		// Data empty.
		if hasGuard {
			return nil, nil, fmt.Errorf("edge CA secret %s/%s has the generation guard but EMPTY data — a populated CA was blanked; refusing to regenerate (would distrust the fleet). Restore the CA or rotate deliberately", namespace, name)
		}

		// Virgin stub → generate once and CAS-write.
		certPEM, keyPEM, err = GenerateCA(ttl)
		if err != nil {
			return nil, nil, err
		}
		id, err := caBundleID(certPEM)
		if err != nil {
			return nil, nil, err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data["tls.crt"] = certPEM
		sec.Data["tls.key"] = keyPEM
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		sec.Annotations[caGenerationAnnotation] = id // deterministic fingerprint of the CA we wrote

		if _, err := rw.UpdateSecret(ctx, namespace, sec); err != nil {
			if apierrors.IsConflict(err) {
				// Another bootstrapper won the CAS; re-read and adopt its CA.
				continue
			}
			return nil, nil, fmt.Errorf("persist edge CA: %w", err)
		}
		return certPEM, keyPEM, nil
	}
	return nil, nil, fmt.Errorf("ensure edge CA: exhausted CAS retries for %s/%s", namespace, name)
}

// validCAKeypair reports whether (certPEM, keyPEM) parse as a matching CA keypair.
// certPEM may be a bundle (OLD++NEW): the FIRST CERTIFICATE block must match keyPEM
// (tls.key tracks the OLD/active cert, which is first in the bundle).
func validCAKeypair(certPEM, keyPEM []byte) bool {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return false
	}
	cert, err := parseCACert(certPEM)
	if err != nil {
		return false
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return false
	}
	return publicKeyMatches(cert.PublicKey, key.Public())
}

// reencodeCertBundle parses every CERTIFICATE block (all-or-nothing) and re-encodes
// them into a guaranteed well-formed PEM, returning the bundle and its cert count.
// A non-CERTIFICATE block is skipped; an unparseable CERTIFICATE block is an error.
func reencodeCertBundle(certPEM []byte) (bundle []byte, count int, err error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, 0, fmt.Errorf("parse cert in bundle: %w", err)
		}
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		count++
	}
	return bundle, count, nil
}

// RotateCA performs the NON-DESTRUCTIVE half of a CA rotation: on a populated
// single-CA Secret it generates a NEW CA in memory and CAS-writes tls.crt =
// OLD++NEW, stages the NEW key in tls-new.key, and stamps phase=overlap /
// active=old. It NEVER drops OLD and NEVER flips the active key — so trust only
// widens (the core's strictPool already trusts every cert in the bundle while edges
// keep presenting OLD-CA leaves). The destructive trim + active flip are a later
// step. Returns the OLD++NEW bundle PEM.
//
// It is idempotent: a re-run on an already-overlap Secret (2 certs + a staged
// tls-new.key) is a no-op that returns the existing bundle, so an Argo re-sync or a
// Job retry never appends a third cert. Like EnsureCA it uses a resourceVersion CAS
// loop, re-reading and re-evaluating idempotency on a Conflict. Cluster-backend only
// (the fs backend's UpdateSecret is non-CAS).
func RotateCA(ctx context.Context, rw SecretRW, namespace, name string, ttl time.Duration) (bundlePEM []byte, err error) {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sec, err := rw.GetSecret(ctx, namespace, name)
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("edge CA secret %s/%s not found — rotation only runs on an existing CA", namespace, name)
		}
		if err != nil {
			return nil, fmt.Errorf("get edge CA secret: %w", err)
		}

		crt := sec.Data["tls.crt"]
		key := sec.Data["tls.key"]
		// Rotation requires an existing, valid CA (the active OLD pair). The first
		// CERTIFICATE block must match tls.key.
		if !validCAKeypair(crt, key) {
			return nil, fmt.Errorf("edge CA secret %s/%s is not a populated/valid CA — bootstrap before rotating", namespace, name)
		}

		_, count, err := reencodeCertBundle(crt)
		if err != nil {
			return nil, fmt.Errorf("edge CA secret %s/%s has an unparseable bundle: %w", namespace, name, err)
		}
		phase := sec.Annotations[caRotationPhaseAnnotation]

		// Idempotency: already in the overlap we'd produce (2 certs + staged NEW key).
		if phase == caPhaseOverlap && count == 2 && len(sec.Data[caNewKeyField]) > 0 {
			return append([]byte(nil), crt...), nil
		}
		// Any other multi-cert state is unexpected (a partial/foreign rotation); don't
		// blindly append a third cert.
		if count != 1 {
			return nil, fmt.Errorf("edge CA secret %s/%s has %d certs (phase=%q) — not a clean single-CA to rotate; investigate", namespace, name, count, phase)
		}

		// Generate NEW and assemble OLD++NEW (both normalized, exactly 2 blocks).
		oldBundle, _, err := reencodeCertBundle(crt)
		if err != nil {
			return nil, err
		}
		newCert, newKey, err := GenerateCA(ttl)
		if err != nil {
			return nil, err
		}
		newBundle := append(append([]byte(nil), oldBundle...), newCert...)
		if _, n, err := reencodeCertBundle(newBundle); err != nil || n != 2 {
			return nil, fmt.Errorf("assemble OLD++NEW bundle: want 2 certs, got %d (err=%v)", n, err)
		}

		id, err := caBundleID(newBundle)
		if err != nil {
			return nil, err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data["tls.crt"] = newBundle
		sec.Data[caNewKeyField] = newKey // tls.key stays OLD (active)
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		sec.Annotations[caRotationPhaseAnnotation] = caPhaseOverlap
		sec.Annotations[caActiveAnnotation] = caActiveOld
		sec.Annotations[caGenerationAnnotation] = id // re-stamp (NEVER blank — keep the anti-regen guard)

		if _, err := rw.UpdateSecret(ctx, namespace, sec); err != nil {
			if apierrors.IsConflict(err) {
				continue // re-read + re-evaluate idempotency (don't append a third cert)
			}
			return nil, fmt.Errorf("persist rotated edge CA: %w", err)
		}

		// Re-GET and assert the live Secret round-trips to exactly OLD++NEW before
		// returning (mirror EnsureCA's re-verify discipline).
		check, err := rw.GetSecret(ctx, namespace, name)
		if err != nil {
			return nil, fmt.Errorf("verify rotated edge CA: %w", err)
		}
		if _, n, err := reencodeCertBundle(check.Data["tls.crt"]); err != nil || n != 2 {
			return nil, fmt.Errorf("post-rotation verify: want 2 certs, got %d (err=%v)", n, err)
		}
		return append([]byte(nil), newBundle...), nil
	}
	return nil, fmt.Errorf("rotate edge CA: exhausted CAS retries for %s/%s", namespace, name)
}
