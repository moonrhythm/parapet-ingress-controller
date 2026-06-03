package edgecp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "parapet-edge-ca"},
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
