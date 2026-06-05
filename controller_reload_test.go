package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func ptr[T any](v T) *T { return &v }

// matchedPattern returns the ServeMux pattern that a request for host+path
// resolves to, without invoking the backend handler. Empty means no route.
func matchedPattern(t *testing.T, mux *http.ServeMux, host, path string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	_, pattern := mux.Handler(r)
	return pattern
}

func clusterIPService(namespace, name string, port, targetPort int) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{Port: int32(port), TargetPort: intstr.FromInt(targetPort)},
			},
		},
	}
}

func ingressToService(namespace, name, host, path string, pathType networking.PathType, svcName string, svcPort int) *networking.Ingress {
	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networking.IngressSpec{
			IngressClassName: ptr(IngressClass),
			Rules: []networking.IngressRule{
				{
					Host: host,
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path:     path,
									PathType: ptr(pathType),
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: svcName,
											Port: networking.ServiceBackendPort{Number: int32(svcPort)},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestReloadIngress(t *testing.T) {
	t.Run("ImplementationSpecific registers host/path as-is", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
		ctrl.watchedIngresses.Store("default/ing",
			ingressToService("default", "ing", "example.com", "/", networking.PathTypeImplementationSpecific, "web", 80))

		ctrl.reloadIngressDebounced()

		assert.Equal(t, "example.com/", matchedPattern(t, ctrl.mux, "example.com", "/"))
	})

	t.Run("Prefix registers both exact and subtree", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
		ctrl.watchedIngresses.Store("default/ing",
			ingressToService("default", "ing", "example.com", "/app", networking.PathTypePrefix, "web", 80))

		ctrl.reloadIngressDebounced()

		assert.Equal(t, "example.com/app", matchedPattern(t, ctrl.mux, "example.com", "/app"))
		assert.Equal(t, "example.com/app/", matchedPattern(t, ctrl.mux, "example.com", "/app/sub"))
	})

	t.Run("Exact registers single path", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
		ctrl.watchedIngresses.Store("default/ing",
			ingressToService("default", "ing", "example.com", "/app", networking.PathTypeExact, "web", 80))

		ctrl.reloadIngressDebounced()

		assert.Equal(t, "example.com/app", matchedPattern(t, ctrl.mux, "example.com", "/app"))
		// Exact must not match the subtree
		assert.Empty(t, matchedPattern(t, ctrl.mux, "example.com", "/app/sub"))
	})

	t.Run("skips ingress with non-matching class", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
		ing := ingressToService("default", "ing", "example.com", "/", networking.PathTypeImplementationSpecific, "web", 80)
		ing.Spec.IngressClassName = ptr("not-parapet")
		ctrl.watchedIngresses.Store("default/ing", ing)

		ctrl.reloadIngressDebounced()

		assert.Empty(t, matchedPattern(t, ctrl.mux, "example.com", "/"))
	})

	t.Run("skips path when backend service is missing", func(t *testing.T) {
		ctrl := New("", proxy.New())
		// no service stored
		ctrl.watchedIngresses.Store("default/ing",
			ingressToService("default", "ing", "example.com", "/", networking.PathTypeImplementationSpecific, "web", 80))

		ctrl.reloadIngressDebounced()

		assert.Empty(t, matchedPattern(t, ctrl.mux, "example.com", "/"))
	})

	t.Run("recovers from a panicking plugin", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.Use(func(_ plugin.Context) { panic("boom") })
		ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
		ctrl.watchedIngresses.Store("default/ing",
			ingressToService("default", "ing", "example.com", "/", networking.PathTypeImplementationSpecific, "web", 80))

		assert.NotPanics(t, func() { ctrl.reloadIngressDebounced() })
	})
}

func TestReloadServiceAndEndpoint(t *testing.T) {
	ctrl := New("", proxy.New())
	ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
	ctrl.watchedEndpoints.Store("default/web", &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Subsets: []v1.EndpointSubset{
			{Addresses: []v1.EndpointAddress{{IP: "10.0.0.1"}}},
		},
	})

	ctrl.reloadServiceDebounced()  // populates port routes (svc addr -> target port)
	ctrl.reloadEndpointDebounced() // populates host routes (svc host -> pod IPs)

	// Lookup resolves service addr to a concrete pod addr (pod IP : target port)
	assert.Equal(t, "10.0.0.1:8080",
		ctrl.routeTable.Lookup("web.default.svc.cluster.local:80"))

	// unknown service resolves to empty
	assert.Empty(t, ctrl.routeTable.Lookup("missing.default.svc.cluster.local:80"))
}

func namedPortService(namespace, name, portName string, port int) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				// NAMED targetPort: no number lives in the Service object.
				{Name: portName, Port: int32(port), TargetPort: intstr.FromString(portName)},
			},
		},
	}
}

func endpointsNamedPort(namespace, name, ip, portName string, port int) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{{IP: ip}},
				Ports:     []v1.EndpointPort{{Name: portName, Port: int32(port)}},
			},
		},
	}
}

func TestReloadServiceNamedTargetPort(t *testing.T) {
	// A named targetPort ("http") carries no number in the Service; it must be
	// resolved from the matching EndpointPort, not read as IntVal (which is 0 and
	// would route every request to ":0" → dial failure → 503).
	ctrl := New("", proxy.New())
	ctrl.watchedServices.Store("default/web", namedPortService("default", "web", "http", 80))
	ctrl.watchedEndpoints.Store("default/web", endpointsNamedPort("default", "web", "10.0.0.1", "http", 8080))

	ctrl.reloadServiceDebounced()
	ctrl.reloadEndpointDebounced()

	assert.Equal(t, "10.0.0.1:8080",
		ctrl.routeTable.Lookup("web.default.svc.cluster.local:80"),
		"named targetPort resolves to the matching EndpointPort number")
}

func TestReloadServiceNamedTargetPortConvergesWhenEndpointsArrive(t *testing.T) {
	// Service reloads before its endpoints exist: the named port can't resolve
	// yet, so no dead ":0" route is produced (Lookup is empty, fail-fast 503). It
	// converges once endpoints arrive and reloadService runs again (which the
	// endpoint watch triggers in production).
	ctrl := New("", proxy.New())
	ctrl.watchedServices.Store("default/web", namedPortService("default", "web", "http", 80))

	ctrl.reloadServiceDebounced()
	assert.Empty(t, ctrl.routeTable.Lookup("web.default.svc.cluster.local:80"),
		"unresolved named port must not create a ':0' route")

	ctrl.watchedEndpoints.Store("default/web", endpointsNamedPort("default", "web", "10.0.0.2", "http", 9090))
	ctrl.reloadServiceDebounced()  // endpoint watch triggers this in production
	ctrl.reloadEndpointDebounced() // host routes (pod IPs)

	assert.Equal(t, "10.0.0.2:9090",
		ctrl.routeTable.Lookup("web.default.svc.cluster.local:80"),
		"named port converges once endpoints arrive")
}

func TestReloadEndpointEmptySubsetIsNotRouted(t *testing.T) {
	ctrl := New("", proxy.New())
	ctrl.watchedServices.Store("default/web", clusterIPService("default", "web", 80, 8080))
	ctrl.watchedEndpoints.Store("default/web", &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		// no subsets -> no usable backend
	})

	ctrl.reloadServiceDebounced()
	ctrl.reloadEndpointDebounced()

	assert.Empty(t, ctrl.routeTable.Lookup("web.default.svc.cluster.local:80"))
}

func TestReloadSecret(t *testing.T) {
	certPEM, keyPEM := selfSignedCertPEM(t, "secure.example.com")
	tlsSecret := func(namespace, name string) *v1.Secret {
		return &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Type:       v1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
		}
	}
	hello := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: name, SupportedVersions: []uint16{tls.VersionTLS13}}
	}

	t.Run("loads secrets referenced by an ingress spec.tls", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedSecrets.Store("default/tls", tlsSecret("default", "tls"))
		ing := &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ing"},
			Spec:       networking.IngressSpec{TLS: []networking.IngressTLS{{SecretName: "tls"}}},
		}
		ctrl.watchedIngresses.Store("default/ing", ing)

		ctrl.reloadSecretDebounced()

		got, err := ctrl.GetCertificate(hello("secure.example.com"))
		require.NoError(t, err)
		assert.NotNil(t, got)

		got, err = ctrl.GetCertificate(hello("other.example.com"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("does not load an unreferenced secret by default", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.watchedSecrets.Store("default/tls", tlsSecret("default", "tls"))
		// no ingress references it

		ctrl.reloadSecretDebounced()

		got, err := ctrl.GetCertificate(hello("secure.example.com"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("LoadAllCerts loads every TLS secret without an ingress reference", func(t *testing.T) {
		ctrl := New("", proxy.New())
		ctrl.LoadAllCerts = true
		ctrl.watchedSecrets.Store("default/tls", tlsSecret("default", "tls"))

		ctrl.reloadSecretDebounced()

		got, err := ctrl.GetCertificate(hello("secure.example.com"))
		require.NoError(t, err)
		assert.NotNil(t, got)
	})
}

// selfSignedCertPEM returns a freshly-generated self-signed ECDSA certificate
// and key in PEM form, valid for the given DNS names.
func selfSignedCertPEM(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
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

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
