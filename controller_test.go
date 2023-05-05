package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func TestHealthy(t *testing.T) {
	t.Parallel()

	t.Run("Readiness not healthy when create", func(t *testing.T) {
		ctrl := New("default", proxy.New())

		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz?ready=1", nil)
		w := httptest.NewRecorder()
		ctrl.Healthz().ServeHandler(http.NotFoundHandler()).ServeHTTP(w, r)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("Liveness healthy when create", func(t *testing.T) {
		ctrl := New("default", proxy.New())

		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
		w := httptest.NewRecorder()
		ctrl.Healthz().ServeHandler(http.NotFoundHandler()).ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Readiness healthy after reload", func(t *testing.T) {
		ctrl := New("default", proxy.New())
		ctrl.firstReload()
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz?ready=1", nil)
		w := httptest.NewRecorder()
		ctrl.Healthz().ServeHandler(http.NotFoundHandler()).ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// verify http.ServeMux behavior
func TestMux(t *testing.T) {
	t.Parallel()

	t.Run("Prefix Host", func(t *testing.T) {
		t.Run("Match Exact", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("Match Prefix", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/test/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})
	})

	t.Run("Prefix Path", func(t *testing.T) {
		t.Run("Not Match Exact without trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.False(t, called)
		})

		t.Run("Match Exact with trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})
	})

	t.Run("Exact Path", func(t *testing.T) {
		t.Run("Match Exact", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("Not Match trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.False(t, called)
		})
	})
}

func TestBuildHost(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "api.default.svc.cluster.local", buildHost("default", "api"))
}

func TestBuildHostPort(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "api.default.svc.cluster.local:8080", buildHostPort("default", "api", 8080))
}

func TestBuildRoutes(t *testing.T) {
	var called string
	h := func(p string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			called = p
		}
	}

	routes := map[string]http.Handler{}
	routes["example.com/"] = h("example.com/")
	routes["example.com/path"] = h("example.com/path")
	routes["example.com/path/"] = h("example.com/path/")
	routes["example.com/path/path2"] = h("example.com/path/path2")

	mux := buildRoutes(routes)

	f := func(path string, expected string) {
		called = ""
		r := httptest.NewRequest(http.MethodGet, "http://"+path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		assert.Equal(t, expected, called)
	}
	f("example.com/", "example.com/")
	f("example.com/path", "example.com/path")
	f("example.com/path/test", "example.com/path/")
	f("example.com/path/path2", "example.com/path/path2")
	f("example.com/path/path2/path3", "example.com/path/")
}

func TestBuildRoutes_Duplicate(t *testing.T) {
	t.Parallel()

	routes := map[string]http.Handler{}
	routes["example.com/path"] = http.NotFoundHandler()
	routes["example.com/path"] = http.NotFoundHandler()
	var called bool
	routes["example.com/path2"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	var mux *http.ServeMux
	assert.NotPanics(t, func() {
		mux = buildRoutes(routes)
	})
	r := httptest.NewRequest(http.MethodGet, "http://example.com/path2", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	assert.True(t, called)
}

func TestGetIngressClass(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		ing := networking.Ingress{}
		assert.Equal(t, "", getIngressClass(&ing))
	})

	t.Run("Annotation", func(t *testing.T) {
		ing := networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"kubernetes.io/ingress.class": "parapet",
				},
			},
		}
		assert.Equal(t, "parapet", getIngressClass(&ing))
	})

	t.Run("ingressClassName", func(t *testing.T) {
		ing := networking.Ingress{
			Spec: networking.IngressSpec{
				IngressClassName: pointer.String("parapet"),
			},
		}
		assert.Equal(t, "parapet", getIngressClass(&ing))
	})
}

func TestGetBackendConfig(t *testing.T) {
	t.Parallel()

	t.Run("Port Name", func(t *testing.T) {
		backend := networking.IngressBackend{
			Service: &networking.IngressServiceBackend{
				Name: "service",
				Port: networking.ServiceBackendPort{
					Name: "http",
				},
			},
		}
		service := v1.Service{
			Spec: v1.ServiceSpec{
				Ports: []v1.ServicePort{
					{
						Name: "tcp",
						Port: 9000,
					},
					{
						Name:        "http",
						Port:        8080,
						AppProtocol: pointer.String("h2c"),
					},
				},
			},
		}
		config, ok := getBackendConfig(&backend, &service)
		assert.True(t, ok)
		assert.Equal(t, "http", config.PortName)
		assert.Equal(t, 8080, config.PortNumber)
		assert.Equal(t, "h2c", config.Protocol)
	})

	t.Run("Port Number", func(t *testing.T) {
		backend := networking.IngressBackend{
			Service: &networking.IngressServiceBackend{
				Name: "service",
				Port: networking.ServiceBackendPort{
					Number: 8080,
				},
			},
		}
		service := v1.Service{
			Spec: v1.ServiceSpec{
				Ports: []v1.ServicePort{
					{
						Name: "tcp",
						Port: 9000,
					},
					{
						Name:        "http",
						Port:        8080,
						AppProtocol: pointer.String("h2c"),
					},
				},
			},
		}
		config, ok := getBackendConfig(&backend, &service)
		assert.True(t, ok)
		assert.Equal(t, "http", config.PortName)
		assert.Equal(t, 8080, config.PortNumber)
		assert.Equal(t, "h2c", config.Protocol)
	})
}

func TestEndpointToRRLB(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		ep := v1.Endpoints{}
		lb := endpointToRRLB(&ep)
		assert.Nil(t, lb)
	})

	t.Run("Single Subset", func(t *testing.T) {
		ep := v1.Endpoints{
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.1"},
						{IP: "192.168.0.2"},
						{IP: "192.168.0.3"},
					},
				},
			},
		}
		lb := endpointToRRLB(&ep)
		if assert.NotNil(t, lb) {
			assert.EqualValues(t, []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}, lb.IPs)
		}
	})

	t.Run("Multiple Subsets", func(t *testing.T) {
		ep := v1.Endpoints{
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.1"},
						{IP: "192.168.0.2"},
					},
				},
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.3"},
					},
				},
			},
		}
		lb := endpointToRRLB(&ep)
		if assert.NotNil(t, lb) {
			assert.EqualValues(t, []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}, lb.IPs)
		}
	})
}
