package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/moonrhythm/parapet/pkg/gcp"
	"github.com/moonrhythm/parapet/pkg/host"
	"github.com/moonrhythm/parapet/pkg/location"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"
	"k8s.io/client-go/kubernetes"
)

const (
	ingressClass = "parapet"
	bufferSize   = 16 * 1024
)

var (
	client    *kubernetes.Clientset
	namespace string
)

func main() {
	flag.Parse()

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "80"
	}
	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "443"
	}
	namespace = os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	glog.Infoln("parapet-ingress-controller")
	glog.Infoln("http_port:", httpPort)
	glog.Infoln("https_port:", httpsPort)
	glog.Infoln("namespace:", namespace)

	var err error
	client, err = newKubernetesClient()
	if err != nil {
		glog.Fatal(err)
		os.Exit(1)
	}

	go prom.Start(":9187")

	ctrl := &ingressController{}
	go func() {
		ctrl.reload()
		ctrl.watchIngresses()
	}()

	m := parapet.Middlewares{}
	m.Use(func() parapet.Middleware {
		h := host.NewCIDR("0.0.0.0/0")
		l := location.Exact("/healthz")
		l.Use(parapet.MiddlewareFunc(func(http.Handler) http.Handler {
			var (
				once     sync.Once
				shutdown int32
			)
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() {
					if srv, ok := r.Context().Value(parapet.ServerContextKey).(*parapet.Server); ok {
						srv.RegisterOnShutdown(func() {
							atomic.StoreInt32(&shutdown, 1)
						})
					}
				})

				if r.URL.Query().Get("ready") != "" {
					p := atomic.LoadInt32(&shutdown)
					if p > 0 || !ctrl.Ready() {
						w.WriteHeader(http.StatusServiceUnavailable)
						w.Write([]byte("Service Unavailable"))
						return
					}
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})
		}))
		h.Use(l)
		return h
	}())
	m.Use(gcp.HLBImmediateIP(0)) // TODO: configurable
	m.Use(logger.Stdout())
	m.Use(&_promRequests)
	m.Use(compress.Gzip())
	m.Use(compress.Br())
	m.Use(ctrl)

	// http
	{
		s := parapet.New()
		s.Use(m)
		prom.Connections(s)
		prom.Networks(s)
		s.Addr = ":" + httpPort

		go func() {
			err := s.ListenAndServe()
			if err != nil {
				glog.Fatal(err)
				os.Exit(1)
			}
		}()
	}

	// https
	{
		cert, err := parapet.GenerateSelfSignCertificate(parapet.SelfSign{
			CommonName: "parapet-ingress-controller",
		})
		if err != nil {
			glog.Fatal(err)
			os.Exit(1)
		}

		s := parapet.New()
		s.Use(m)
		prom.Connections(s)
		prom.Networks(s)
		s.Addr = ":" + httpsPort
		s.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			Certificates:   []tls.Certificate{cert},
			GetCertificate: ctrl.GetCertificate,
		}

		err = s.ListenAndServe()
		if err != nil {
			glog.Fatal(err)
			os.Exit(1)
		}
	}
}
