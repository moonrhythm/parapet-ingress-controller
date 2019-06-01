package main

import (
	"crypto/tls"
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/moonrhythm/parapet/pkg/gcp"
	"github.com/moonrhythm/parapet/pkg/healthz"
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
		httpPort = "443"
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
	ctrl.reload()
	go ctrl.watchIngresses()

	m := parapet.Middlewares{}
	m.Use(health())
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

func health() parapet.Middleware {
	h := host.NewCIDR("0.0.0.0/0")
	l := location.Exact("/healthz")
	l.Use(healthz.New())
	h.Use(l)
	return h
}
