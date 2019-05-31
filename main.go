package main

import (
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
	"k8s.io/client-go/rest"
)

var (
	client    *kubernetes.Clientset
	namespace string
)

func main() {
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	namespace = os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	glog.Infoln("parapet-ingress-controller")
	glog.Infoln("port:", port)
	glog.Infoln("namespace:", namespace)

	var err error
	client, err = newKubernetesClient()
	if err != nil {
		glog.Fatal(err)
		os.Exit(1)
	}

	s := parapet.New()
	s.Use(health())
	s.Use(gcp.HLBImmediateIP(0)) // TODO: configurable
	s.Use(logger.Stdout())
	s.Use(promRequests())
	s.Use(compress.Gzip())
	s.Use(compress.Br())

	s.Use(router{})

	prom.Connections(s)
	prom.Networks(s)
	go prom.Start(":9187")

	s.Addr = ":" + port

	err = s.ListenAndServe()
	if err != nil {
		glog.Fatal(err)
		os.Exit(1)
	}
}

func health() parapet.Middleware {
	h := host.NewCIDR("0.0.0.0/0")
	l := location.Exact("/healthz")
	l.Use(healthz.New())
	h.Use(l)
	return h
}

func newKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}
