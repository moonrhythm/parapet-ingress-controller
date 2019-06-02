package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
)

const ingressClass = "parapet"

type ingressController struct {
	mu                sync.RWMutex
	m                 *http.ServeMux
	nameToCertificate map[string]*tls.Certificate
	plugins           []plugin.Plugin
	health            *healthz.Healthz
	debounceMu        sync.Mutex
	debounceTimer     *time.Timer
	watchNamespace    string
}

func newIngressController(watchNamespace string) *ingressController {
	ctrl := &ingressController{}
	ctrl.health = healthz.New()
	ctrl.health.SetReady(false)
	ctrl.watchNamespace = watchNamespace
	return ctrl
}

func (ctrl *ingressController) Use(m plugin.Plugin) {
	ctrl.plugins = append(ctrl.plugins, m)
}

func (ctrl *ingressController) ServeHandler(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctrl.mu.RLock()
		mux := ctrl.m
		ctrl.mu.RUnlock()

		mux.ServeHTTP(w, r)
	})
}

func (ctrl *ingressController) watchIngresses() {
	for {
		w, err := k8s.WatchIngresses(ctrl.watchNamespace)
		if err != nil {
			glog.Error("can not watch ingresses;", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			if event.Type == watch.Error {
				continue
			}

			ctrl.safeReload()
		}

		w.Stop()
		glog.Info("restart watcher")
	}
}

func (ctrl *ingressController) safeReload() {
	ctrl.debounceMu.Lock()
	defer ctrl.debounceMu.Unlock()

	if ctrl.debounceTimer != nil {
		ctrl.debounceTimer.Stop()
	}
	ctrl.debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
		glog.Info("reload ingresses")

		defer func() {
			if err := recover(); err != nil {
				glog.Error(err)
			}
		}()
		ctrl.reload()
	})
}

func (ctrl *ingressController) reload() {
	list, err := k8s.GetIngresses(ctrl.watchNamespace)
	if err != nil {
		panic(err)
	}

	var certs []tls.Certificate
	routes := make(map[string]http.Handler)

	for _, ing := range list {
		if ing.Annotations == nil || ing.Annotations["kubernetes.io/ingress.class"] != ingressClass {
			glog.Infof("skip: %s/%s", ing.Namespace, ing.Name)
			continue
		}
		glog.Infof("load: %s/%s", ing.Namespace, ing.Name)

		var h parapet.Middlewares
		for _, m := range ctrl.plugins {
			m(plugin.Context{
				Middlewares: &h,
				Routes:      routes,
				Ingress:     &ing,
			})
		}

		if ing.Spec.Backend != nil {
			glog.Warning("ingress spec.backend not support")
		}

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				backend := path.Backend
				path := path.Path
				if path == "" {
					path = "/"
				}

				port := int(backend.ServicePort.IntVal)
				if backend.ServicePort.Type == intstr.String {
					// TODO: add to watched services
					// TODO: support custom proto backend
					port = k8s.GetServicePort(ing.Namespace, backend.ServiceName, backend.ServicePort.StrVal)
				}
				if port <= 0 {
					continue
				}

				src := rule.Host + path
				// service.namespace.svc.cluster.local:port
				target := fmt.Sprintf("%s.%s.svc.cluster.local:%d", backend.ServiceName, ing.Namespace, port)
				routes[src] = h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Host = target
					proxy.ServeHTTP(w, r)
				}))
				glog.V(1).Infof("registered: %s => %s", src, target)
			}

			for _, t := range ing.Spec.TLS {
				// TODO: add to watched tls
				crt, key, err := k8s.GetSecretTLS(ing.Namespace, t.SecretName)
				if err != nil {
					glog.Errorf("can not get secret %s/%s; %v", ing.Namespace, t.SecretName, err)
					continue
				}

				cert, err := tls.X509KeyPair(crt, key)
				if err != nil {
					glog.Errorf("can not load x509 certificate %s/%s; %v", ing.Namespace, t.SecretName, err)
					continue
				}
				certs = append(certs, cert)
			}
		}
	}

	mux := http.NewServeMux()
	for r, h := range routes {
		mux.Handle(r, h)
	}

	tlsConfig := tls.Config{
		Certificates: certs,
	}
	tlsConfig.BuildNameToCertificate()

	ctrl.mu.Lock()
	ctrl.m = mux
	ctrl.nameToCertificate = tlsConfig.NameToCertificate
	ctrl.mu.Unlock()
	ctrl.health.SetReady(true)
}

func (ctrl *ingressController) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// from tls/common.go

	name := strings.ToLower(clientHello.ServerName)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	ctrl.mu.RLock()
	certs := ctrl.nameToCertificate
	ctrl.mu.RUnlock()

	if cert, ok := certs[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := certs[candidate]; ok {
			return cert, nil
		}
	}

	return nil, nil
}

// Healthz returns healthz check middleware
func (ctrl *ingressController) Healthz() parapet.Middleware {
	return ctrl.health
}
