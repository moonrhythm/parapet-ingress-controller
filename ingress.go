package controller

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
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
)

// IngressClass to load ingresses
const IngressClass = "parapet"

// Controller is the parapet ingress controller
type Controller struct {
	mu                sync.RWMutex
	m                 *http.ServeMux
	watchedServices   map[string]struct{}
	watchedSecrets    map[string]struct{}
	nameToCertificate map[string]*tls.Certificate

	plugins        []plugin.Plugin
	health         *healthz.Healthz
	reload         *debounce
	watchNamespace string
}

// New creates new ingress controller
func New(watchNamespace string) *Controller {
	ctrl := &Controller{}
	ctrl.health = healthz.New()
	ctrl.health.SetReady(false)
	ctrl.watchNamespace = watchNamespace
	ctrl.reload = newDebounce(ctrl.reloadDebounced, 100*time.Millisecond)
	return ctrl
}

// Use appends a plugin
func (ctrl *Controller) Use(m plugin.Plugin) {
	ctrl.plugins = append(ctrl.plugins, m)
}

// ServeHandler implements parapet.Middleware
func (ctrl *Controller) ServeHandler(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctrl.mu.RLock()
		mux := ctrl.m
		ctrl.mu.RUnlock()

		mux.ServeHTTP(w, r)
	})
}

// Watch starts watch k8s resource
func (ctrl *Controller) Watch() {
	ctrl.Reload()

	watch := func(resourceType string, f func(namespace string) (watch.Interface, error), filter *map[string]struct{}) {
		for {
			w, err := f(ctrl.watchNamespace)
			if err != nil {
				glog.Errorf("can not watch %s; %v", resourceType, err)
				time.Sleep(5 * time.Second)
				continue
			}

			for event := range w.ResultChan() {
				if event.Type == watch.Error {
					continue
				}

				// filter out unrelated resources
				if filter != nil {
					var meta *metav1.ObjectMeta
					switch obj := event.Object.(type) {
					case *v1.Service:
						meta = &obj.ObjectMeta
					case *v1.Secret:
						meta = &obj.ObjectMeta
					}
					if meta != nil {
						key := meta.Namespace + "/" + meta.Name
						ctrl.mu.RLock()
						var ok bool
						if *filter != nil {
							_, ok = (*filter)[key]
						}
						ctrl.mu.RUnlock()
						if !ok {
							continue
						}
					}
				}

				ctrl.Reload()
			}

			// channel closed, retry watch again
			w.Stop()
			glog.Infof("restart %s watcher", resourceType)
		}
	}

	go watch("ingresses", k8s.WatchIngresses, nil)
	go watch("services", k8s.WatchServices, &ctrl.watchedServices)
	go watch("secrets", k8s.WatchSecrets, &ctrl.watchedSecrets)
}

// Reload reloads ingresses
func (ctrl *Controller) Reload() {
	ctrl.reload.Call()
}

func (ctrl *Controller) reloadDebounced() {
	glog.Info("reload ingresses")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
		}
	}()

	services, err := k8s.GetServices(ctrl.watchNamespace)
	if err != nil {
		glog.Error("can not get services;", err)
	}
	nameToService := make(map[string]*v1.Service)
	for _, s := range services {
		nameToService[s.Namespace+"/"+s.Name] = &s
	}

	secrets, err := k8s.GetSecrets(ctrl.watchNamespace)
	if err != nil {
		glog.Error("can not get secrets;", err)
	}
	nameToSecret := make(map[string]*v1.Secret)
	for _, s := range secrets {
		nameToSecret[s.Namespace+"/"+s.Name] = &s
	}

	ingresses, err := k8s.GetIngresses(ctrl.watchNamespace)
	if err != nil {
		glog.Error("can not get ingresses;", err)
		return
	}

	routes := make(map[string]http.Handler)
	watchedServices := make(map[string]struct{})
	watchedSecrets := make(map[string]struct{})

	for _, ing := range ingresses {
		if ing.Annotations == nil || ing.Annotations["kubernetes.io/ingress.class"] != IngressClass {
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

				var config backendConfig

				port := int(backend.ServicePort.IntVal)
				if backend.ServicePort.Type == intstr.String {
					key := ing.Namespace + "/" + backend.ServiceName
					svc := nameToService[key]
					if svc == nil {
						glog.Errorf("service %s not found", key)
						continue
					}
					watchedServices[key] = struct{}{}

					// TODO: support custom proto backend

					// find port number
					for _, p := range svc.Spec.Ports {
						if p.Name == backend.ServicePort.StrVal {
							port = int(p.Port)
						}
					}
					if port == 0 {
						glog.Errorf("port %s on service %s not found", backend.ServiceName, key)
						continue
					}

					if svc.Annotations != nil {
						if a := svc.Annotations["parapet.moonrhythm.io/backend-config"]; a != "" {
							var cfg map[string]backendConfig
							err = yaml.Unmarshal([]byte(a), &cfg)
							if err != nil {
								glog.Errorf("can not parse backend-config from annotation;", err)
							}
							config = cfg[backend.ServicePort.StrVal]
						}
					}
				}
				if port <= 0 {
					continue
				}

				src := strings.ToLower(rule.Host) + path
				// service.namespace.svc.cluster.local:port
				target := fmt.Sprintf("%s.%s.svc.cluster.local:%d", backend.ServiceName, ing.Namespace, port)
				routes[src] = h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Host = target

					// TODO: add support h2c
					switch config.Protocol {
					case "http":
						r.URL.Scheme = "http"
					case "https":
						r.URL.Scheme = "https"
					}
					proxy.ServeHTTP(w, r)
				}))
				glog.V(1).Infof("registered: %s => %s", src, target)
			}

			for _, t := range ing.Spec.TLS {
				key := ing.Namespace + "/" + t.SecretName
				if _, ok := nameToSecret[key]; !ok {
					glog.Errorf("secret %s not found", key)
					continue
				}
				watchedSecrets[key] = struct{}{}
			}
		}
	}

	// build routes
	mux := http.NewServeMux()
	for r, h := range routes {
		mux.Handle(r, h)
	}

	// build certs
	var certs []tls.Certificate
	for key := range watchedSecrets {
		s := nameToSecret[key]
		if s == nil {
			continue
		}
		crt, key := s.Data["tls.crt"], s.Data["tls.key"]
		cert, err := tls.X509KeyPair(crt, key)
		if err != nil {
			glog.Errorf("can not load x509 certificate %s/%s; %v", s.Namespace, s.Name, err)
			continue
		}
		certs = append(certs, cert)
	}
	tlsConfig := tls.Config{Certificates: certs}
	tlsConfig.BuildNameToCertificate()

	ctrl.mu.Lock()
	ctrl.m = mux
	ctrl.watchedServices = watchedServices
	ctrl.watchedSecrets = watchedSecrets
	ctrl.nameToCertificate = tlsConfig.NameToCertificate
	ctrl.mu.Unlock()
	ctrl.health.SetReady(true)
}

// GetCertificate returns certificate for given client hello information
func (ctrl *Controller) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

// Healthz returns health check middleware
func (ctrl *Controller) Healthz() parapet.Middleware {
	return ctrl.health
}

type backendConfig struct {
	Protocol string `json:"protocol" yaml:"protocol"`
}
