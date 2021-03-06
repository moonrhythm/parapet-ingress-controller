package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// IngressClass to load ingresses
const IngressClass = "parapet"

// Controller is the parapet ingress controller
type Controller struct {
	mu                sync.RWMutex
	m                 *http.ServeMux
	watchedServices   map[string]struct{}
	watchedSecrets    map[string]struct{}
	nameToCertificate map[string][]*tls.Certificate

	plugins                []plugin.Plugin
	health                 *healthz.Healthz
	reloadDebounce         *debounce
	reloadEndpointDebounce *debounce
	watchNamespace         string
}

// New creates new ingress controller
func New(watchNamespace string) *Controller {
	ctrl := &Controller{}
	ctrl.health = healthz.New()
	ctrl.health.SetReady(false)
	ctrl.watchNamespace = watchNamespace
	ctrl.reloadDebounce = newDebounce(ctrl.reloadDebounced, 300*time.Millisecond)
	ctrl.reloadEndpointDebounce = newDebounce(ctrl.reloadEndpointDebounced, 300*time.Millisecond)
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

	watch := func(
		resourceType string,
		f func(ctx context.Context, namespace string) (watch.Interface, error),
		filter *map[string]struct{},
		reload func(),
	) {
		for {
			w, err := f(context.Background(), ctrl.watchNamespace)
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
					case *v1.Endpoints:
						meta = &obj.ObjectMeta
					}
					if meta == nil {
						continue
					}

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

					glog.Infof("reload because %s %s/%s changed", resourceType, meta.Namespace, meta.Name)
				}

				reload()
			}

			// channel closed, retry watch again
			w.Stop()
			glog.Infof("restart %s watcher", resourceType)
		}
	}

	go watch("ingresses", k8s.WatchIngresses, nil, ctrl.Reload)
	go watch("services", k8s.WatchServices, &ctrl.watchedServices, ctrl.Reload)
	go watch("endpoints", k8s.WatchEndpoints, &ctrl.watchedServices, ctrl.reloadEndpoint)
	go watch("secrets", k8s.WatchSecrets, &ctrl.watchedSecrets, ctrl.Reload)
}

// Reload reloads ingresses
func (ctrl *Controller) Reload() {
	ctrl.reloadDebounce.Call()
}

func (ctrl *Controller) reloadDebounced() {
	glog.Info("reload")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
			metric.Reload(false)
			return
		}
		metric.Reload(true)
	}()

	ctx := context.Background()

	services, err := k8s.GetServices(ctx, ctrl.watchNamespace)
	if err != nil {
		panic(fmt.Errorf("can not get services; %w", err))
	}

	secrets, err := k8s.GetSecrets(ctx, ctrl.watchNamespace)
	if err != nil {
		panic(fmt.Errorf("can not get secrets; %w", err))
	}

	ingresses, err := k8s.GetIngresses(ctx, ctrl.watchNamespace)
	if err != nil {
		panic(fmt.Errorf("can not get ingresses; %w", err))
	}

	addrToPort := make(map[string]string)
	nameToService := make(map[string]v1.Service)
	for _, s := range services {
		nameToService[s.Namespace+"/"+s.Name] = s

		// build route target port
		for _, p := range s.Spec.Ports {
			addr := buildHostPort(s.Namespace, s.Name, int(p.Port))
			target := strconv.Itoa(int(p.TargetPort.IntVal))
			addrToPort[addr] = target
		}
	}
	nameToSecret := make(map[string]v1.Secret)
	for _, s := range secrets {
		nameToSecret[s.Namespace+"/"+s.Name] = s
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
		h.Use(parapet.MiddlewareFunc(retryMiddleware))

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

				svcKey := ing.Namespace + "/" + backend.ServiceName
				watchedServices[svcKey] = struct{}{} // service may create later

				svc, ok := nameToService[svcKey]
				if !ok {
					glog.Errorf("service %s not found", svcKey)
					continue
				}

				// find port
				var (
					portVal  int
					portName string
				)
				if backend.ServicePort.Type == intstr.String {
					portName = backend.ServicePort.StrVal

					// find port number
					for _, p := range svc.Spec.Ports {
						if p.Name == backend.ServicePort.StrVal {
							portVal = int(p.Port)
						}
					}
					if portVal == 0 {
						glog.Errorf("port %s on service %s not found", backend.ServicePort.StrVal, svcKey)
						continue
					}
				} else {
					portVal = int(backend.ServicePort.IntVal)

					// find port name
					for _, p := range svc.Spec.Ports {
						if p.Port == backend.ServicePort.IntVal {
							portName = p.Name
						}
					}
				}

				if svc.Annotations != nil {
					if a := svc.Annotations["parapet.moonrhythm.io/backend-config"]; a != "" {
						var cfg map[string]backendConfig
						err = yaml.Unmarshal([]byte(a), &cfg)
						if err != nil {
							glog.Errorf("can not parse backend-config from annotation; %v", err)
						}
						config = cfg[portName]
					}
				}
				if portVal <= 0 {
					continue
				}

				src := strings.ToLower(rule.Host) + path
				target := buildHostPort(ing.Namespace, backend.ServiceName, portVal)
				routes[src] = h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if config.Protocol != "" {
						r.URL.Scheme = config.Protocol
					}

					ctx := r.Context()
					s := state.Get(ctx)
					s["serviceType"] = string(svc.Spec.Type)
					s["serviceName"] = svc.Name
					s["serviceTarget"] = r.URL.Host

					nr := r.WithContext(ctx)
					nr.RemoteAddr = ""
					nr.URL.Host = globalRouteTable.Lookup(target)
					proxy.ServeHTTP(w, nr)
				}))

				glog.V(1).Infof("registered: %s => %s", src, target)
			}
		}

		for _, t := range ing.Spec.TLS {
			key := ing.Namespace + "/" + t.SecretName
			watchedSecrets[key] = struct{}{} // watch not exists secret
			if _, ok := nameToSecret[key]; !ok {
				glog.Errorf("secret %s not found", key)
				continue
			}
		}
	}

	// build routes
	mux := http.NewServeMux()
	for r, h := range routes {
		func() {
			defer func() {
				err := recover()
				if err != nil {
					glog.Errorf("register handler at %s; %v", r, err)
				}
			}()
			mux.Handle(r, h)
		}()
	}

	// build certs
	var certs []*tls.Certificate
	for key := range watchedSecrets {
		s, ok := nameToSecret[key]
		if !ok {
			continue
		}
		crt, key := s.Data["tls.crt"], s.Data["tls.key"]
		cert, err := tls.X509KeyPair(crt, key)
		if err != nil {
			glog.Errorf("can not load x509 certificate %s/%s; %v", s.Namespace, s.Name, err)
			continue
		}
		certs = append(certs, &cert)
	}
	nameToCert := buildNameToCertificate(certs)

	ctrl.mu.Lock()
	ctrl.m = mux
	ctrl.watchedServices = watchedServices
	ctrl.watchedSecrets = watchedSecrets
	ctrl.nameToCertificate = nameToCert
	globalRouteTable.SetPortRoute(addrToPort)
	ctrl.mu.Unlock()
	ctrl.health.SetReady(true)
	ctrl.reloadEndpoint()
}

func (ctrl *Controller) reloadEndpoint() {
	ctrl.reloadEndpointDebounce.Call()
}

func (ctrl *Controller) reloadEndpointDebounced() {
	glog.Info("reload endpoints")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
		}
	}()

	ctx := context.Background()

	endpoints, err := k8s.GetEndpoints(ctx, ctrl.watchNamespace)
	if err != nil {
		glog.Error("can not get endpoints;", err)
		return
	}

	routes := make(map[string]*rrlb)
	for _, ep := range endpoints {
		if len(ep.Subsets) == 0 {
			continue
		}

		var b rrlb
		for _, ss := range ep.Subsets {
			for _, addr := range ss.Addresses {
				b.IPs = append(b.IPs, addr.IP)
			}
		}
		routes[buildHost(ep.Namespace, ep.Name)] = &b
	}

	globalRouteTable.SetHostRoute(routes)
}

// GetCertificate returns certificate for given client hello information
func (ctrl *Controller) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// from tls/common.go

	ctrl.mu.RLock()
	certs := ctrl.nameToCertificate
	ctrl.mu.RUnlock()

	name := strings.ToLower(clientHello.ServerName)

	// exact name
	if cert, ok := certs[name]; ok {
		c := findSupportCert(cert, clientHello)
		if c != nil {
			return c, nil
		}
	}

	// wildcard name
	if len(name) > 0 {
		labels := strings.Split(name, ".")
		labels[0] = "*"
		wildcardName := strings.Join(labels, ".")
		if cert, ok := certs[wildcardName]; ok {
			return findSupportCert(cert, clientHello), nil
		}
	}

	return nil, nil
}

// Healthz returns health check middleware
func (ctrl *Controller) Healthz() parapet.Middleware {
	return ctrl.health
}

type backendConfig struct {
	// TODO: migrate to k8s native's service.ports.appProtocol ?
	Protocol string `json:"protocol" yaml:"protocol"`
}

func buildHost(namespace, name string) string {
	// service.namespace.svc.cluster.local
	return fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
}

func buildHostPort(namespace, name string, port int) string {
	// service.namespace.svc.cluster.local:port
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, namespace, port)
}

func buildNameToCertificate(certs []*tls.Certificate) map[string][]*tls.Certificate {
	m := make(map[string][]*tls.Certificate)
	for _, cert := range certs {
		var err error
		x509Cert := cert.Leaf
		if x509Cert == nil {
			x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}
		}
		// use only SAN, CN already deprecated
		for _, san := range x509Cert.DNSNames {
			m[san] = append(m[san], cert)
		}
	}
	return m
}

func findSupportCert(certs []*tls.Certificate, clientHello *tls.ClientHelloInfo) *tls.Certificate {
	for _, cert := range certs {
		err := clientHello.SupportsCertificate(cert)
		if err == nil {
			return cert
		}
	}
	return nil
}
