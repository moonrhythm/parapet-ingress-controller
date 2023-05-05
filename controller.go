package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/cert"
	"github.com/moonrhythm/parapet-ingress-controller/debounce"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/proxy"
	"github.com/moonrhythm/parapet-ingress-controller/route"
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// IngressClass to load ingresses
var IngressClass = "parapet"

// Controller is the parapet ingress controller
type Controller struct {
	// mu is the mutex for mux
	mu  sync.RWMutex
	mux *http.ServeMux

	// namespace to watch, or empty to watch all
	watchNamespace string

	// holds current k8s state
	watchedIngresses sync.Map
	watchedServices  sync.Map
	watchedSecrets   sync.Map
	watchedEndpoints sync.Map

	certTable  cert.Table
	routeTable route.Table

	proxy *proxy.Proxy

	plugins []plugin.Plugin
	health  *healthz.Healthz

	reloadIngressDebounce  *debounce.Debounce
	reloadServiceDebounce  *debounce.Debounce
	reloadSecretDebounce   *debounce.Debounce
	reloadEndpointDebounce *debounce.Debounce
}

// New creates new ingress controller
func New(watchNamespace string, proxy *proxy.Proxy) *Controller {
	ctrl := &Controller{}
	ctrl.health = healthz.New()
	ctrl.health.SetReady(false)
	ctrl.watchNamespace = watchNamespace
	ctrl.reloadIngressDebounce = debounce.New(ctrl.reloadIngressDebounced, 300*time.Millisecond)
	ctrl.reloadServiceDebounce = debounce.New(ctrl.reloadServiceDebounced, 300*time.Millisecond)
	ctrl.reloadSecretDebounce = debounce.New(ctrl.reloadSecretDebounced, 300*time.Millisecond)
	ctrl.reloadEndpointDebounce = debounce.New(ctrl.reloadEndpointDebounced, 300*time.Millisecond)
	ctrl.proxy = proxy
	ctrl.proxy.OnDialError = ctrl.routeTable.MarkBad
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
		mux := ctrl.mux
		ctrl.mu.RUnlock()

		mux.ServeHTTP(w, r)
	})
}

// Watch starts watch k8s resource
func (ctrl *Controller) Watch() {
	ctx := context.Background()

	// preload all resources
	{
		ingresses, _ := k8s.GetIngresses(ctx, ctrl.watchNamespace)
		for _, i := range ingresses {
			i := i
			ctrl.watchedIngresses.Store(i.Namespace+"/"+i.Name, &i)
		}

		services, _ := k8s.GetServices(ctx, ctrl.watchNamespace)
		for _, s := range services {
			s := s
			ctrl.watchedServices.Store(s.Namespace+"/"+s.Name, &s)
		}

		secrets, _ := k8s.GetSecrets(ctx, ctrl.watchNamespace)
		for _, s := range secrets {
			s := s
			ctrl.watchedSecrets.Store(s.Namespace+"/"+s.Name, &s)
		}

		endpoints, _ := k8s.GetEndpoints(ctx, ctrl.watchNamespace)
		for _, e := range endpoints {
			e := e
			ctrl.watchedEndpoints.Store(e.Namespace+"/"+e.Name, &e)
		}
	}

	ctrl.reloadServiceDebounced()
	ctrl.reloadIngressDebounced()
	ctrl.reloadSecretDebounced()
	ctrl.reloadEndpointDebounced()

	// ready to serve requests
	ctrl.health.SetReady(true)

	go ctrl.watchIngresses(ctx)
	go ctrl.watchServices(ctx)
	go ctrl.watchSecrets(ctx)
	go ctrl.watchEndpoints(ctx)
}

func (ctrl *Controller) watchIngresses(ctx context.Context) {
	for {
		w, err := k8s.WatchIngresses(ctx, ctrl.watchNamespace)
		if err != nil {
			glog.Errorf("can not watch ingresses; %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj := event.Object.(*networking.Ingress)
			key := obj.Namespace + "/" + obj.Name

			switch event.Type {
			case watch.Added, watch.Modified:
				ctrl.watchedIngresses.Store(key, obj)
			case watch.Deleted:
				ctrl.watchedIngresses.Delete(key)
			default:
				continue
			}
			ctrl.reloadIngress()
		}

		w.Stop()
		glog.Infof("restart ingresses watcher")
	}
}

func (ctrl *Controller) watchServices(ctx context.Context) {
	for {
		w, err := k8s.WatchServices(ctx, ctrl.watchNamespace)
		if err != nil {
			glog.Errorf("can not watch services; %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj := event.Object.(*v1.Service)
			key := obj.Namespace + "/" + obj.Name

			switch event.Type {
			case watch.Added, watch.Modified:
				ctrl.watchedServices.Store(key, obj)
			case watch.Deleted:
				ctrl.watchedServices.Delete(key)
			default:
				continue
			}
			ctrl.reloadService()
			ctrl.reloadIngress()
		}

		w.Stop()
		glog.Infof("restart services watcher")
	}
}

func (ctrl *Controller) watchSecrets(ctx context.Context) {
	for {
		w, err := k8s.WatchSecrets(ctx, ctrl.watchNamespace)
		if err != nil {
			glog.Errorf("can not watch secrets; %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj := event.Object.(*v1.Secret)
			key := obj.Namespace + "/" + obj.Name

			switch event.Type {
			case watch.Added, watch.Modified:
				ctrl.watchedSecrets.Store(key, obj)
			case watch.Deleted:
				ctrl.watchedSecrets.Delete(key)
			default:
				continue
			}
			ctrl.reloadSecret()
		}

		w.Stop()
		glog.Infof("restart secrets watcher")
	}
}

func (ctrl *Controller) watchEndpoints(ctx context.Context) {
	for {
		w, err := k8s.WatchEndpoints(ctx, ctrl.watchNamespace)
		if err != nil {
			glog.Errorf("can not watch endpoints; %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj := event.Object.(*v1.Endpoints)
			key := obj.Namespace + "/" + obj.Name

			switch event.Type {
			case watch.Added, watch.Modified:
				ctrl.watchedEndpoints.Store(key, obj)
				ctrl.reloadSingleEndpoint(obj)
				continue
			case watch.Deleted:
				ctrl.watchedEndpoints.Delete(key)
			default:
				continue
			}
			ctrl.reloadEndpoint()
		}

		w.Stop()
		glog.Infof("restart endpoints watcher")
	}
}

func (ctrl *Controller) reloadIngress() {
	ctrl.reloadIngressDebounce.Call()
}

func (ctrl *Controller) reloadIngressDebounced() {
	glog.Info("reload ingresses")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
			metric.Reload(false)
			return
		}
		metric.Reload(true)
	}()

	routes := make(map[string]http.Handler)

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)

		if getIngressClass(ing) != IngressClass {
			glog.Infof("skip: %s/%s", ing.Namespace, ing.Name)
			return true
		}

		glog.Infof("load: %s/%s", ing.Namespace, ing.Name)

		var h parapet.Middlewares
		for _, m := range ctrl.plugins {
			m(plugin.Context{
				Middlewares: &h,
				Routes:      routes,
				Ingress:     ing,
			})
		}
		h.Use(parapet.MiddlewareFunc(retryMiddleware))

		if ing.Spec.DefaultBackend != nil {
			glog.Warning("ingress spec.defaultBackend not support")
		}

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, httpPath := range rule.HTTP.Paths {
				backend := httpPath.Backend
				if backend.Service == nil {
					glog.Warningf("ingress %s/%s: backend service empty", ing.Namespace, ing.Name)
					continue
				}

				path := httpPath.Path
				if path == "" { // path can not be empty
					path = "/"
				}
				if !strings.HasPrefix(path, "/") { // path must start with /
					path = "/" + path
				}

				pathType := networking.PathTypeImplementationSpecific
				if httpPath.PathType != nil {
					pathType = *httpPath.PathType
				}

				svcKey := ing.Namespace + "/" + backend.Service.Name

				v, ok := ctrl.watchedServices.Load(svcKey)
				if !ok {
					glog.Errorf("service %s not found", svcKey)
					continue
				}
				svc := v.(*v1.Service)

				// find port
				config, ok := getBackendConfig(&backend, svc)
				if !ok {
					glog.Errorf("port %s on service %s not found", backend.Service.Port.Name, svcKey)
					continue
				}
				if config.PortNumber <= 0 { // missing port
					continue
				}

				target := buildHostPort(ing.Namespace, backend.Service.Name, config.PortNumber)
				handler := ctrl.makeHandler(ing, svc, config, target)
				host := strings.ToLower(rule.Host)
				switch pathType {
				case networking.PathTypePrefix:
					// register path as prefix
					src := host + strings.TrimSuffix(path, "/")
					if path != "/" {
						routes[src] = h.ServeHandler(handler)
					}
					routes[src+"/"] = h.ServeHandler(handler)
					glog.V(1).Infof("registered: [prefix] %s => %s", src+"/", target)
				case networking.PathTypeExact:
					src := host + strings.TrimSuffix(path, "/")
					if path == "/" {
						glog.Warningf("register: %s => %s; path type exact at root path is not supported, switch to prefix", src, target)
						src = host + path
					}
					routes[src] = h.ServeHandler(handler)
					glog.V(1).Infof("registered: [exact] %s => %s", src, target)
				case networking.PathTypeImplementationSpecific:
					src := host + path
					routes[src] = h.ServeHandler(handler)
					glog.V(1).Infof("registered: [specific] %s => %s", src, target)
				}
			}
		}

		return true
	})

	mux := buildRoutes(routes)
	ctrl.mu.Lock()
	ctrl.mux = mux
	ctrl.mu.Unlock()
	ctrl.reloadSecret()
}

func (ctrl *Controller) reloadService() {
	ctrl.reloadServiceDebounce.Call()
}

func (ctrl *Controller) reloadServiceDebounced() {
	glog.Info("reload services")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
		}
	}()

	addrToPort := map[string]string{}

	ctrl.watchedServices.Range(func(_, value any) bool {
		s := value.(*v1.Service)

		// build route target port
		for _, p := range s.Spec.Ports {
			addr := buildHostPort(s.Namespace, s.Name, int(p.Port))
			target := strconv.Itoa(int(p.TargetPort.IntVal))
			addrToPort[addr] = target
		}

		return true
	})

	ctrl.routeTable.SetPortRoutes(addrToPort)
}

func (ctrl *Controller) reloadSecret() {
	ctrl.reloadSecretDebounce.Call()
}

func (ctrl *Controller) reloadSecretDebounced() {
	glog.Info("reload secrets")

	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
		}
	}()

	secretToBuild := map[string]struct{}{}

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)
		for _, t := range ing.Spec.TLS {
			key := ing.Namespace + "/" + t.SecretName
			secretToBuild[key] = struct{}{}
		}
		return true
	})

	// build certs
	var certs []*tls.Certificate
	for key := range secretToBuild {
		v, ok := ctrl.watchedSecrets.Load(key)
		if !ok {
			glog.Errorf("secret %s not found", key)
			continue
		}
		s := v.(*v1.Secret)
		crt, err := tls.X509KeyPair(s.Data["tls.crt"], s.Data["tls.key"])
		if err != nil {
			glog.Errorf("can not load x509 certificate %s/%s; %v", s.Namespace, s.Name, err)
			continue
		}
		certs = append(certs, &crt)
	}

	ctrl.certTable.Set(certs)
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

	routes := make(map[string]*route.RRLB)
	ctrl.watchedEndpoints.Range(func(_, value any) bool {
		ep := value.(*v1.Endpoints)
		if lb := endpointToRRLB(ep); lb != nil {
			routes[buildHost(ep.Namespace, ep.Name)] = lb
		}
		return true
	})

	ctrl.routeTable.SetHostRoutes(routes)
}

func (ctrl *Controller) reloadSingleEndpoint(ep *v1.Endpoints) {
	glog.Infof("reload endpoint: %s/%s", ep.Namespace, ep.Name)

	ctrl.routeTable.SetHostRoute(buildHost(ep.Namespace, ep.Name), endpointToRRLB(ep))
}

func (ctrl *Controller) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ctrl.certTable.Get(clientHello)
}

// Healthz returns health check middleware
func (ctrl *Controller) Healthz() parapet.Middleware {
	return ctrl.health
}

type backendConfig struct {
	Protocol   string
	PortName   string
	PortNumber int
}

func buildHost(namespace, name string) string {
	// service.namespace.svc.cluster.local
	return fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
}

func buildHostPort(namespace, name string, port int) string {
	// service.namespace.svc.cluster.local:port
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, namespace, port)
}

func buildRoutes(routes map[string]http.Handler) *http.ServeMux {
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
	return mux
}

func getIngressClass(ing *networking.Ingress) string {
	if ing.Spec.IngressClassName != nil {
		return *ing.Spec.IngressClassName
	}
	if ing.Annotations != nil {
		return ing.Annotations["kubernetes.io/ingress.class"]
	}
	return ""
}

func getBackendConfig(backend *networking.IngressBackend, svc *v1.Service) (config backendConfig, ok bool) {
	// specifies port by name
	if backend.Service.Port.Name != "" {
		config.PortName = backend.Service.Port.Name

		// find port number
		for _, p := range svc.Spec.Ports {
			if p.Name == backend.Service.Port.Name {
				config.PortNumber = int(p.Port)
				if p.AppProtocol != nil {
					config.Protocol = *p.AppProtocol
				}
			}
		}
		if config.PortNumber == 0 {
			return config, false
		}
		ok = true
		return
	}

	// specifies port by number
	config.PortNumber = int(backend.Service.Port.Number)

	// find port name
	for _, p := range svc.Spec.Ports {
		if p.Port == backend.Service.Port.Number {
			config.PortName = p.Name
			if p.AppProtocol != nil {
				config.Protocol = *p.AppProtocol
			}
		}
	}
	ok = true
	return
}

func (ctrl *Controller) makeHandler(ing *networking.Ingress, svc *v1.Service, config backendConfig, target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		nr.URL.Host = ctrl.routeTable.Lookup(target)
		ctrl.proxy.ServeHTTP(w, nr)
	})
}

func endpointToRRLB(ep *v1.Endpoints) *route.RRLB {
	var b route.RRLB
	for _, ss := range ep.Subsets {
		for _, addr := range ss.Addresses {
			b.IPs = append(b.IPs, addr.IP)
		}
	}
	if len(b.IPs) == 0 {
		return nil
	}
	return &b
}
