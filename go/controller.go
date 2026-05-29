package controller

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/waf"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/go/cert"
	"github.com/moonrhythm/parapet-ingress-controller/go/debounce"
	"github.com/moonrhythm/parapet-ingress-controller/go/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/go/metric"
	"github.com/moonrhythm/parapet-ingress-controller/go/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/go/proxy"
	"github.com/moonrhythm/parapet-ingress-controller/go/route"
	"github.com/moonrhythm/parapet-ingress-controller/go/state"
)

// IngressClass to load ingresses
var IngressClass = "parapet"

const (
	routeSizeHint    = 500
	endpointSizeHint = 500
	secretSizeHint   = 50
)

// Controller is the parapet ingress controller
type Controller struct {
	// mu is the mutex for mux
	mu  sync.RWMutex
	mux *http.ServeMux
	// knownHosts is the set of hosts the current mux serves (the host part of
	// each registered route). Guarded by mu and swapped atomically with mux on
	// reload. Used to bound host-labeled metric cardinality: a Host the router
	// doesn't serve collapses to a sentinel label instead of creating an
	// unbounded number of series under a random-Host flood.
	knownHosts map[string]struct{}

	// namespace to watch, or empty to watch all
	watchNamespace string

	// LoadAllCerts, when true, builds the cert table from every TLS-typed
	// secret in the watch namespace instead of only those referenced by an
	// Ingress's spec.tls.secretName. The cert table already does SNI lookup
	// with wildcard climbing, so enabling this lets a wildcard cert serve any
	// matching subdomain without the user (or operator) having to wire the
	// matching secret into each ingress. Off by default to preserve behavior.
	LoadAllCerts bool

	// WAFConfig configures the web application firewall; PodNamespace is the
	// controller's own namespace, which bounds where the global ruleset may be
	// defined. Both are set before Watch(). See controller_waf.go.
	WAFConfig    WAFConfig
	PodNamespace string

	// globalWAF is the always-on baseline firewall; zones holds the tenant zone
	// registry keyed by <namespace>/<name>, swapped atomically on WAF reload.
	// WAF reloads are decoupled from the mux — they never rebuild routes.
	globalWAF *waf.WAF
	zones     atomic.Pointer[map[string]*waf.WAF]

	// WAF rule-input fingerprints from the last reload, used to skip recompiling
	// CEL rulesets whose effective input (the sorted concatenated rule YAML) is
	// byte-for-byte unchanged. Only ever read/written from reloadWAFDebounced,
	// which the debounce serializes, so they need no lock.
	globalWAFFingerprint string
	zoneFingerprints     map[string]string

	// holds current k8s state
	watchedIngresses  sync.Map
	watchedServices   sync.Map
	watchedSecrets    sync.Map
	watchedEndpoints  sync.Map
	watchedConfigMaps sync.Map

	certTable  cert.Table
	routeTable route.Table

	proxy *proxy.Proxy

	plugins []plugin.Plugin
	health  *healthz.Healthz

	reloadIngressDebounce *debounce.Debounce
	reloadServiceDebounce *debounce.Debounce
	reloadSecretDebounce  *debounce.Debounce
	reloadWAFDebounce     *debounce.Debounce
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
	ctrl.reloadWAFDebounce = debounce.New(ctrl.reloadWAFDebounced, 300*time.Millisecond)
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

	ctrl.preloadResources(ctx)
	ctrl.firstReload()

	go ctrl.watchIngresses(ctx)
	go ctrl.watchServices(ctx)
	go ctrl.watchSecrets(ctx)
	go ctrl.watchEndpoints(ctx)
	if ctrl.WAFConfig.Enabled {
		go ctrl.watchConfigMaps(ctx)
	}
}

func (ctrl *Controller) preloadResources(ctx context.Context) {
	ingresses, _ := k8s.GetIngresses(ctx, ctrl.watchNamespace)
	for _, i := range ingresses {
		ctrl.watchedIngresses.Store(i.Namespace+"/"+i.Name, &i)
	}

	services, _ := k8s.GetServices(ctx, ctrl.watchNamespace)
	for _, s := range services {
		ctrl.watchedServices.Store(s.Namespace+"/"+s.Name, &s)
	}

	secrets, _ := k8s.GetSecrets(ctx, ctrl.watchNamespace)
	for _, s := range secrets {
		ctrl.watchedSecrets.Store(s.Namespace+"/"+s.Name, &s)
	}

	endpoints, _ := k8s.GetEndpoints(ctx, ctrl.watchNamespace)
	for _, e := range endpoints {
		ctrl.watchedEndpoints.Store(e.Namespace+"/"+e.Name, &e)
	}

	if ctrl.WAFConfig.Enabled {
		configmaps, _ := k8s.GetConfigMaps(ctx, ctrl.watchNamespace, wafLabelKey)
		for _, cm := range configmaps {
			ctrl.watchedConfigMaps.Store(cm.Namespace+"/"+cm.Name, &cm)
		}
	}
}

func (ctrl *Controller) firstReload() {
	ctrl.reloadServiceDebounced()
	ctrl.reloadIngressDebounced()
	ctrl.reloadSecretDebounced()
	ctrl.reloadEndpointDebounced()
	ctrl.reloadWAFDebounced() // no-op when WAF disabled

	// ready to serve requests
	ctrl.health.SetReady(true)
}

// watchResource runs a resilient watch loop for a single Kubernetes resource
// type: it (re)starts the watch on error, mirrors Added/Modified/Deleted events
// into store, and invokes onUpsert / onDelete so the caller triggers the right
// reload. PT is the pointer type of T (e.g. *networking.Ingress); the
// metav1.Object constraint gives access to the object's namespace and name.
// onDelete receives the deleted object so a caller can reload incrementally
// (e.g. drop just that one host) instead of rebuilding from the whole store.
func watchResource[T any, PT interface {
	*T
	metav1.Object
}](
	ctx context.Context,
	namespace, name string,
	watchFn func(ctx context.Context, namespace string) (watch.Interface, error),
	store *sync.Map,
	onUpsert func(obj PT),
	onDelete func(obj PT),
) {
	for {
		w, err := watchFn(ctx, namespace)
		if err != nil {
			slog.Error("can not watch "+name, "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj, ok := event.Object.(PT)
			if !ok {
				continue
			}
			key := obj.GetNamespace() + "/" + obj.GetName()

			switch event.Type {
			case watch.Added, watch.Modified:
				store.Store(key, obj)
				onUpsert(obj)
			case watch.Deleted:
				store.Delete(key)
				onDelete(obj)
			default:
				continue
			}
		}

		w.Stop()
		slog.Info("restart " + name + " watcher")
	}
}

func (ctrl *Controller) watchIngresses(ctx context.Context) {
	watchResource(ctx, ctrl.watchNamespace, "ingresses", k8s.WatchIngresses,
		&ctrl.watchedIngresses,
		func(_ *networking.Ingress) { ctrl.reloadIngress() },
		func(_ *networking.Ingress) { ctrl.reloadIngress() },
	)
}

func (ctrl *Controller) watchServices(ctx context.Context) {
	// a service change can change both port routing and which ingress backends
	// resolve, so refresh both tables.
	reload := func() {
		ctrl.reloadService()
		ctrl.reloadIngress()
	}
	watchResource(ctx, ctrl.watchNamespace, "services", k8s.WatchServices,
		&ctrl.watchedServices,
		func(_ *v1.Service) { reload() },
		func(_ *v1.Service) { reload() },
	)
}

func (ctrl *Controller) watchSecrets(ctx context.Context) {
	watchResource(ctx, ctrl.watchNamespace, "secrets", k8s.WatchSecrets,
		&ctrl.watchedSecrets,
		func(_ *v1.Secret) { ctrl.reloadSecret() },
		func(_ *v1.Secret) { ctrl.reloadSecret() },
	)
}

func (ctrl *Controller) watchEndpoints(ctx context.Context) {
	// a single endpoint event only touches its own service's host, so both
	// upsert and delete update just that one host in place instead of rebuilding
	// the whole endpoint table. The full rebuild (reloadEndpointDebounced) is
	// reserved for the initial sync / resync in firstReload, where the entire
	// set is (re)listed.
	watchResource(ctx, ctrl.watchNamespace, "endpoints", k8s.WatchEndpoints,
		&ctrl.watchedEndpoints,
		ctrl.reloadSingleEndpoint,
		ctrl.deleteSingleEndpoint,
	)
}

func (ctrl *Controller) reloadIngress() {
	ctrl.reloadIngressDebounce.Call()
}

func (ctrl *Controller) reloadIngressDebounced() {
	slog.Info("reload ingresses")

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload ingresses failed", "error", err)
			metric.Reload(false)
			return
		}
		metric.Reload(true)
	}()

	routes := make(map[string]http.Handler, routeSizeHint)

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)

		if getIngressClass(ing) != IngressClass {
			slog.Info("skip ingress", "namespace", ing.Namespace, "name", ing.Name)
			return true
		}

		slog.Info("load ingress", "namespace", ing.Namespace, "name", ing.Name)

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
			slog.Warn("ingress spec.defaultBackend not support", "namespace", ing.Namespace, "name", ing.Name)
		}

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, httpPath := range rule.HTTP.Paths {
				backend := httpPath.Backend
				if backend.Service == nil {
					slog.Warn("ingress backend service empty", "namespace", ing.Namespace, "name", ing.Name)
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
					slog.Error("service not found", "namespace", ing.Namespace, "name", backend.Service.Name)
					continue
				}
				svc := v.(*v1.Service)

				// find port
				config, ok := getBackendConfig(&backend, svc)
				if !ok {
					slog.Error("port not found", "namespace", ing.Namespace, "name", backend.Service.Name, "port", backend.Service.Port.Name)
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
					src += "/"
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "prefix", "path", src, "target", target)
				case networking.PathTypeExact:
					src := host + strings.TrimSuffix(path, "/")
					if path == "/" {
						slog.Warn("register path type exact at root path is not supported, switch to prefix", "path", src, "target", target)
						src = host + path
					}
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "exact", "path", src, "target", target)
				case networking.PathTypeImplementationSpecific:
					src := host + path
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "specific", "path", src, "target", target)
				}
			}
		}

		return true
	})

	mux := buildRoutes(routes)
	knownHosts := buildKnownHosts(routes)
	ctrl.mu.Lock()
	ctrl.mux = mux
	ctrl.knownHosts = knownHosts
	ctrl.mu.Unlock()
	ctrl.reloadSecret()
}

// buildKnownHosts extracts the distinct host part (everything before the first
// '/') of each registered route key. Host-less routes (keys starting with '/')
// contribute nothing.
func buildKnownHosts(routes map[string]http.Handler) map[string]struct{} {
	hosts := make(map[string]struct{}, len(routes))
	for r := range routes {
		if i := strings.IndexByte(r, '/'); i > 0 {
			hosts[r[:i]] = struct{}{}
		}
	}
	return hosts
}

// IsKnownHost reports whether the current routes serve host (already lowercased
// and port-stripped by the upstream middleware, matching the registered keys).
func (ctrl *Controller) IsKnownHost(host string) bool {
	ctrl.mu.RLock()
	_, ok := ctrl.knownHosts[host]
	ctrl.mu.RUnlock()
	return ok
}

func (ctrl *Controller) reloadService() {
	ctrl.reloadServiceDebounce.Call()
}

func (ctrl *Controller) reloadServiceDebounced() {
	slog.Info("reload services")

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload services failed", "error", err)
		}
	}()

	addrToPort := make(map[string]string, endpointSizeHint)

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
	slog.Info("reload secrets")

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload secrets failed", "error", err)
		}
	}()

	var certs []*tls.Certificate

	if ctrl.LoadAllCerts {
		// Load every TLS-typed secret in the watch namespace. The cert table
		// indexes by SAN and does SNI lookup with wildcard climbing, so this
		// is enough for a wildcard cert in tls-example-com to serve SNI for
		// foo.example.com without any ingress wiring.
		ctrl.watchedSecrets.Range(func(_, value any) bool {
			s := value.(*v1.Secret)
			if s.Type != v1.SecretTypeTLS {
				return true
			}
			crt, err := tls.X509KeyPair(s.Data["tls.crt"], s.Data["tls.key"])
			if err != nil {
				slog.Error("can not load x509 certificate", "namespace", s.Namespace, "name", s.Name, "error", err)
				return true
			}
			certs = append(certs, &crt)
			return true
		})
		ctrl.certTable.Set(certs)
		return
	}

	secretToBuild := make(map[string]struct{}, secretSizeHint)

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)
		for _, t := range ing.Spec.TLS {
			key := ing.Namespace + "/" + t.SecretName
			secretToBuild[key] = struct{}{}
		}
		return true
	})

	// build certs
	for key := range secretToBuild {
		v, ok := ctrl.watchedSecrets.Load(key)
		if !ok {
			slog.Error("secret not found", "key", key)
			continue
		}
		s := v.(*v1.Secret)
		crt, err := tls.X509KeyPair(s.Data["tls.crt"], s.Data["tls.key"])
		if err != nil {
			slog.Error("can not load x509 certificate", "namespace", s.Namespace, "name", s.Name, "error", err)
			continue
		}
		certs = append(certs, &crt)
	}

	ctrl.certTable.Set(certs)
}

// reloadEndpointDebounced rebuilds the entire host -> pod-IP table from the
// whole watched-endpoints store. It is the initial-sync / resync path (called
// from firstReload); steady-state endpoint events are applied incrementally
// per host by reloadSingleEndpoint / deleteSingleEndpoint and never come here.
func (ctrl *Controller) reloadEndpointDebounced() {
	slog.Info("reload endpoints")

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload endpoints failed", "error", err)
		}
	}()

	routes := make(map[string]*route.RRLB, endpointSizeHint)
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
	slog.Info("reload single endpoint", "namespace", ep.Namespace, "name", ep.Name)

	ctrl.routeTable.SetHostRoute(buildHost(ep.Namespace, ep.Name), endpointToRRLB(ep))
}

func (ctrl *Controller) deleteSingleEndpoint(ep *v1.Endpoints) {
	slog.Info("delete single endpoint", "namespace", ep.Namespace, "name", ep.Name)

	// the host is gone, so drop just that one entry; passing nil makes
	// SetHostRoute delete it, leaving the rest of the table untouched.
	ctrl.routeTable.SetHostRoute(buildHost(ep.Namespace, ep.Name), nil)
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
	return name + "." + namespace + ".svc.cluster.local"
}

func buildHostPort(namespace, name string, port int) string {
	// service.namespace.svc.cluster.local:port
	return name + "." + namespace + ".svc.cluster.local:" + strconv.Itoa(port)
}

func buildRoutes(routes map[string]http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	for r, h := range routes {
		func() {
			defer func() {
				err := recover()
				if err != nil {
					slog.Error("register handler failed", "path", r, "error", err)
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
	// since port name is required in kubernetes, we can assume that port name is always available
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
		s := state.Get(r.Context())
		s["serviceType"] = string(svc.Spec.Type)
		s["serviceName"] = svc.Name

		target := ctrl.routeTable.Lookup(target)
		if target == "" { // fail fast
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		if config.Protocol != "" {
			r.URL.Scheme = config.Protocol
		}
		r.RemoteAddr = "" // prevent httputil.ReverseProxy append remote addr to XFF
		r.URL.Host = target

		s["serviceTarget"] = target

		ctrl.proxy.ServeHTTP(w, r)
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
