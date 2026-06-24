package k8s

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
)

type fsClient struct {
	mu             sync.RWMutex
	dir            string
	ingresses      []networking.Ingress
	services       []v1.Service
	endpointSlices []discovery.EndpointSlice
	endpoints      []v1.Endpoints
	secrets        []v1.Secret
	configmaps     []v1.ConfigMap
}

func newFSClient(dir string) (*fsClient, error) {
	c := &fsClient{
		dir: dir,
	}
	err := c.load()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *fsClient) reset() {
	c.ingresses = nil
	c.services = nil
	c.endpointSlices = nil
	c.endpoints = nil
	c.secrets = nil
	c.configmaps = nil
}

func (c *fsClient) load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reset()

	err := filepath.WalkDir(c.dir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(filepath.Join(c.dir, d.Name()))
		if err != nil {
			return err
		}

		c.addObject(data)

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *fsClient) decode(raw []byte, out any) error {
	return yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 32*1024).Decode(out)
}

func (c *fsClient) decodeDocuments(raw []byte) ([][]byte, error) {
	var rs [][]byte
	rd := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		r, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return rs, nil
}

func (c *fsClient) addObject(raw []byte) {
	ok := false
	defer func() {
		if !ok {
			slog.Warn("can not add object", "data", string(raw))
		}
	}()

	docs, err := c.decodeDocuments(raw)
	if len(docs) > 1 {
		for _, doc := range docs {
			c.addObject(doc)
		}
		ok = true
		return
	}

	var meta runtime.TypeMeta
	err = c.decode(raw, &meta)
	if err != nil {
		return
	}

	switch meta {
	default:
		slog.Warn("unsupported object", "apiVersion", meta.APIVersion, "kind", meta.Kind)
		return
	case runtime.TypeMeta{
		APIVersion: "v1",
		Kind:       "List",
	}:
		var list v1.List
		err := c.decode(raw, &list)
		if err != nil {
			return
		}
		for _, it := range list.Items {
			c.addObject(it.Raw)
		}
	case runtime.TypeMeta{
		APIVersion: "extensions/v1beta1",
		Kind:       "Ingress",
	}, runtime.TypeMeta{
		APIVersion: "networking.k8s.io/v1",
		Kind:       "Ingress",
	}:
		var ing networking.Ingress
		err := c.decode(raw, &ing)
		if err != nil {
			return
		}
		c.autofillMeta(&ing.ObjectMeta)
		c.ingresses = append(c.ingresses, ing)
	case runtime.TypeMeta{
		APIVersion: "v1",
		Kind:       "Service",
	}:
		var svc v1.Service
		err := c.decode(raw, &svc)
		if err != nil {
			return
		}
		c.autofillMeta(&svc.ObjectMeta)
		c.services = append(c.services, svc)
	case runtime.TypeMeta{
		APIVersion: "discovery.k8s.io/v1",
		Kind:       "EndpointSlice",
	}:
		var es discovery.EndpointSlice
		err := c.decode(raw, &es)
		if err != nil {
			return
		}
		c.autofillMeta(&es.ObjectMeta)
		c.endpointSlices = append(c.endpointSlices, es)
	case runtime.TypeMeta{
		APIVersion: "v1",
		Kind:       "Endpoints",
	}:
		var ep v1.Endpoints
		err := c.decode(raw, &ep)
		if err != nil {
			return
		}
		c.autofillMeta(&ep.ObjectMeta)
		c.endpoints = append(c.endpoints, ep)
	case runtime.TypeMeta{
		APIVersion: "v1",
		Kind:       "Secret",
	}:
		var s v1.Secret
		err := c.decode(raw, &s)
		if err != nil {
			return
		}
		c.autofillMeta(&s.ObjectMeta)
		c.secrets = append(c.secrets, s)
	case runtime.TypeMeta{
		APIVersion: "v1",
		Kind:       "ConfigMap",
	}:
		var cm v1.ConfigMap
		err := c.decode(raw, &cm)
		if err != nil {
			return
		}
		c.autofillMeta(&cm.ObjectMeta)
		c.configmaps = append(c.configmaps, cm)
	}
	ok = true
}

func (c *fsClient) autofillMeta(meta *metav1.ObjectMeta) {
	if meta.Namespace == "" {
		meta.Namespace = "default"
	}
}

func (c *fsClient) WatchIngresses(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}

func (c *fsClient) GetServices(ctx context.Context, namespace string) ([]v1.Service, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.services, nil
}

func (c *fsClient) WatchServices(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}

func (c *fsClient) GetIngresses(ctx context.Context, namespace string) ([]networking.Ingress, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ingresses, nil
}

func (c *fsClient) GetSecrets(ctx context.Context, namespace string) ([]v1.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.secrets, nil
}

func (c *fsClient) WatchSecrets(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}

// GetSecret returns a copy of the named secret, or a NotFound error. The fs backend
// is for local dev / tests; namespace is matched only when the fixture sets one.
func (c *fsClient) GetSecret(ctx context.Context, namespace, name string) (*v1.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.secrets {
		s := &c.secrets[i]
		if s.Name == name && (namespace == "" || s.Namespace == "" || s.Namespace == namespace) {
			cp := s.DeepCopy()
			return cp, nil
		}
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
}

// UpdateSecret replaces (or appends) the secret in memory. Best-effort and NON-CAS
// (no resourceVersion semantics) — dev-only; the cluster backend is the real CAS.
func (c *fsClient) UpdateSecret(ctx context.Context, namespace string, secret *v1.Secret) (*v1.Secret, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.secrets {
		if c.secrets[i].Name == secret.Name {
			c.secrets[i] = *secret.DeepCopy()
			return secret.DeepCopy(), nil
		}
	}
	c.secrets = append(c.secrets, *secret.DeepCopy())
	return secret.DeepCopy(), nil
}

func (c *fsClient) GetEndpointSlices(ctx context.Context, namespace string) ([]discovery.EndpointSlice, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpointSlices, nil
}

func (c *fsClient) WatchEndpointSlices(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}

func (c *fsClient) GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpoints, nil
}

func (c *fsClient) WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}

// GetConfigMaps returns all loaded config maps. The label selector is ignored
// here (the fs backend has no label index); the controller filters by the
// label value (parapet.moonrhythm.io/waf, parapet.moonrhythm.io/ratelimit)
// after listing, so the unfiltered list is safe — unlabeled ConfigMaps fall
// through each reloader's role switch.
func (c *fsClient) GetConfigMaps(ctx context.Context, namespace, labelSelector string) ([]v1.ConfigMap, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configmaps, nil
}

func (c *fsClient) WatchConfigMaps(ctx context.Context, namespace, labelSelector string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}
