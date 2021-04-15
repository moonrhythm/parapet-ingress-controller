package k8s

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/golang/glog"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
)

type fsClient struct {
	mu        sync.RWMutex
	dir       string
	ingresses []v1beta1.Ingress
	services  []v1.Service
	endpoints []v1.Endpoints
	secrets   []v1.Secret
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
	c.endpoints = nil
	c.secrets = nil
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

func (c *fsClient) decode(raw []byte, out interface{}) error {
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
			glog.Warningf("can not add object %s", raw)
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
		glog.Warningf("unsupport object %s.%s", meta.APIVersion, meta.Kind)
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
	}:
		var ing v1beta1.Ingress
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

func (c *fsClient) GetIngresses(ctx context.Context, namespace string) ([]v1beta1.Ingress, error) {
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

func (c *fsClient) GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpoints, nil
}

func (c *fsClient) WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error) {
	ch := make(chan watch.Event)
	return watch.NewProxyWatcher(ch), nil
}
