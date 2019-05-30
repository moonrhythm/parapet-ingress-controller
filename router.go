package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/body"
	"github.com/moonrhythm/parapet/pkg/hsts"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"gopkg.in/yaml.v2"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
)

type router struct{}

func (r router) ServeHandler(http.Handler) http.Handler {
	var mapper hostMapper

	go func() {
		for {
			w, err := client.ExtensionsV1beta1().Ingresses(namespace).Watch(metav1.ListOptions{})
			if err != nil {
				glog.Error("can not watch ingresses;", err)
				continue
			}

			result := w.ResultChan()

			for {
				event := <-result
				ing, ok := event.Object.(*v1beta1.Ingress)
				if !ok {
					break
				}

				if ing.Annotations["kubernetes.io/ingress.class"] != "parapet" {
					glog.Infof("skip %s/%s\n", ing.Namespace, ing.Name)
					continue
				}

				switch event.Type {
				case watch.Added, watch.Modified:
					glog.Infof("upsert %s/%s\n", ing.Namespace, ing.Name)
					mapper.Upsert(ing)
				case watch.Deleted:
					glog.Infof("delete %s/%s\n", ing.Namespace, ing.Name)
					mapper.Delete(ing)
				}
			}

			w.Stop()
		}
	}()

	return &mapper
}

type hostMapper struct {
	mu  sync.RWMutex
	raw map[string]*v1beta1.Ingress
	m   *http.ServeMux
}

func (m *hostMapper) Upsert(obj *v1beta1.Ingress) {
	if m.raw == nil {
		m.raw = make(map[string]*v1beta1.Ingress)
	}
	m.raw[obj.Namespace+"/"+obj.Name] = obj
	m.flush()
}

func (m *hostMapper) Delete(obj *v1beta1.Ingress) {
	if m.raw == nil {
		return
	}

	delete(m.raw, obj.Namespace+"/"+obj.Name)
	m.flush()
}

func (m *hostMapper) flush() {
	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
		}
	}()
	mux := http.NewServeMux()
	for _, ing := range m.raw {
		var h parapet.Middlewares
		if a := ing.Annotations["parapet.moonrhythm.io/hsts"]; a != "" {
			if a == "preload" {
				h.Use(hsts.Preload())
			} else {
				h.Use(hsts.Default())
			}
		}
		if a := ing.Annotations["parapet.moonrhythm.io/redirect"]; a != "" {
			var obj map[string]string
			yaml.Unmarshal([]byte(a), &obj)
			for srcHost, targetURL := range obj {
				if srcHost == "" || targetURL == "" || strings.HasPrefix(srcHost, "/") {
					return
				}
				if !strings.HasSuffix(srcHost, "/") {
					srcHost += "/"
				}

				target := targetURL
				status := http.StatusFound
				if ts := strings.SplitN(targetURL, ",", 2); len(ts) == 2 {
					st, _ := strconv.Atoi(ts[0])
					if st > 0 {
						status = st
						target = ts[1]
					}
				}

				mux.Handle(srcHost, h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target, status)
				})))
				glog.Infof("registered: %s ==> %d,%s", srcHost, status, target)
			}
		}
		if a := ing.Annotations["parapet.moonrhythm.io/ratelimit-s"]; a != "" {
			rate, _ := strconv.Atoi(a)
			if rate > 0 {
				h.Use(ratelimit.FixedWindowPerSecond(rate))
			}
		}
		if a := ing.Annotations["parapet.moonrhythm.io/ratelimit-m"]; a != "" {
			rate, _ := strconv.Atoi(a)
			if rate > 0 {
				h.Use(ratelimit.FixedWindowPerMinute(rate))
			}
		}
		if a := ing.Annotations["parapet.moonrhythm.io/ratelimit-h"]; a != "" {
			rate, _ := strconv.Atoi(a)
			if rate > 0 {
				h.Use(ratelimit.FixedWindowPerHour(rate))
			}
		}
		if a := ing.Annotations["parapet.moonrhythm.io/body-limitrequest"]; a != "" {
			size, _ := strconv.ParseInt(a, 10, 64)
			if size > 0 {
				h.Use(body.LimitRequest(size))
			}
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
					port = getServicePort(backend.ServiceName, backend.ServicePort.StrVal)
				}
				if port <= 0 {
					continue
				}

				src := rule.Host + path
				target := fmt.Sprintf("%s:%d", backend.ServiceName, port)
				mux.Handle(src, h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Host = target
					proxy.ServeHTTP(w, r)
				})))
				glog.Infof("registered: %s => %s:%d", src, backend.ServiceName, port)
			}
		}
	}

	m.mu.Lock()
	m.m = mux
	m.mu.Unlock()
}

func (m *hostMapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	mux := m.m
	m.mu.RUnlock()

	mux.ServeHTTP(w, r)
}

func getServicePort(serviceName, portName string) int {
	svc, err := client.CoreV1().Services(namespace).Get(serviceName, metav1.GetOptions{})
	if err != nil {
		glog.Error("can not get service %s/%s; %v\n", namespace, serviceName, err)
		return 0
	}

	for _, port := range svc.Spec.Ports {
		if port.Name == portName {
			return int(port.Port)
		}
	}
	return 0
}
