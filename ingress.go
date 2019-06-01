package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/body"
	"github.com/moonrhythm/parapet/pkg/hsts"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"github.com/moonrhythm/parapet/pkg/redirect"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
)

type ingressController struct {
	mu sync.RWMutex
	m  *http.ServeMux

	debounceMu    sync.Mutex
	debounceTimer *time.Timer
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
		w, err := client.ExtensionsV1beta1().Ingresses(namespace).Watch(metav1.ListOptions{})
		if err != nil {
			glog.Error("can not watch ingresses;", err)
			time.Sleep(5 * time.Second)
			continue
		}

		result := w.ResultChan()

		for {
			event := <-result
			if event.Type == watch.Error {
				break
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
	list, err := getIngresses()
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	for _, ing := range list {
		if ing.Annotations == nil || ing.Annotations["kubernetes.io/ingress.class"] != ingressClass {
			glog.Infof("skip: %s/%s", ing.Namespace, ing.Name)
			continue
		}
		glog.Infof("load: %s/%s", ing.Namespace, ing.Name)

		var h parapet.Middlewares
		h.Use(injectIngress{Namespace: ing.Namespace, Name: ing.Name})

		if a := ing.Annotations["parapet.moonrhythm.io/redirect-https"]; a == "true" {
			h.Use(redirect.HTTPS())
		}
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
					// TODO: add to watched services
					port = getServicePort(ing.Namespace, backend.ServiceName, backend.ServicePort.StrVal)
				}
				if port <= 0 {
					continue
				}

				src := rule.Host + path
				// service.namespace.svc.cluster.local:port
				target := fmt.Sprintf("%s.%s.svc.cluster.local:%d", backend.ServiceName, ing.Namespace, port)
				mux.Handle(src, h.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Host = target
					proxy.ServeHTTP(w, r)
				})))
				glog.Infof("registered: %s => %s", src, target)
			}
		}
	}

	ctrl.mu.Lock()
	ctrl.m = mux
	ctrl.mu.Unlock()
}

type injectIngress struct {
	Namespace string
	Name      string
}

func (m injectIngress) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger.Set(ctx, "namespace", m.Namespace)
		logger.Set(ctx, "ingress", m.Name)
		h.ServeHTTP(w, r)
	})
}
