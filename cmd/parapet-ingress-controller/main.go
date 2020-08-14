package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"

	controller "github.com/moonrhythm/parapet-ingress-controller"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

var version = "HEAD"

func main() {
	flag.Parse()

	httpPort := config.StringDefault("HTTP_PORT", "80")
	httpsPort := config.StringDefault("HTTPS_PORT", "443")
	podNamespace := config.String("POD_NAMESPACE")
	watchNamespace := config.StringDefault("WATCH_NAMESPACE", "")
	enableProfiler := config.Bool("PROFILER")
	disableLog := config.Bool("DISABLE_LOG")
	hostname, _ := os.Hostname()

	glog.Infoln("parapet-ingress-controller")
	glog.Infoln("version:", version)
	glog.Infoln("hostname:", hostname)
	glog.Infoln("http_port:", httpPort)
	glog.Infoln("https_port:", httpsPort)
	glog.Infoln("pod_namespace:", podNamespace)
	glog.Infoln("watch_namespace:", watchNamespace)
	glog.Infoln("profiler:", enableProfiler)

	if enableProfiler {
		err := profiler.Start(profiler.Config{
			Service:        "parapet-ingress-controller",
			ServiceVersion: version,
			Instance:       hostname,
		})
		if err != nil {
			glog.Errorf("can not start profiler: %v", err)
		}
	}

	err := k8s.Init()
	if err != nil {
		glog.Fatal(err)
		os.Exit(1)
	}

	go prom.Start(":9187")

	ctrl := controller.New(watchNamespace)
	ctrl.Use(plugin.InjectStateIngress)
	ctrl.Use(plugin.AllowRemote)
	ctrl.Use(plugin.RedirectHTTPS)
	ctrl.Use(plugin.InjectHSTS)
	ctrl.Use(plugin.RedirectRules)
	ctrl.Use(plugin.RateLimit)
	ctrl.Use(plugin.BodyLimit)
	ctrl.Use(plugin.UpstreamProtocol)
	ctrl.Use(plugin.UpstreamHost)
	ctrl.Use(plugin.BasicAuth)
	go ctrl.Watch()

	m := parapet.Middlewares{}
	m.Use(ctrl.Healthz())
	m.Use(parapet.MiddlewareFunc(lowerCaseHost))
	if !disableLog {
		m.Use(logger.Stdout())
	}
	m.Use(state.Middleware())
	m.Use(metric.Requests())
	m.Use(compress.Gzip())
	m.Use(compress.Br())
	m.Use(ctrl)

	var trustProxy parapet.Conditional
	{
		p := config.String("TRUST_PROXY")
		switch p {
		case "true":
			trustProxy = parapet.Trusted()
		case "false", "":
		default:
			trustProxy = parapet.TrustCIDRs(config.Strings("TRUST_PROXY"))
		}
	}

	// http
	{
		s := &parapet.Server{
			Addr:               ":" + httpPort,
			TrustProxy:         trustProxy,
			IdleTimeout:        60 * time.Second,
			TCPKeepAlivePeriod: 1 * time.Minute,
			GraceTimeout:       1 * time.Minute,
			WaitBeforeShutdown: 30 * time.Second,
			Handler:            http.NotFoundHandler(),
		}
		prom.Connections(s)
		prom.Networks(s)

		s.Use(m)

		go func() {
			err := s.ListenAndServe()
			if err != nil {
				glog.Fatal(err)
				os.Exit(1)
			}
		}()
	}

	// https
	{
		cert, err := parapet.GenerateSelfSignCertificate(parapet.SelfSign{
			CommonName: "parapet-ingress-controller",
		})
		if err != nil {
			glog.Fatal(err)
			os.Exit(1)
		}

		s := &parapet.Server{
			Addr:               ":" + httpsPort,
			TrustProxy:         trustProxy,
			IdleTimeout:        320 * time.Second,
			TCPKeepAlivePeriod: 1 * time.Minute,
			GraceTimeout:       1 * time.Minute,
			WaitBeforeShutdown: 30 * time.Second,
			Handler:            http.NotFoundHandler(),
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.X25519,
					tls.CurveP256,
				},
				PreferServerCipherSuites: true,
				Certificates:             []tls.Certificate{cert},
				GetCertificate:           ctrl.GetCertificate,
			},
		}
		tlsSessionTicketKey := config.Base64("TLS_SESSION_TICKET_KEY")
		if l := len(tlsSessionTicketKey); l > 0 {
			if l == 32 {
				copy(s.TLSConfig.SessionTicketKey[:], tlsSessionTicketKey)
			} else {
				glog.Error("invalid TLS_SESSION_TICKET_KEY")
			}
		}
		prom.Connections(s)
		prom.Networks(s)

		s.Use(m)

		err = s.ListenAndServe()
		if err != nil {
			glog.Fatal(err)
			os.Exit(1)
		}
	}
}

func lowerCaseHost(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = strings.ToLower(r.Host)
		h.ServeHTTP(w, r)
	})
}
