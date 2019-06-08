package metric

import (
	"net/http"
	"strconv"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

func Requests() parapet.Middleware {
	return &_promRequests
}

var _promRequests promRequests

type promRequests struct {
	vec *prometheus.CounterVec
}

func init() {
	_promRequests.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "requests",
	}, []string{"host", "status", "method", "ingress_name", "ingress_namespace"})
	prom.Registry().MustRegister(_promRequests.vec)
}

func (p *promRequests) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		l := prometheus.Labels{
			"method": r.Method,
			"host":   r.Host,
		}
		nw := requestTrackRW{
			ResponseWriter: w,
		}
		defer func() {
			l["status"] = strconv.Itoa(nw.status)
			l["ingress_name"], _ = logger.Get(ctx, "ingress").(string)
			l["ingress_namespace"], _ = logger.Get(ctx, "namespace").(string)
			counter, err := p.vec.GetMetricWith(l)
			if err != nil {
				return
			}
			counter.Inc()
		}()

		h.ServeHTTP(&nw, r)
	})
}

type requestTrackRW struct {
	http.ResponseWriter

	wroteHeader bool
	status      int
}

func (w *requestTrackRW) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *requestTrackRW) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
