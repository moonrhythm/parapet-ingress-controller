package metric

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const backendSizeHint = 100

type backendMetrics struct {
	connections prometheus.Gauge
	reads       prometheus.Counter
	writes      prometheus.Counter
}

// backendKey identifies the backend Service a connection belongs to. Keying on
// the Service (not the dialed pod IP:port) keeps the series count bounded by the
// number of Services — pods churn on every deploy/scale, and an addr-keyed
// handle cache never evicts, so stale per-pod series would accumulate at 0/
// constant for the life of the process. A pod address belongs to exactly one
// Service, so attributing the connection to it at dial time is stable.
type backendKey struct {
	serviceType      string
	serviceNamespace string
	serviceName      string
}

type backendConnections struct {
	connections *prometheus.GaugeVec
	reads       *prometheus.CounterVec
	writes      *prometheus.CounterVec

	cache *cache[backendKey, *backendMetrics]
}

var _backendConnections backendConnections

func init() {
	labels := []string{"service_type", "service_namespace", "service_name"}
	_backendConnections.connections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "backend_connections",
	}, labels)
	_backendConnections.reads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_read_bytes",
	}, labels)
	_backendConnections.writes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_write_bytes",
	}, labels)
	_backendConnections.cache = newCache[backendKey, *backendMetrics](backendSizeHint)

	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.reads)
	prom.Registry().MustRegister(_backendConnections.writes)
}

func (p *backendConnections) getM(key backendKey) *backendMetrics {
	return p.cache.getOrCreate(key, func() *backendMetrics {
		l := prometheus.Labels{
			"service_type":      key.serviceType,
			"service_namespace": key.serviceNamespace,
			"service_name":      key.serviceName,
		}
		return &backendMetrics{
			connections: p.connections.With(l),
			reads:       p.reads.With(l),
			writes:      p.writes.With(l),
		}
	})
}

// BackendConnections collects backend connection metrics, attributed to the
// destination Service (serviceType/namespace/name) rather than the dialed pod
// address — see backendKey for why.
func BackendConnections(conn net.Conn, serviceType, serviceNamespace, serviceName string) net.Conn {
	m := _backendConnections.getM(backendKey{
		serviceType:      serviceType,
		serviceNamespace: serviceNamespace,
		serviceName:      serviceName,
	})
	trackConn := &trackBackendConn{
		Conn: conn,
		m:    m,
	}
	m.connections.Inc()

	return trackConn
}

type trackBackendConn struct {
	net.Conn
	m      *backendMetrics
	closed int32
}

func (conn *trackBackendConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if n > 0 {
		conn.m.reads.Add(float64(n))
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if n > 0 {
		conn.m.writes.Add(float64(n))
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) trackClose() {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		conn.m.connections.Dec()
	}
}

func (conn *trackBackendConn) Close() error {
	conn.trackClose()
	return conn.Conn.Close()
}

// ReadFrom implements io.ReaderFrom so the sendfile/splice fast path
// (io.Copy(conn, r), used by the transport when flushing request bodies)
// stays zero-copy. Data flows from r into the socket — i.e. it is written
// to the backend — so it counts toward writes, not reads.
func (conn *trackBackendConn) ReadFrom(r io.Reader) (n int64, err error) {
	n, err = conn.Conn.(io.ReaderFrom).ReadFrom(r)
	if n > 0 {
		conn.m.writes.Add(float64(n))
	}
	if err != nil {
		conn.trackClose()
	}
	return
}
