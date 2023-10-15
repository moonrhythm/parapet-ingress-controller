package metric

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const addrSizeHint = 300

type backendMetrics struct {
	connections prometheus.Gauge
	reads       prometheus.Counter
	writes      prometheus.Counter
}

type backendConnections struct {
	connections *prometheus.GaugeVec
	reads       *prometheus.CounterVec
	writes      *prometheus.CounterVec

	mu sync.RWMutex
	m  map[string]*backendMetrics // addr
}

var _backendConnections backendConnections

func init() {
	_backendConnections.connections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "backend_connections",
	}, []string{"addr"})
	_backendConnections.reads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_read_bytes",
	}, []string{"addr"})
	_backendConnections.writes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_write_bytes",
	}, []string{"addr"})
	_backendConnections.m = make(map[string]*backendMetrics, addrSizeHint)

	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.reads)
	prom.Registry().MustRegister(_backendConnections.writes)
}

func (p *backendConnections) getM(addr string) *backendMetrics {
	p.mu.RLock()
	m := p.m[addr]
	p.mu.RUnlock()

	if m == nil {
		p.mu.Lock()
		if p.m[addr] == nil {
			l := prometheus.Labels{
				"addr": addr,
			}
			p.m[addr] = &backendMetrics{
				connections: p.connections.With(l),
				reads:       p.reads.With(l),
				writes:      p.writes.With(l),
			}
		}
		m = p.m[addr]
		p.mu.Unlock()
	}

	return m
}

// BackendConnections collects backend connection metrics
func BackendConnections(conn net.Conn, addr string) net.Conn {
	m := _backendConnections.getM(addr)
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

func (conn *trackBackendConn) ReadFrom(r io.Reader) (n int64, err error) {
	n, err = conn.Conn.(io.ReaderFrom).ReadFrom(r)
	if n > 0 {
		conn.m.reads.Add(float64(n))
	}
	if err != nil {
		conn.trackClose()
	}
	return
}
