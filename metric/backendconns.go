package metric

import (
	"net"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

type backendConnections struct {
	connections *prometheus.GaugeVec
	requests    *prometheus.CounterVec
	responses   *prometheus.CounterVec
}

var _backendConnections backendConnections

func init() {
	_backendConnections.connections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "backend_connections",
	}, []string{"backend"})
	_backendConnections.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_request_bytes",
	}, []string{"backend"})
	_backendConnections.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_response_bytes",
	}, []string{"backend"})
	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.requests)
	prom.Registry().MustRegister(_backendConnections.responses)
}

func (p *backendConnections) inc(addr string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{"backend": addr})
	if err != nil {
		return
	}
	c.Inc()
}

func (p *backendConnections) dec(addr string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{"backend": addr})
	if err != nil {
		return
	}
	c.Dec()
}

func (p *backendConnections) read(addr string, n int) {
	c, err := p.requests.GetMetricWith(prometheus.Labels{"backend": addr})
	if err != nil {
		return
	}
	c.Add(float64(n))
}

func (p *backendConnections) write(addr string, n int) {
	c, err := p.responses.GetMetricWith(prometheus.Labels{"backend": addr})
	if err != nil {
		return
	}
	c.Add(float64(n))
}

// BackendConnections collects backend connection metrics
func BackendConnections(conn net.Conn, addr string) net.Conn {
	_backendConnections.inc(addr)

	return &trackBackendConn{
		Conn: conn,
		addr: addr,
	}
}

type trackBackendConn struct {
	net.Conn
	addr   string
	closed int32
}

func (conn *trackBackendConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if n > 0 {
		_backendConnections.read(conn.addr, n)
	}
	return
}

func (conn *trackBackendConn) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if n > 0 {
		_backendConnections.write(conn.addr, n)
	}
	return
}

func (conn *trackBackendConn) Close() error {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		_backendConnections.dec(conn.addr)
	}
	return conn.Conn.Close()
}
