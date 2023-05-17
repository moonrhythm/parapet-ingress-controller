package metric

import (
	"net"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

type backendConnections struct {
	connections *prometheus.GaugeVec
	reads       *prometheus.CounterVec
	writes      *prometheus.CounterVec
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
	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.reads)
	prom.Registry().MustRegister(_backendConnections.writes)
}

func (p *backendConnections) getConnectionGauge(addr string) prometheus.Gauge {
	c, _ := p.connections.GetMetricWith(prometheus.Labels{
		"addr": addr,
	})
	return c
}

func (p *backendConnections) getReadCounter(addr string) prometheus.Counter {
	c, _ := p.reads.GetMetricWith(prometheus.Labels{
		"addr": addr,
	})
	return c
}

func (p *backendConnections) getWriteCounter(addr string) prometheus.Counter {
	c, _ := p.writes.GetMetricWith(prometheus.Labels{
		"addr": addr,
	})
	return c
}

// BackendConnections collects backend connection metrics
func BackendConnections(conn net.Conn, addr string) net.Conn {
	trackConn := &trackBackendConn{
		Conn:         conn,
		connGauge:    _backendConnections.getConnectionGauge(addr),
		readCounter:  _backendConnections.getReadCounter(addr),
		writeCounter: _backendConnections.getWriteCounter(addr),
	}
	trackConn.connGauge.Inc()

	return trackConn
}

type trackBackendConn struct {
	net.Conn
	connGauge    prometheus.Gauge
	readCounter  prometheus.Counter
	writeCounter prometheus.Counter
	closed       int32
}

func (conn *trackBackendConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if n > 0 {
		if conn.readCounter != nil {
			conn.readCounter.Add(float64(n))
		}
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if n > 0 {
		if conn.writeCounter != nil {
			conn.writeCounter.Add(float64(n))
		}
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) trackClose() {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		if conn.connGauge != nil {
			conn.connGauge.Dec()
		}
	}
}

func (conn *trackBackendConn) Close() error {
	conn.trackClose()
	return conn.Conn.Close()
}
