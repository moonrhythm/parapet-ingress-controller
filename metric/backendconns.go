package metric

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/logger"
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
	}, []string{"backend", "service_type", "service_name"})
	_backendConnections.reads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_read_bytes",
	}, []string{"backend", "service_type", "service_name"})
	_backendConnections.writes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_write_bytes",
	}, []string{"backend", "service_type", "service_name"})
	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.reads)
	prom.Registry().MustRegister(_backendConnections.writes)
}

func (p *backendConnections) inc(addr string, serviceType string, serviceName string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{
		"backend":      addr,
		"service_type": serviceType,
		"service_name": serviceName,
	})
	if err != nil {
		return
	}
	c.Inc()
}

func (p *backendConnections) dec(addr string, serviceType string, serviceName string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{
		"backend":      addr,
		"service_type": serviceType,
		"service_name": serviceName,
	})
	if err != nil {
		return
	}
	c.Dec()
}

func (p *backendConnections) read(addr string, serviceType string, serviceName string, n int) {
	c, err := p.reads.GetMetricWith(prometheus.Labels{
		"backend":      addr,
		"service_type": serviceType,
		"service_name": serviceName,
	})
	if err != nil {
		return
	}
	c.Add(float64(n))
}

func (p *backendConnections) write(addr string, serviceType string, serviceName string, n int) {
	c, err := p.writes.GetMetricWith(prometheus.Labels{
		"backend":      addr,
		"service_type": serviceType,
		"service_name": serviceName,
	})
	if err != nil {
		return
	}
	c.Add(float64(n))
}

// BackendConnections collects backend connection metrics
func BackendConnections(ctx context.Context, conn net.Conn, addr string) net.Conn {
	serviceType, _ := logger.Get(ctx, "serviceType").(string)
	serviceName, _ := logger.Get(ctx, "serviceName").(string)

	_backendConnections.inc(addr, serviceType, serviceName)

	return &trackBackendConn{
		Conn:        conn,
		addr:        addr,
		serviceType: serviceType,
		serviceName: serviceName,
	}
}

type trackBackendConn struct {
	net.Conn
	addr        string
	closed      int32
	serviceType string
	serviceName string
}

func (conn *trackBackendConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if n > 0 {
		_backendConnections.read(conn.addr, conn.serviceType, conn.serviceName, n)
	}
	return
}

func (conn *trackBackendConn) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if n > 0 {
		_backendConnections.write(conn.addr, conn.serviceType, conn.serviceName, n)
	}
	return
}

func (conn *trackBackendConn) Close() error {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		_backendConnections.dec(conn.addr, conn.serviceType, conn.serviceName)
	}
	return conn.Conn.Close()
}
