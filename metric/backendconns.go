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
	}, []string{"backend", "service_namespace", "service_type", "service_name", "ingress"})
	_backendConnections.reads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_read_bytes",
	}, []string{"backend", "service_namespace", "service_type", "service_name", "ingress"})
	_backendConnections.writes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_network_write_bytes",
	}, []string{"backend", "service_namespace", "service_type", "service_name", "ingress"})
	prom.Registry().MustRegister(_backendConnections.connections)
	prom.Registry().MustRegister(_backendConnections.reads)
	prom.Registry().MustRegister(_backendConnections.writes)
}

func (p *backendConnections) inc(addr string, namespace, serviceType, serviceName, ingress string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{
		"backend":           addr,
		"service_namespace": namespace,
		"service_type":      serviceType,
		"service_name":      serviceName,
		"ingress":           ingress,
	})
	if err != nil {
		return
	}
	c.Inc()
}

func (p *backendConnections) dec(addr string, namespace, serviceType, serviceName, ingress string) {
	c, err := p.connections.GetMetricWith(prometheus.Labels{
		"backend":           addr,
		"service_namespace": namespace,
		"service_type":      serviceType,
		"service_name":      serviceName,
		"ingress":           ingress,
	})
	if err != nil {
		return
	}
	c.Dec()
}

func (p *backendConnections) read(addr string, namespace, serviceType, serviceName, ingress string, n int) {
	c, err := p.reads.GetMetricWith(prometheus.Labels{
		"backend":           addr,
		"service_namespace": namespace,
		"service_type":      serviceType,
		"service_name":      serviceName,
		"ingress":           ingress,
	})
	if err != nil {
		return
	}
	c.Add(float64(n))
}

func (p *backendConnections) write(addr string, namespace, serviceType, serviceName, ingress string, n int) {
	c, err := p.writes.GetMetricWith(prometheus.Labels{
		"backend":           addr,
		"service_namespace": namespace,
		"service_type":      serviceType,
		"service_name":      serviceName,
		"ingress":           ingress,
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
	namespace, _ := logger.Get(ctx, "namespace").(string)
	ingress, _ := logger.Get(ctx, "ingress").(string)

	_backendConnections.inc(addr, namespace, serviceType, serviceName, ingress)

	return &trackBackendConn{
		Conn:        conn,
		addr:        addr,
		namespace:   namespace,
		serviceType: serviceType,
		serviceName: serviceName,
		ingress:     ingress,
	}
}

type trackBackendConn struct {
	net.Conn
	addr        string
	closed      int32
	namespace   string
	serviceType string
	serviceName string
	ingress     string
}

func (conn *trackBackendConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if n > 0 {
		_backendConnections.read(conn.addr, conn.namespace, conn.serviceType, conn.serviceName, conn.ingress, n)
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if n > 0 {
		_backendConnections.write(conn.addr, conn.namespace, conn.serviceType, conn.serviceName, conn.ingress, n)
	}
	if err != nil {
		conn.trackClose()
	}
	return
}

func (conn *trackBackendConn) trackClose() {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		_backendConnections.dec(conn.addr, conn.namespace, conn.serviceType, conn.serviceName, conn.ingress)
	}
}

func (conn *trackBackendConn) Close() error {
	conn.trackClose()
	return conn.Conn.Close()
}
