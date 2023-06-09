package route

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTable(t *testing.T) {
	t.Parallel()

	tb := Table{}
	tb.SetHostRoutes(map[string]*RRLB{
		"api.default.svc.cluster.local":        {IPs: []string{"192.168.0.1"}},
		"backoffice.default.svc.cluster.local": {IPs: []string{"192.168.0.2"}},
		"api.service.svc.cluster.local":        {IPs: []string{"192.168.1.1", "192.168.1.2"}},
		"payment.service.svc.cluster.local":    {IPs: []string{"192.168.2.1", "192.168.2.2"}},
	})
	tb.SetPortRoutes(map[string]string{
		"api.default.svc.cluster.local:8080":     "9000",
		"api.service.svc.cluster.local:8000":     "9001",
		"payment.service.svc.cluster.local:8000": "9002",
		"about.service.svc.cluster.local:8000":   "9003",
	})

	t.Run("Not Found", func(t *testing.T) {
		res := tb.Lookup("frontend.default.svc.cluster.local:8080")
		assert.Empty(t, res)
	})

	t.Run("Invalid Format", func(t *testing.T) {
		res := tb.Lookup("api.default.svc.cluster.local")
		assert.Empty(t, res)
	})

	t.Run("Found Host and Port", func(t *testing.T) {
		res := tb.Lookup("api.default.svc.cluster.local:8080")
		assert.Equal(t, "192.168.0.1:9000", res)
	})

	t.Run("Found Only Host", func(t *testing.T) {
		// this should never happen, since kubernetes service port name is required
		res := tb.Lookup("backoffice.default.svc.cluster.local:8080")
		assert.Empty(t, res)
	})

	t.Run("Some Bad", func(t *testing.T) {
		tb.MarkBad("192.168.1.1")

		for i := 0; i < 3; i++ {
			res := tb.Lookup("api.service.svc.cluster.local:8000")
			assert.Equal(t, "192.168.1.2:9001", res)
		}
	})

	t.Run("SetHostRoute", func(t *testing.T) {
		tb.SetHostRoute("about.service.svc.cluster.local", &RRLB{IPs: []string{"192.168.3.1"}})
		res := tb.Lookup("about.service.svc.cluster.local:8000")
		assert.Equal(t, "192.168.3.1:9003", res)

		tb.SetHostRoute("about.service.svc.cluster.local", &RRLB{IPs: []string{"192.168.3.2"}})
		res = tb.Lookup("about.service.svc.cluster.local:8000")
		assert.Equal(t, "192.168.3.2:9003", res)
	})
}

func BenchmarkSprintf(b *testing.B) {
	host := "192.168.100.10"
	port := "8080"
	var r string
	for i := 0; i < b.N; i++ {
		r = fmt.Sprintf("%s:%s", host, port)
	}
	_ = r
}

func BenchmarkStringConcat(b *testing.B) {
	host := "192.168.100.10"
	port := "8080"
	var r string
	for i := 0; i < b.N; i++ {
		r = host + ":" + port
	}
	_ = r
}

func BenchmarkStringsJoin(b *testing.B) {
	host := "192.168.100.10"
	port := "8080"
	var r string
	for i := 0; i < b.N; i++ {
		r = strings.Join([]string{host, port}, ":")
	}
	_ = r
}
