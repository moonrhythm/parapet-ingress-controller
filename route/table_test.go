package route

import (
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

	t.Run("SetHostRoute nil deletes", func(t *testing.T) {
		tb.SetHostRoute("about.service.svc.cluster.local", &RRLB{IPs: []string{"192.168.3.9"}})
		assert.Equal(t, "192.168.3.9:9003", tb.Lookup("about.service.svc.cluster.local:8000"))

		// passing nil removes just that host; the lookup now misses
		tb.SetHostRoute("about.service.svc.cluster.local", nil)
		assert.Empty(t, tb.Lookup("about.service.svc.cluster.local:8000"))
	})
}

func TestTableExternalName(t *testing.T) {
	t.Parallel()

	tb := Table{}
	tb.SetExternalNameRoutes(map[string]string{
		"ext.default.svc.cluster.local": "api.example.com",
	})
	tb.SetPortRoutes(map[string]string{
		"ext.default.svc.cluster.local:443": "443",
		"ext.default.svc.cluster.local:80":  "80",
	})

	t.Run("resolves to the external DNS name and port", func(t *testing.T) {
		assert.Equal(t, "api.example.com:443",
			tb.Lookup("ext.default.svc.cluster.local:443"))
		assert.Equal(t, "api.example.com:80",
			tb.Lookup("ext.default.svc.cluster.local:80"))
	})

	t.Run("missing port misses even with an externalName host", func(t *testing.T) {
		assert.Empty(t, tb.Lookup("ext.default.svc.cluster.local:8443"))
	})

	t.Run("unknown host misses", func(t *testing.T) {
		assert.Empty(t, tb.Lookup("other.default.svc.cluster.local:443"))
	})

	t.Run("a pod host route takes precedence over externalName", func(t *testing.T) {
		// Both maps can briefly hold the same host during a Service type change;
		// the real pod endpoints win, and once they are gone Lookup falls back to
		// the externalName.
		tb.SetHostRoutes(map[string]*RRLB{
			"ext.default.svc.cluster.local": {IPs: []string{"10.0.0.9"}},
		})
		assert.Equal(t, "10.0.0.9:443", tb.Lookup("ext.default.svc.cluster.local:443"))

		tb.SetHostRoutes(map[string]*RRLB{})
		assert.Equal(t, "api.example.com:443", tb.Lookup("ext.default.svc.cluster.local:443"))
	})
}

// hostIPs reads back the IP set the table currently holds for each host so two
// tables built different ways can be compared for equality.
func hostIPs(t *Table) map[string][]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string][]string, len(t.addrToTargetHost))
	for host, lb := range t.addrToTargetHost {
		out[host] = lb.IPs
	}
	return out
}

// TestTableIncrementalMatchesRebuild proves that driving the host table with
// per-host SetHostRoute calls (the watch-event path) lands in exactly the same
// state a full SetHostRoutes rebuild (the initial-sync path) would produce, for
// adding a host, changing a host's IPs, deleting a host, and a no-op re-set.
func TestTableIncrementalMatchesRebuild(t *testing.T) {
	t.Parallel()

	type set map[string][]string

	// the sequence of desired states the table passes through
	states := []set{
		// initial set
		{
			"a.default.svc.cluster.local": {"10.0.0.1"},
			"b.default.svc.cluster.local": {"10.0.1.1", "10.0.1.2"},
		},
		// add a host (c)
		{
			"a.default.svc.cluster.local": {"10.0.0.1"},
			"b.default.svc.cluster.local": {"10.0.1.1", "10.0.1.2"},
			"c.default.svc.cluster.local": {"10.0.2.1"},
		},
		// change a host's IPs (b scaled / pods replaced)
		{
			"a.default.svc.cluster.local": {"10.0.0.1"},
			"b.default.svc.cluster.local": {"10.0.1.3"},
			"c.default.svc.cluster.local": {"10.0.2.1"},
		},
		// no-op: identical to the previous state
		{
			"a.default.svc.cluster.local": {"10.0.0.1"},
			"b.default.svc.cluster.local": {"10.0.1.3"},
			"c.default.svc.cluster.local": {"10.0.2.1"},
		},
		// delete a host (c removed)
		{
			"a.default.svc.cluster.local": {"10.0.0.1"},
			"b.default.svc.cluster.local": {"10.0.1.3"},
		},
	}

	toRoutes := func(s set) map[string]*RRLB {
		m := make(map[string]*RRLB, len(s))
		for host, ips := range s {
			m[host] = &RRLB{IPs: ips}
		}
		return m
	}

	// incremental: seed with the first state, then apply each subsequent state
	// as per-host upserts/deletes, mirroring reloadSingleEndpoint /
	// deleteSingleEndpoint.
	var incr Table
	incr.SetHostRoutes(toRoutes(states[0]))
	for i := 1; i < len(states); i++ {
		prev, cur := states[i-1], states[i]
		for host, ips := range cur { // upserts
			incr.SetHostRoute(host, &RRLB{IPs: ips})
		}
		for host := range prev { // deletes
			if _, ok := cur[host]; !ok {
				incr.SetHostRoute(host, nil)
			}
		}

		// a full rebuild of the same desired state must match the incremental one
		var full Table
		full.SetHostRoutes(toRoutes(cur))

		assert.Equal(t, hostIPs(&full), hostIPs(&incr),
			"incremental state diverged from full rebuild at step %d", i)
	}
}
