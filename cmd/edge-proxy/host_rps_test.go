package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/edge"
	"github.com/moonrhythm/parapet-ingress-controller/hostlabel"
)

func TestHostRPS_EnvOff(t *testing.T) {
	t.Setenv("EDGE_HOST_RPS", "")
	assert.Nil(t, hostRPS(nil))

	t.Setenv("EDGE_HOST_RPS", "0")
	assert.Nil(t, hostRPS(nil))

	t.Setenv("EDGE_HOST_RPS", "-3")
	assert.Nil(t, hostRPS(nil))
}

func TestHostRPS_EnvOn(t *testing.T) {
	t.Setenv("EDGE_HOST_RPS", "10")
	assert.NotNil(t, hostRPS(nil))
}

func TestHostRPSRegistrationSlot(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	require.NoError(t, err)
	body := string(src)

	idx := func(needle string) int {
		i := strings.Index(body, needle)
		require.GreaterOrEqualf(t, i, 0, "registration not found in main.go: %s", needle)
		return i
	}

	requests := idx("m.Use(edge.Requests(edgeHosts.IsKnownHost))")
	rps := idx("m.Use(hostRPS(edgeHosts))")
	log := idx("m.Use(logger.Stdout())")
	strip := idx("m.Use(edge.StripWAFClaim())")

	require.Less(t, requests, rps, "hostRPS must register AFTER edge.Requests so 503s are counted")
	require.Less(t, rps, log, "hostRPS must register BEFORE the access log")
	require.Less(t, rps, strip, "hostRPS must register BEFORE WAF (StripWAFClaim is the WAF-adjacent slot)")
}

func TestHostRPS_OverflowIncrementsMetrics(t *testing.T) {
	t.Setenv("EDGE_HOST_RPS", "1")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := range 5 {
		host := "overflow-" + strings.Repeat("x", i+1) + ".example.com"
		hosts := edge.NewEdgeHosts()
		hosts.Update(1, []string{host}, `"t"`)
		m := hostRPS(hosts)
		require.NotNil(t, m)
		h := m.ServeHandler(ok)
		serve := func() int {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = host
			h.ServeHTTP(rec, r)
			return rec.Code
		}
		if serve() != http.StatusOK {
			continue
		}
		if serve() == http.StatusOK {
			continue
		}
		assert.Equal(t, 1.0, counterValue(t, "parapet_host_ratelimit_requests", "host", host))
		assert.GreaterOrEqual(t, counterValue(t, "parapet_rejected_requests", "reason", "host_rps"), 1.0)
		return
	}
	t.Fatal("could not land a host-RPS overflow in the same 1s window after 5 attempts")
}

func TestHostRPS_Gen0OverflowMetricIsOther(t *testing.T) {
	t.Setenv("EDGE_HOST_RPS", "1")
	hosts := edge.NewEdgeHosts() // Generation()==0: limiter fail-open, metric must still collapse
	m := hostRPS(hosts)
	require.NotNil(t, m)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := m.ServeHandler(ok)
	before := counterValueOrZero(t, "parapet_host_ratelimit_requests", "host", hostlabel.Other)
	for range 5 {
		host := "gen0-flood.example.com"
		serve := func() int {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = host
			h.ServeHTTP(rec, r)
			return rec.Code
		}
		if serve() != http.StatusOK {
			continue
		}
		if serve() == http.StatusOK {
			continue
		}
		assert.Greater(t, counterValue(t, "parapet_host_ratelimit_requests", "host", hostlabel.Other), before)
		assert.Equal(t, 0.0, counterValueOrZero(t, "parapet_host_ratelimit_requests", "host", host),
			"raw Host must not appear as a metric label at gen 0")
		return
	}
	t.Fatal("could not land a gen-0 overflow in the same 1s window after 5 attempts")
}

func counterValueOrZero(t *testing.T, name, label, value string) float64 {
	t.Helper()
	mfs, err := prom.Registry().Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label && lp.GetValue() == value {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func counterValue(t *testing.T, name, label, value string) float64 {
	t.Helper()
	mfs, err := prom.Registry().Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label && lp.GetValue() == value {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("%s{%s=%q} not found", name, label, value)
	return 0
}
