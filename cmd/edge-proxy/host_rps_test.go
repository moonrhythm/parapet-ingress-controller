package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	rps := idx("m.Use(hostRPS(edgeHosts.HostRPSKnown))")
	log := idx("m.Use(logger.Stdout())")
	strip := idx("m.Use(edge.StripWAFClaim())")

	require.Less(t, requests, rps, "hostRPS must register AFTER edge.Requests so 503s are counted")
	require.Less(t, rps, log, "hostRPS must register BEFORE the access log")
	require.Less(t, rps, strip, "hostRPS must register BEFORE WAF (StripWAFClaim is the WAF-adjacent slot)")
}
