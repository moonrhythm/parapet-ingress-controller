package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	tracker := idx("m.Use(metric.HostActiveTracker(ctrl.IsKnownHost))")
	rps := idx("m.Use(hostRPS(ctrl.IsKnownHost))")
	country := idx("m.Use(hostCountryRateLimit(ctrl.IsKnownHost))")
	concurrent := idx("m.Use(hostRateLimit(ctrl.IsKnownHost))")

	require.Less(t, tracker, rps, "hostRPS must register AFTER HostActiveTracker")
	require.Less(t, rps, country, "hostRPS must register BEFORE hostCountryRateLimit")
	require.Less(t, rps, concurrent, "hostRPS must register BEFORE hostRateLimit")
}
