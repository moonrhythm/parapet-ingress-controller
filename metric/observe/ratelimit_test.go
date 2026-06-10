package observe

import (
	"testing"

	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestRateLimit(t *testing.T) {
	const name = "ratelimit-observer-test"
	obs := RateLimit(name)

	obs(ratelimit.Event{Name: name, Result: ratelimit.ResultAllowed})
	obs(ratelimit.Event{Name: name, Result: ratelimit.ResultAllowed})
	obs(ratelimit.Event{Name: name, Result: ratelimit.ResultLimited})
	// an unknown result is dropped, not counted
	obs(ratelimit.Event{Name: name, Result: ratelimit.Result(99)})

	allowed := _ratelimit.vec.With(prometheus.Labels{"name": name, "result": "allowed"})
	limited := _ratelimit.vec.With(prometheus.Labels{"name": name, "result": "limited"})
	assert.Equal(t, 2.0, testutil.ToFloat64(allowed))
	assert.Equal(t, 1.0, testutil.ToFloat64(limited))

	// a re-created observer for the same name (e.g. a reload re-running the
	// plugin) resolves to the same underlying series — counts continue
	obs2 := RateLimit(name)
	obs2(ratelimit.Event{Name: name, Result: ratelimit.ResultAllowed})
	assert.Equal(t, 3.0, testutil.ToFloat64(allowed))
}
