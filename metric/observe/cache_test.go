package observe

import (
	"net/http/httptest"
	"testing"
	"time"

	pcache "github.com/moonrhythm/parapet/pkg/cache"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheResult(t *testing.T) {
	obs := CacheResult()
	r := httptest.NewRequest("GET", "http://cache-result-test.example.com/x", nil)

	obs(r, pcache.ResultInfo{Result: pcache.ResultHit})
	obs(r, pcache.ResultInfo{Result: pcache.ResultMiss, FillDuration: 30 * time.Millisecond})
	obs(r, pcache.ResultInfo{Result: pcache.ResultBypass})
	// an unknown result is dropped, not counted under a new label
	obs(r, pcache.ResultInfo{Result: pcache.Result("WEIRD")})

	assert.Equal(t, 1.0, testutil.ToFloat64(_respCache.total[pcache.ResultHit]))
	assert.Equal(t, 1.0, testutil.ToFloat64(_respCache.total[pcache.ResultMiss]))
	assert.Equal(t, 1.0, testutil.ToFloat64(_respCache.total[pcache.ResultBypass]))
	assert.Equal(t, 0.0, testutil.ToFloat64(_respCache.total[pcache.ResultStale]))
	assert.Equal(t, 0.0, testutil.ToFloat64(_respCache.total[pcache.ResultStaleError]))

	// the fill histogram saw only the MISS — the sole event with FillDuration set
	var m dto.Metric
	require.NoError(t, _respCache.fill.Write(&m))
	assert.EqualValues(t, 1, m.GetHistogram().GetSampleCount())
	assert.InDelta(t, 0.030, m.GetHistogram().GetSampleSum(), 1e-9)
}
