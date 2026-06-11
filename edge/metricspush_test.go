package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushMetricsOnce(t *testing.T) {
	type got struct {
		method, path, auth, instance, contentType string
		body                                      string
	}
	var last got
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last = got{
			method:      r.Method,
			path:        r.URL.Path,
			auth:        r.Header.Get("Authorization"),
			instance:    r.Header.Get("X-Edge-Instance"),
			contentType: r.Header.Get("Content-Type"),
			body:        string(b),
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	cp, err := NewCpClient(srv.URL, "tok-1", nil)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		// Ensure a known edge_* family has at least one series (a vec with no
		// series is omitted from Gather output).
		metricsPush("ok")
		require.NoError(t, PushMetricsOnce(cp, "pod-1"))
		assert.Equal(t, http.MethodPost, last.method)
		assert.Equal(t, "/v1/metrics", last.path)
		assert.Equal(t, "Bearer tok-1", last.auth)
		assert.Equal(t, "pod-1", last.instance)
		assert.Contains(t, last.contentType, "text/plain")

		// The body must re-parse as valid exposition and carry the full shared
		// registry — a known edge_* family proves it isn't a filtered subset.
		parser := expfmt.NewTextParser(model.UTF8Validation)
		families, err := parser.TextToMetricFamilies(strings.NewReader(last.body))
		require.NoError(t, err)
		assert.Contains(t, families, "parapet_edge_metrics_client_push_total")
	})

	t.Run("non-2xx is an error", func(t *testing.T) {
		status = http.StatusServiceUnavailable
		assert.Error(t, PushMetricsOnce(cp, "pod-1"))
	})
}
