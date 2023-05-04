package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/moonrhythm/parapet-ingress-controller/plugin"
)

func TestJaegerTrace(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//
	}))
	defer ts.Close()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/jaeger-trace":                    "true",
					"parapet.moonrhythm.io/jaeger-trace-collector-endpoint": ts.URL,
				},
			},
		},
	}
	JaegerTrace(ctx)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	var called bool
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, trace.SpanContextFromContext(r.Context()).IsValid())
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}

func TestOperationsTrace(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/operations-trace":         "true",
					"parapet.moonrhythm.io/operations-trace-project": "project",
				},
			},
		},
	}
	OperationsTrace(ctx)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	var called bool
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, trace.SpanContextFromContext(r.Context()).IsValid())
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}
