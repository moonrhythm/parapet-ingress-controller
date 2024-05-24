package plugin

import (
	"log/slog"
	"net/http"
	"strconv"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/header"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// OperationsTrace traces to google cloud operation
func OperationsTrace(ctx Context) {
	enable := ctx.Ingress.Annotations[namespace+"/operations-trace"]
	if enable != "true" {
		return
	}

	projectID := ctx.Ingress.Annotations[namespace+"/operations-trace-project"]
	if projectID == "" {
		return
	}

	var sampler float64 = 1
	if s := ctx.Ingress.Annotations[namespace+"/operations-trace-sampler"]; s != "" {
		sampler, _ = strconv.ParseFloat(s, 64)
		if sampler <= 0 {
			return
		}
	}

	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		slog.Error("plugin/OperationsTrace: NewExporter error", "error", err)
		return
	}

	generalTrace(ctx, exporter, sampler)
}

func generalTrace(ctx Context, exporter sdktrace.SpanExporter, sampler float64) {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampler)),
	)

	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return otelhttp.NewHandler(h, ctx.Ingress.Namespace+"/"+ctx.Ingress.Name,
			otelhttp.WithTracerProvider(tp),
			otelhttp.WithSpanNameFormatter(traceSpanNameFormatter),
		)
	}))
}

func traceSpanNameFormatter(_ string, r *http.Request) string {
	proto := header.Get(r.Header, header.XForwardedProto)
	return proto + "://" + r.Host + r.RequestURI
}
