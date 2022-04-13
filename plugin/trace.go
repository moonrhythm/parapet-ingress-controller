package plugin

import (
	"net/http"
	"strconv"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/exporters/jaeger"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// JaegerTrace traces to jaeger
func JaegerTrace(ctx Context) {
	enable := ctx.Ingress.Annotations["parapet.moonrhythm.io/jaeger-trace"]
	if enable != "true" {
		return
	}

	collectorEndpoint := ctx.Ingress.Annotations["parapet.moonrhythm.io/jaeger-trace-collector-endpoint"]
	if collectorEndpoint == "" {
		return
	}

	collectorUsername := ctx.Ingress.Annotations["parapet.moonrhythm.io/jaeger-trace-collector-username"]
	collectorPassword := ctx.Ingress.Annotations["parapet.moonrhythm.io/jaeger-trace-collector-password"]

	var sampler float64 = 1
	if s := ctx.Ingress.Annotations["parapet.moonrhythm.io/jaeger-trace-sampler"]; s != "" {
		sampler, _ = strconv.ParseFloat(s, 64)
		if sampler <= 0 {
			return
		}
	}

	collectorOptions := []jaeger.CollectorEndpointOption{
		jaeger.WithEndpoint(collectorEndpoint),
	}
	if collectorUsername != "" {
		collectorOptions = append(collectorOptions, jaeger.WithUsername(collectorUsername))
	}
	if collectorPassword != "" {
		collectorOptions = append(collectorOptions, jaeger.WithPassword(collectorPassword))
	}

	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(collectorOptions...),
	)
	if err != nil {
		glog.Errorf("plugin/JaegerTrace: NewRawExporter error; %v", err)
		return
	}

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

// OperationsTrace traces to google cloud operation
func OperationsTrace(ctx Context) {
	enable := ctx.Ingress.Annotations["parapet.moonrhythm.io/operations-trace"]
	if enable != "true" {
		return
	}

	projectID := ctx.Ingress.Annotations["parapet.moonrhythm.io/operations-trace-project"]
	if projectID == "" {
		return
	}

	var sampler float64 = 1
	if s := ctx.Ingress.Annotations["parapet.moonrhythm.io/operations-trace-sampler"]; s != "" {
		sampler, _ = strconv.ParseFloat(s, 64)
		if sampler <= 0 {
			return
		}
	}

	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		glog.Errorf("plugin/OperationsTrace: NewExporter error; %v", err)
		return
	}

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
	proto := r.Header.Get("X-Forwarded-Proto")
	return proto + "://" + r.Host + r.RequestURI
}
