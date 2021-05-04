module github.com/moonrhythm/parapet-ingress-controller

go 1.16

require (
	cloud.google.com/go v0.81.0
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v0.20.0
	github.com/acoshift/configfile v1.7.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/moonrhythm/parapet v0.9.4
	github.com/prometheus/client_golang v1.9.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.20.0
	go.opentelemetry.io/otel/sdk v0.20.0
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420
	golang.org/x/sys v0.0.0-20210503173754-0981d6026fa6 // indirect
	google.golang.org/api v0.46.0 // indirect
	google.golang.org/genproto v0.0.0-20210503173045-b96a97608f20 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
)
