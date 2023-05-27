module github.com/moonrhythm/parapet-ingress-controller

go 1.20

replace github.com/prometheus/client_golang => github.com/moonrhythm/prometheus-client_golang v1.15.1-patch.2

require (
	cloud.google.com/go v0.110.2 // indirect
	cloud.google.com/go/profiler v0.3.1
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v1.13.1
	github.com/acoshift/configfile v1.8.0
	github.com/golang/glog v1.1.1
	github.com/moonrhythm/parapet v0.12.4
	github.com/prometheus/client_golang v1.15.1
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.41.1
	go.opentelemetry.io/otel/exporters/jaeger v1.15.1
	go.opentelemetry.io/otel/sdk v1.15.1
	golang.org/x/net v0.10.0
	golang.org/x/sys v0.8.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.25.10
	k8s.io/apimachinery v0.25.10
	k8s.io/client-go v0.25.10
)

require (
	github.com/stretchr/testify v1.8.3
	go.opentelemetry.io/otel/trace v1.15.1
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
)

require (
	cloud.google.com/go/compute v1.19.2 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/trace v1.9.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.37.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/brotli/go/cbrotli v0.0.0-20230201092028-ed1995b6bda1 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20221103000818-d260c55eee4c // indirect
	github.com/google/s2a-go v0.1.3 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.8.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kavu/go_reuseport v1.5.0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/otel v1.15.1 // indirect
	go.opentelemetry.io/otel/metric v0.38.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/term v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	google.golang.org/api v0.122.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.55.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/klog/v2 v2.70.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)
