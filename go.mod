module github.com/moonrhythm/parapet-ingress-controller

go 1.16

require (
	cloud.google.com/go v0.81.0
	contrib.go.opencensus.io/exporter/stackdriver v0.13.5
	github.com/acoshift/configfile v1.7.0
	github.com/aws/aws-sdk-go v1.37.15 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/moonrhythm/parapet v0.9.4
	github.com/prometheus/client_golang v1.9.0
	go.opencensus.io v0.23.0
	golang.org/x/net v0.0.0-20210410081132-afb366fc7cd1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
)
