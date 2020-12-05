module github.com/moonrhythm/parapet-ingress-controller

go 1.15

require (
	cloud.google.com/go v0.72.0
	contrib.go.opencensus.io/exporter/stackdriver v0.13.4
	github.com/acoshift/configfile v1.7.0
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/moonrhythm/parapet v0.9.2
	github.com/prometheus/client_golang v1.8.0
	go.opencensus.io v0.22.5
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
	k8s.io/client-go v0.0.0-20190819141724-e14f31a72a77
	k8s.io/utils v0.0.0-20200603063816-c1c6865ac451 // indirect
)
