module github.com/moonrhythm/parapet-ingress-controller

go 1.14

require (
	cloud.google.com/go v0.63.0
	github.com/acoshift/configfile v1.6.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/kavu/go_reuseport v1.5.0 // indirect
	github.com/moonrhythm/parapet v0.9.1
	github.com/prometheus/client_golang v1.7.1
	golang.org/x/tools v0.0.0-20200806234136-990129eca547 // indirect
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
	k8s.io/client-go v0.0.0-20190819141724-e14f31a72a77
	k8s.io/utils v0.0.0-20200603063816-c1c6865ac451 // indirect
)
