package main

import (
	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/hostrps"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
)

func hostRPS(isKnownHost func(host string) bool) parapet.Middleware {
	return hostrps.New(config.Int("HOST_RPS"), isKnownHost, func(host string) {
		metric.HostRatelimitRequest(host)
		metric.RejectedRequest("host_rps")
	})
}
