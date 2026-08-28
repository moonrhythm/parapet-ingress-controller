package main

import (
	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/edge"
	"github.com/moonrhythm/parapet-ingress-controller/hostlabel"
	"github.com/moonrhythm/parapet-ingress-controller/hostrps"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
)

func hostRPS(hosts *edge.EdgeHosts) parapet.Middleware {
	var known func(string) bool
	if hosts != nil {
		known = hosts.HostRPSKnown
	}
	return hostrps.New(int(envInt64("EDGE_HOST_RPS", 0)), known, func(host string) {
		// Limiter key may be uncollapsed at Generation()==0 (fail-open). Metric
		// labels always use IsKnownHost so a random-Host flood cannot mint series.
		label := host
		if hosts != nil {
			label = hostlabel.Of(host, hosts.IsKnownHost)
		}
		observe.HostRatelimitRequest(label)
		observe.RejectedRequest("host_rps")
	})
}
