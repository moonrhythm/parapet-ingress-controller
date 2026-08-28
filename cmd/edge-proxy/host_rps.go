package main

import (
	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/hostrps"
)

func hostRPS(isKnownHost func(host string) bool) parapet.Middleware {
	return hostrps.New(int(envInt64("EDGE_HOST_RPS", 0)), isKnownHost, nil)
}
