package main

import (
	"net/http"
	"strings"
)

type httpsRedirector struct{}

func (m httpsRedirector) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.RequestURI, "/.well-known/acme-challenge") {
			h.ServeHTTP(w, r)
			return
		}

		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "http" {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			return
		}

		h.ServeHTTP(w, r)
	})
}
