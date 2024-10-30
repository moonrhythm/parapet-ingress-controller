package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/moonrhythm/parapet/pkg/header"
	"golang.org/x/net/http2"
)

type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func newHTTPTransport(dial dialContextFunc) *http.Transport {
	return &http.Transport{
		DialContext:           dial,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		ResponseHeaderTimeout: 3 * time.Minute,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

type h2cTransport struct {
	*http2.Transport
	fallback http.RoundTripper
}

func (t *h2cTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"

	if header.Exists(r.Header, header.Upgrade) {
		return t.fallback.RoundTrip(r)
	}

	return t.Transport.RoundTrip(r)
}

func newH2CTransport(dial dialContextFunc, fallback http.RoundTripper) *h2cTransport {
	return &h2cTransport{
		Transport: &http2.Transport{
			AllowHTTP:          true,
			DisableCompression: true,
			MaxReadFrameSize:   1 << 17,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dial(ctx, network, addr)
			},
			IdleConnTimeout: 30 * time.Second,
			ReadIdleTimeout: 15 * time.Second,
			PingTimeout:     10 * time.Second,
		},
		fallback: fallback,
	}
}
