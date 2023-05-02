package controller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func retryMiddleware(h http.Handler) http.Handler {
	const maxRetry = 5

	canRequestRetry := func(r *http.Request) bool {
		if r.Body == nil || r.Body == http.NoBody {
			return true
		}
		if t, ok := r.Body.(*trackBodyRead); ok {
			return !t.read
		}
		return false
	}

	tryServe := func(w http.ResponseWriter, r *http.Request) (ok bool) {
		defer func() {
			if e := recover(); e != nil {
				err, _ := e.(error)
				if errors.Is(err, context.Canceled) {
					ok = true
					return
				}
				if canRequestRetry(r) && proxy.IsRetryable(err) {
					// retry
					return
				}
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			}
			ok = true
		}()

		h.ServeHTTP(w, r)
		return
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &trackBodyRead{ReadCloser: r.Body}
		}

		for i := 0; i < maxRetry; i++ {
			if tryServe(w, r) {
				return
			}

			select {
			case <-time.After(backoffDuration(i)):
			case <-ctx.Done():
				break
			}
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	})
}

const maxBackoffDuration = 3 * time.Second

func backoffDuration(round int) (t time.Duration) {
	t = time.Duration(1<<uint(round)) * 10 * time.Millisecond
	if t > maxBackoffDuration {
		t = maxBackoffDuration
	}
	return
}

type trackBodyRead struct {
	io.ReadCloser
	read bool
}

func (t *trackBodyRead) Read(p []byte) (n int, err error) {
	t.read = true
	return t.ReadCloser.Read(p)
}
