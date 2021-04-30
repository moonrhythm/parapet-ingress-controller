package controller

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func retryMiddleware(h http.Handler) http.Handler {
	const maxRetry = 30

	tryServe := func(w http.ResponseWriter, r *http.Request) (ok bool) {
		defer func() {
			if e := recover(); e != nil {
				err, _ := e.(error)
				if errors.Is(err, context.Canceled) {
					ok = true
					return
				}
				if isRetryable(err) {
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

		for i := 0; i < maxRetry; i++ {
			if tryServe(w, r) {
				break
			}

			select {
			case <-time.After(backoffDuration(i)):
			case <-ctx.Done():
				break
			}
		}
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
