package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

func retryMiddleware(h http.Handler) http.Handler {
	const maxRetry = 15

	replaceBody := func(r *http.Request) error {
		// empty body
		if r.Body == nil || r.Body == http.NoBody {
			return nil
		}

		// body less than buffer size, load all to buffer
		if r.ContentLength <= bufferSize {
			buf := bufferPool.Get()

			_, err := r.Body.Read(buf)
			if err != nil {
				bufferPool.Put(buf)
				return err
			}

			r.Body = &bufferedBody{
				Reader: bytes.NewReader(buf),
				buf:    buf,
			}
			return nil
		}

		// unknown size body
		r.Body = &trackReadBody{ReadCloser: r.Body}
		return nil
	}

	resetBody := func(r *http.Request) {
		if t, ok := r.Body.(*bufferedBody); ok {
			t.Reset()
		}
	}

	closeBody := func(r *http.Request) {
		if t, ok := r.Body.(*bufferedBody); ok {
			t.Close()
		}
	}

	canRequestRetry := func(r *http.Request) bool {
		if r.Body == nil || r.Body == http.NoBody {
			return true
		}

		switch t := r.Body.(type) {
		case *bufferedBody:
			return true
		case *trackReadBody:
			return !t.read
		default:
			return false
		}
	}

	tryServe := func(w http.ResponseWriter, r *http.Request) (ok bool) {
		defer func() {
			if e := recover(); e != nil {
				err, _ := e.(error)
				if errors.Is(err, context.Canceled) {
					ok = true
					return
				}
				if canRequestRetry(r) && isRetryable(err) {
					// retry
					return
				}
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			}
			ok = true
		}()

		resetBody(r)
		h.ServeHTTP(w, r)
		return
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if err := replaceBody(r); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer closeBody(r)

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

func isRetryable(err error) bool {
	if isDialError(err) {
		return true
	}
	if errors.Is(err, errBadGateway) {
		return true
	}
	if errors.Is(err, errServiceUnavailable) {
		return true
	}
	return false
}

type trackReadBody struct {
	io.ReadCloser
	read bool
}

func (b *trackReadBody) Read(p []byte) (n int, err error) {
	b.read = true
	return b.ReadCloser.Read(p)
}

type bufferedBody struct {
	*bytes.Reader
	buf    []byte
	closed bool
}

func (b *bufferedBody) Read(p []byte) (n int, err error) {
	if b.closed {
		return 0, io.EOF
	}
	return b.Reader.Read(p)
}

func (b *bufferedBody) Reset() {
	b.Reader.Reset(b.buf)
}

func (b *bufferedBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	bufferPool.Put(b.buf)
	return nil
}
