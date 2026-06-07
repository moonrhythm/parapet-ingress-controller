package state

import (
	"context"
	"net/http"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/logger"
)

// State holds request state
//
// It's not safe for concurrent use by multiple goroutines.
type State map[string]string

type ctxKey struct{}

const sizeHint = 5

var pool = sync.Pool{
	New: func() any {
		return make(State, sizeHint)
	},
}

func putState(s State) {
	clear(s)
	pool.Put(s)
}

// Get returns the State stored in ctx by Middleware.
//
// If ctx carries no State — i.e. Get is called outside the Middleware chain —
// it returns an empty throwaway State so callers can read and write without a
// nil check. That fallback map is not pooled and never reaches the access log,
// so writes to it are silently dropped; in normal operation every request
// passes through Middleware and this path is not taken.
func Get(ctx context.Context) State {
	s, _ := ctx.Value(ctxKey{}).(State)
	if s == nil {
		s = make(State, sizeHint)
	}
	return s
}

// NewContext creates new value context with given State
func NewContext(parent context.Context, s State) context.Context {
	return context.WithValue(parent, ctxKey{}, s)
}

// Middleware injects a pooled per-request State into the context. When logEnabled is
// true it also copies every state field into the request's access-log record on the
// way out. With logging disabled the copy loop is skipped entirely — it would
// otherwise iterate the map and walk the context chain via logger.Set on every
// request for a log line that is never emitted, so a disabled access log pays nothing.
func Middleware(logEnabled bool) parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			s := pool.Get().(State)
			defer func() {
				if logEnabled {
					for k, v := range s {
						logger.Set(ctx, k, v)
					}
				}
				putState(s)
			}()

			h.ServeHTTP(w, r.WithContext(NewContext(ctx, s)))
		})
	})
}
