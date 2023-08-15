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

// Get gets state from context
func Get(ctx context.Context) State {
	s, _ := ctx.Value(ctxKey{}).(State)
	if s == nil {
		s = make(State) // this line is not used, since we inject middleware
	}
	return s
}

// NewContext creates new value context with given State
func NewContext(parent context.Context, s State) context.Context {
	return context.WithValue(parent, ctxKey{}, s)
}

// Middleware injects empty state context to request and set all state values to logger
func Middleware() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			s := pool.Get().(State)
			defer func() {
				// inject state to log
				for k, v := range s {
					logger.Set(ctx, k, v) // TODO: implement log to reduce memory usage
				}
				putState(s)
			}()

			h.ServeHTTP(w, r.WithContext(NewContext(ctx, s)))
		})
	})
}
