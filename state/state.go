package state

import (
	"context"
	"net/http"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/logger"
)

type State map[string]interface{}

type ctxKey struct{}

func Get(ctx context.Context) State {
	s, _ := ctx.Value(ctxKey{}).(State)
	if s == nil {
		s = make(State)
	}
	return s
}

func NewContext(parent context.Context, s State) context.Context {
	return context.WithValue(parent, ctxKey{}, s)
}

func Middleware() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			s := make(State)
			defer func() {
				// inject state to log
				for k, v := range s {
					logger.Set(ctx, k, v)
				}
			}()

			h.ServeHTTP(w, r.WithContext(NewContext(ctx, s)))
		})
	})
}
