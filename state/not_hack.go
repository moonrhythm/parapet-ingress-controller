//go:build !hack

package state

import (
	"context"
	"net/http"
)

func setRequestContext(r *http.Request, ctx context.Context) {
	nr := r.WithContext(ctx)
	*r = *nr
}
