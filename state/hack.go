//go:build hack

package state

import (
	"context"
	"net/http"
)

//go:linkname setRequestContext net/http.setRequestContext
func setRequestContext(r *http.Request, ctx context.Context)
