//go:build hack

package state

//go:linkname setRequestContext net/http.setRequestContext
func setRequestContext(r *http.Request, ctx context.Context)
