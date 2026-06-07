package proxy

import "context"

// backendAttr is the immutable per-Service attribution the dialer stamps onto
// connection metrics. It is carried in the request context (set by the route
// handler via WithBackendAttr) rather than read from the pooled state map.
//
// Why not the state map: Go's transport may start a dial on a background
// goroutine that races a fresh connection against an idle one
// (startDialConnForLocked → dialConnFor). That dial runs DialContext with the
// request's context, but it can outlive the originating request — by the time
// it completes, state.Middleware's defer has already cleared the per-request
// State and returned it to the sync.Pool, where another in-flight request may
// have picked it up and started writing. Reading that map from the dial
// goroutine is then a concurrent map read against a map write, which the
// runtime turns into a fatal error. This value is never cleared or recycled, so
// a late read is always safe and returns the correct Service labels.
type backendAttr struct {
	serviceType string
	namespace   string
	serviceName string
}

type backendAttrCtxKey struct{}

// WithBackendAttr returns a child context carrying immutable backend
// attribution (Service type / namespace / name) for connection metrics. The
// route handler sets it before proxying; the dialer reads it when wrapping a
// freshly dialed connection.
func WithBackendAttr(ctx context.Context, serviceType, namespace, serviceName string) context.Context {
	return context.WithValue(ctx, backendAttrCtxKey{}, backendAttr{
		serviceType: serviceType,
		namespace:   namespace,
		serviceName: serviceName,
	})
}

func backendAttrFromContext(ctx context.Context) backendAttr {
	a, _ := ctx.Value(backendAttrCtxKey{}).(backendAttr)
	return a
}
