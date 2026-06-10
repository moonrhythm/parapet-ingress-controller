// Package observe provides bounded, pre-resolved Prometheus observers for
// parapet's per-request observability hooks (waf.WAF.Observe,
// ratelimit.RateLimiter.Observe, cache.Options.OnResult), shared by the
// controller and edge-proxy binaries.
//
// It is deliberately a LEAF package, separate from metric: importing metric
// materializes the controller's core-trust alerting series at init
// (metric/trust.go pre-resolves its gauge/counter handles), and the edge must
// not export constant-zero core-trust gauges that would dilute fleet-wide
// aggregations. Each binary imports only the observers it can actually move.
//
// The observers record the same metric names as parapet's prom.WAF /
// prom.RateLimit / prom.Cache helpers (so dashboards are interchangeable), with
// two differences: handles are resolved at construction, once per instance, so
// the per-request hook is alloc- and lookup-free (the prom helpers re-resolve
// labels on every event); and the label sets are adjusted for this deployment
// (WAF gains the scope label, cache drops the unbounded host label). Because
// the names collide, never wire parapet's prom.WAF()/prom.RateLimit()/
// prom.Cache() in a binary that uses this package — the duplicate
// MustRegister panics at startup.
package observe
