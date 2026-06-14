package edgecp

import (
	"context"
	"sync"
	"time"
)

// EventsSnapshot is the version vector pushed on the GET /v1/events SSE stream.
// It is a WAKE-UP SIGNAL only: opaque per-store versions, never content. On a
// change the edge re-runs its existing ETag-revalidated fetch for that store,
// so authorization scoping, fail-static apply, and keep-last-good semantics all
// stay exactly where they are today. The versions are process-local (a hash or
// counter), so an edge must only ever compare them for INEQUALITY against the
// previous event on the SAME stream — never persist or order them.
type EventsSnapshot struct {
	// WAF/RateLimit/Cache are the stores' content etags ("" when distribution is
	// off).
	WAF       string `json:"waf,omitempty"`
	RateLimit string `json:"ratelimit,omitempty"`
	Cache     string `json:"cache,omitempty"`
	// Hosts is the known-host store's content etag ("" when off). A host change
	// pokes only the edge's hosts refresh — it doesn't affect WAF/ratelimit.
	Hosts string `json:"hosts,omitempty"`
	// GatedHosts is the forward-auth-gated host store's content etag ("" when off).
	// A change pokes only the edge's gated-hosts refresh, which drives the edge
	// response-cache bypass — it doesn't affect WAF/ratelimit.
	GatedHosts string `json:"gatedHosts,omitempty"`
	// Certs is a fingerprint over the cert store's full (name, etag) index.
	Certs string `json:"certs,omitempty"`
	// Purges is the purge journal's last issued seq (0 = none/off).
	Purges uint64 `json:"purges,omitempty"`
}

// EventsHub samples a version snapshot of the distribution stores and fans a
// change event out to every subscribed /v1/events stream. Sampling (instead of
// hooking every store mutation) keeps the stores untouched and is cheap: one
// atomic/RLock read per store per SampleInterval.
type EventsHub struct {
	// SampleInterval is how often the snapshot is polled for change (default 1s).
	SampleInterval time.Duration
	// PingInterval is the SSE keepalive-comment cadence (default 20s). Keep it
	// well under any fronting LB's idle timeout (Google ALB drops at ~60s idle).
	PingInterval time.Duration
	// MaxSubscribers bounds concurrent streams; each pins one goroutine and one
	// connection, and the endpoint is reachable per edge token, so a runaway
	// fleet (or a token in a reconnect loop) must shed instead of exhausting the
	// CP (default 1024). Over-limit gets 503 + Retry-After:RetryAfterSecs.
	MaxSubscribers int
	// MaxPerToken bounds streams per bearer token, so one misbehaving edge (a
	// reconnect loop that leaks streams) can't consume the GLOBAL cap and starve
	// every other edge's stream. Replicas may share one token (one stream each),
	// so size it >= replicas-per-token; default 32. <= 0 disables the per-token
	// bound (the global cap still applies).
	MaxPerToken int
	// RetryAfterSecs is the Retry-After on a shed 503 (default 30).
	RetryAfterSecs int

	snapshot func() EventsSnapshot

	mu       sync.Mutex
	subs     map[chan EventsSnapshot]string // chan -> subscribing token
	perToken map[string]int
}

// NewEventsHub builds a hub over the given snapshot source. Tune the exported
// fields before Run/Subscribe; zero values get the documented defaults.
func NewEventsHub(snapshot func() EventsSnapshot) *EventsHub {
	return &EventsHub{
		SampleInterval: time.Second,
		PingInterval:   20 * time.Second,
		MaxSubscribers: 1024,
		MaxPerToken:    32,
		RetryAfterSecs: 30,
		snapshot:       snapshot,
		subs:           map[chan EventsSnapshot]string{},
		perToken:       map[string]int{},
	}
}

// Current returns the live snapshot (sent as the first event of every stream,
// so a reconnecting edge immediately covers whatever changed while it was
// disconnected).
func (h *EventsHub) Current() EventsSnapshot { return h.snapshot() }

// Subscribe registers a stream for the given bearer token. ok=false means a
// cap is reached — global (MaxSubscribers) or per-token (MaxPerToken) — and the
// handler sheds with 503. The returned cancel must be called exactly once.
// The channel is buffered; a slow consumer keeps only the LATEST undelivered
// snapshot (each event carries the full vector, so intermediate ones are
// redundant) — the hub never blocks on a subscriber.
func (h *EventsHub) Subscribe(token string) (ch <-chan EventsSnapshot, cancel func(), ok bool) {
	c := make(chan EventsSnapshot, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.MaxSubscribers > 0 && len(h.subs) >= h.MaxSubscribers {
		return nil, nil, false
	}
	if h.MaxPerToken > 0 && h.perToken[token] >= h.MaxPerToken {
		return nil, nil, false
	}
	h.subs[c] = token
	h.perToken[token]++
	return c, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, registered := h.subs[c]; !registered {
			return // idempotent: a double cancel must not double-decrement the token count
		}
		delete(h.subs, c)
		if n := h.perToken[token]; n <= 1 {
			delete(h.perToken, token) // don't leak an entry per ever-seen token
		} else {
			h.perToken[token] = n - 1
		}
	}, true
}

// Run samples the snapshot and broadcasts on change, until ctx is done. Run it
// in a goroutine; one per process.
func (h *EventsHub) Run(ctx context.Context) {
	interval := h.SampleInterval
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	last := h.snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := h.snapshot()
			if cur == last {
				continue
			}
			last = cur
			h.broadcast(cur)
		}
	}
}

func (h *EventsHub) broadcast(snap EventsSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs {
		// Latest-wins, never block: drop the stale undelivered snapshot (if any),
		// then enqueue the current one.
		select {
		case <-c:
		default:
		}
		select {
		case c <- snap:
		default:
		}
	}
}
