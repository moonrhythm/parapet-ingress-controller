package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"
)

// eventsSnapshot mirrors edgecp.EventsSnapshot: the version vector the CP pushes
// on GET /v1/events. Values are opaque and process-local to the CP — they are
// only ever compared for inequality against the previous event on the SAME
// stream, never persisted or ordered.
type eventsSnapshot struct {
	WAF       string `json:"waf"`
	RateLimit string `json:"ratelimit"`
	Cache     string `json:"cache"`
	Hosts     string `json:"hosts"`
	Certs     string `json:"certs"`
	Purges    uint64 `json:"purges"`
}

// EventPokes carries the wake-up channels for the resource refresh loops. Each
// is optional (nil = that resource isn't running). Channels should be buffered
// (size 1); sends are non-blocking, so a poke arriving while a refresh is
// already pending coalesces.
type EventPokes struct {
	WAF       chan<- struct{}
	RateLimit chan<- struct{}
	Cache     chan<- struct{}
	Hosts     chan<- struct{}
	Certs     chan<- struct{}
	Purges    chan<- struct{}
}

func (p EventPokes) poke(ch chan<- struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// pokeAll wakes every wired loop — used right after (re)connecting, when any
// change during the disconnected window would otherwise wait for the poll floor.
// Cheap: each refresh is an ETag-revalidated fetch (steady state one 304 each).
func (p EventPokes) pokeAll() {
	p.poke(p.WAF)
	p.poke(p.RateLimit)
	p.poke(p.Cache)
	p.poke(p.Hosts)
	p.poke(p.Certs)
	p.poke(p.Purges)
}

// Watchdog: with the CP pinging every ~20s, a stream silent this long is dead
// (an LB that dropped the connection without FIN would otherwise block the read
// forever) — close and reconnect.
const eventsWatchdogTimeout = 90 * time.Second

// On ErrEventsUnsupported (old CP / events disabled) re-probe this often —
// rarely, since polling is doing the work meanwhile.
const eventsUnsupportedRetry = 5 * time.Minute

// Fleet-decorrelation jitter spans (vars so tests can zero them): the first
// connect after boot, and the reconnect after a clean EOF (a CP restart EOFs
// every edge's stream at the same instant).
var (
	eventsConnectJitter   = 5 * time.Second
	eventsReconnectJitter = 2 * time.Second
)

// RunEvents subscribes to the CP's change-notification stream (GET /v1/events)
// and pokes the matching refresh loop when a store's version changes. It is an
// ACCELERATOR only: every refresh still happens on its loop's goroutine
// (single-flight, fail-static, ETag-revalidated), and the jittered poll timers
// remain the correctness floor — any stream failure just falls back to that
// floor while this loop reconnects with backoff. Runs forever; fail-static.
func RunEvents(ctx context.Context, cp *CpClient, pokes EventPokes) {
	const backoffBase = time.Second
	const backoffMax = time.Minute
	// First connect is jittered like the poll loops: a fleet booted (or bounced)
	// together must not open its streams in lockstep. Boot freshness doesn't
	// suffer — main's synchronous initial fetches already ran.
	if !sleepCtx(ctx, fullJitter(eventsConnectJitter)) {
		return
	}
	backoff := backoffBase
	for ctx.Err() == nil {
		delivered, err := runEventsOnce(ctx, cp, pokes)
		// A stream that delivered events was a HEALTHY subscription, however it
		// ended — and in the documented fronting-LB deployment the common ending
		// is unclean: an LB response-timeout (or a SIGKILLed CP) cuts the chunked
		// response without the terminal 0-chunk, surfacing io.ErrUnexpectedEOF,
		// not a clean EOF. Backoff growth is evidence-of-failure only: without
		// this reset, every routine LB cut would double backoff and permanently
		// ratchet the whole fleet to backoffMax, silently degrading the stream's
		// ~seconds convergence to a fixed blind window per cut.
		if delivered {
			backoff = backoffBase
		}
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, ErrEventsUnsupported):
			slog.Info("edge: control plane has no /v1/events; relying on polling", "retry_in", eventsUnsupportedRetry)
			if !sleepCtx(ctx, eventsUnsupportedRetry) {
				return
			}
			backoff = backoffBase
		case err != nil:
			slog.Warn("edge: event stream ended; polling remains active; reconnecting", "error", err, "delivered", delivered, "backoff", backoff)
			if !sleepCtx(ctx, backoff+fullJitter(backoffBase)) {
				return
			}
			if !delivered {
				backoff = minDur(backoff*2, backoffMax)
			}
		default:
			// Clean EOF after a live stream (graceful CP handler return): reconnect
			// promptly but jittered — a CP restart EOFs the WHOLE fleet's streams at
			// once, and an unjittered reconnect would thunder.
			if !sleepCtx(ctx, fullJitter(eventsReconnectJitter)) {
				return
			}
		}
	}
}

// runEventsOnce opens one stream and consumes it until it ends. delivered
// reports whether at least one event arrived — the caller's backoff evidence:
// a delivered stream was healthy however it ended (LB cuts are unclean), while
// a 200 that ends before any event is an error (a misbehaving intermediary
// must back off, never drive a sleepless reconnect loop).
func runEventsOnce(ctx context.Context, cp *CpClient, pokes EventPokes) (delivered bool, err error) {
	// The watchdog cancels only THIS request's context, forcing the blocked
	// call to return when the stream goes silent past the ping cadence. It is
	// armed BEFORE the connect: the transport bounds each pre-response phase,
	// but the watchdog is the belt-and-suspenders ceiling on the whole connect
	// (a connect that survives past it is canceled, not waited on forever).
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wd := time.AfterFunc(eventsWatchdogTimeout, cancel)
	defer wd.Stop()

	resp, err := cp.OpenEvents(reqCtx)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	wd.Reset(eventsWatchdogTimeout)
	slog.Info("edge: event stream connected")

	// Any change while disconnected has already happened — cover the gap now.
	// The first received event then becomes the comparison baseline.
	pokes.pokeAll()

	var last eventsSnapshot
	first := true
	var data strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		wd.Reset(eventsWatchdogTimeout)
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, ":"): // keepalive comment
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "": // dispatch boundary
			if data.Len() == 0 {
				continue
			}
			var snap eventsSnapshot
			if err := json.Unmarshal([]byte(data.String()), &snap); err != nil {
				slog.Warn("edge: bad event payload; ignoring", "error", err)
			} else {
				if !first {
					if snap.WAF != last.WAF {
						pokes.poke(pokes.WAF)
					}
					if snap.RateLimit != last.RateLimit {
						pokes.poke(pokes.RateLimit)
					}
					if snap.Cache != last.Cache {
						pokes.poke(pokes.Cache)
					}
					if snap.Hosts != last.Hosts {
						pokes.poke(pokes.Hosts)
					}
					if snap.Certs != last.Certs {
						pokes.poke(pokes.Certs)
					}
					if snap.Purges != last.Purges {
						pokes.poke(pokes.Purges)
					}
				}
				last = snap
				first = false
			}
			data.Reset()
		}
	}
	delivered = !first
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		if reqCtx.Err() != nil {
			return delivered, errors.New("stream silent past watchdog; closed")
		}
		return delivered, err
	}
	if !delivered && ctx.Err() == nil {
		// Clean EOF with zero events: the CP always sends the current vector
		// immediately, so this is a misbehaving intermediary (a buffering proxy,
		// a synthesized 200, a CP dying mid-handshake). Surface it as an error so
		// the caller backs off instead of hot-looping the reconnect.
		return false, errors.New("stream ended before the initial event")
	}
	return delivered, nil
}
