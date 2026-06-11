package edge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sseServer streams the snapshots sent on events as SSE change events, then
// blocks until the request context ends.
func sseServer(t *testing.T, events <-chan string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		fl.Flush() // send headers now; the client unblocks on them
		for {
			select {
			case <-r.Context().Done():
				return
			case data, ok := <-events:
				if !ok {
					return
				}
				fmt.Fprintf(w, "event: change\ndata: %s\n\n", data)
				fl.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// zeroEventJitter removes the fleet-decorrelation connect jitter so tests are
// fast and deterministic; the returned func restores it.
func zeroEventJitter(t *testing.T) func() {
	t.Helper()
	prevConnect, prevReconnect := eventsConnectJitter, eventsReconnectJitter
	eventsConnectJitter, eventsReconnectJitter = 0, 0
	return func() { eventsConnectJitter, eventsReconnectJitter = prevConnect, prevReconnect }
}

func expectPoke(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected a %s poke", what)
	}
}

func expectNoPoke(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s poke", what)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRunEventsPokesOnChange(t *testing.T) {
	t.Cleanup(zeroEventJitter(t))
	events := make(chan string, 8)
	srv := sseServer(t, events)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}

	wafPoke := make(chan struct{}, 1)
	certPoke := make(chan struct{}, 1)
	purgePoke := make(chan struct{}, 1)
	pokes := EventPokes{WAF: wafPoke, Certs: certPoke, Purges: purgePoke}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunEvents(ctx, cp, pokes)

	// On connect every wired loop is poked once (gap coverage).
	expectPoke(t, wafPoke, "connect waf")
	expectPoke(t, certPoke, "connect certs")
	expectPoke(t, purgePoke, "connect purges")

	// First event is the baseline — no pokes.
	events <- `{"waf":"a","certs":"c","purges":1}`
	expectNoPoke(t, wafPoke, "baseline waf")

	// Only the changed field pokes.
	events <- `{"waf":"b","certs":"c","purges":1}`
	expectPoke(t, wafPoke, "waf change")
	expectNoPoke(t, certPoke, "certs unchanged")
	expectNoPoke(t, purgePoke, "purges unchanged")

	// A nil channel (resource not running) is skipped without panic.
	events <- `{"waf":"b","certs":"c","purges":2,"ratelimit":"r"}`
	expectPoke(t, purgePoke, "purge change")
}

func TestRunEventsOnceZeroEventEOFErrors(t *testing.T) {
	// A 200 text/event-stream that ends before any event must be an ERROR (the
	// reconnect loop backs off) — nil would drive a sleepless hot loop against a
	// misbehaving intermediary.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		// return: instant clean EOF, zero events
	}))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := runEventsOnce(context.Background(), cp, EventPokes{})
	if err == nil {
		t.Fatal("zero-event EOF must return an error so the caller backs off")
	}
	if delivered {
		t.Fatal("a zero-event stream must not count as delivered")
	}
}

func TestRunEventsOnceDeliveredSurvivesUncleanCut(t *testing.T) {
	// A stream that delivered events and is then cut WITHOUT the chunked
	// terminal 0-chunk (an LB response-timeout, a SIGKILLed CP) must report
	// delivered=true with the read error — the caller resets backoff on
	// delivered streams, so routine LB cuts can't ratchet the fleet to
	// permanent max backoff.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		ev := "event: change\ndata: {\"waf\":\"a\"}\n\n"
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		fmt.Fprintf(buf, "%x\r\n%s\r\n", len(ev), ev)
		buf.Flush()
		// close without the terminal 0-chunk → io.ErrUnexpectedEOF at the client
	}))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := runEventsOnce(context.Background(), cp, EventPokes{})
	if err == nil {
		t.Fatal("an unclean cut must surface a read error")
	}
	if !delivered {
		t.Fatal("a stream that delivered an event must report delivered=true")
	}
}

func TestOpenEventsUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.OpenEvents(context.Background()); !errors.Is(err, ErrEventsUnsupported) {
		t.Fatalf("err = %v, want ErrEventsUnsupported", err)
	}
}

func TestOpenEventsRejectsNonSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.OpenEvents(context.Background()); err == nil {
		t.Fatal("a non-SSE 200 must be rejected")
	}
}

func TestRunWafRefreshPoke(t *testing.T) {
	hits := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/waf" {
			hits <- struct{}{}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}

	poke := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Interval far beyond the test deadline: any fetch can only come from the
	// poke (honored even during the loop's initial jitter window).
	go RunWafRefresh(ctx, cp, NewEdgeWAF(nil, nil, NewEdgeTopology()), 10*time.Minute, nil, poke)
	poke <- struct{}{}
	select {
	case <-hits:
	case <-time.After(2 * time.Second):
		t.Fatal("poke did not trigger a WAF fetch")
	}
}
