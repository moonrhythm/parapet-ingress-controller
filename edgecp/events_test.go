package edgecp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventsHubBroadcastOnChange(t *testing.T) {
	var version atomic.Value
	version.Store("v1")
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{WAF: version.Load().(string)} })
	hub.SampleInterval = 5 * time.Millisecond

	ch, cancel, ok := hub.Subscribe("tok")
	if !ok {
		t.Fatal("subscribe should succeed under the cap")
	}
	defer cancel()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go hub.Run(ctx)
	// Let Run take its v1 baseline before flipping (it samples on start).
	time.Sleep(50 * time.Millisecond)
	version.Store("v2")
	select {
	case snap := <-ch:
		if snap.WAF != "v2" {
			t.Fatalf("snapshot WAF = %q, want v2", snap.WAF)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast after a version change")
	}

	// No change → no event.
	select {
	case snap := <-ch:
		t.Fatalf("unexpected broadcast without change: %+v", snap)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEventsHubSubscriberCapAndLatestWins(t *testing.T) {
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{} })
	hub.MaxSubscribers = 1

	ch, cancel, ok := hub.Subscribe("tok")
	if !ok {
		t.Fatal("first subscribe should succeed")
	}
	if _, _, ok := hub.Subscribe("other"); ok {
		t.Fatal("second subscribe should be rejected at the global cap")
	}

	// A slow consumer keeps only the latest snapshot.
	hub.broadcast(EventsSnapshot{Purges: 1})
	hub.broadcast(EventsSnapshot{Purges: 2})
	if snap := <-ch; snap.Purges != 2 {
		t.Fatalf("slow consumer got %d, want the latest (2)", snap.Purges)
	}

	cancel()
	if _, cancel2, ok := hub.Subscribe("tok"); !ok {
		t.Fatal("subscribe should succeed again after cancel freed the slot")
	} else {
		cancel2()
	}
}

func TestEventsHubPerTokenCap(t *testing.T) {
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{} })
	hub.MaxSubscribers = 10
	hub.MaxPerToken = 1

	_, cancelA, ok := hub.Subscribe("a")
	if !ok {
		t.Fatal("first subscribe for token a should succeed")
	}
	if _, _, ok := hub.Subscribe("a"); ok {
		t.Fatal("second subscribe for token a should be rejected at the per-token cap")
	}
	// Another token is unaffected: the cap is per token, not global.
	if _, cancelB, ok := hub.Subscribe("b"); !ok {
		t.Fatal("token b should not be starved by token a's cap")
	} else {
		defer cancelB()
	}

	// Double cancel must not double-decrement (idempotent), and the freed slot
	// must be reusable.
	cancelA()
	cancelA()
	if _, cancelA2, ok := hub.Subscribe("a"); !ok {
		t.Fatal("token a should subscribe again after cancel")
	} else {
		cancelA2()
	}
}

// eventsTestServer wires a real Server + hub on an httptest server (SSE needs a
// real flusher; httptest.NewRecorder can't stream).
func eventsTestServer(t *testing.T, hub *EventsHub) *httptest.Server {
	t.Helper()
	srv := NewServer(NewCertStore(), NewAuthz(map[string][]string{"tok": {"example.com"}}))
	if hub != nil {
		srv = srv.WithEvents(hub)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHandleEventsAuthAndDisabled(t *testing.T) {
	ts := eventsTestServer(t, nil) // events disabled

	req, _ := http.NewRequest("GET", ts.URL+"/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}

	req.Header.Set("Authorization", "Bearer tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("events disabled: status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleEventsStreamsInitialAndChange(t *testing.T) {
	var version atomic.Value
	version.Store("v1")
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{WAF: version.Load().(string)} })
	hub.SampleInterval = 5 * time.Millisecond
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go hub.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let Run take its v1 baseline

	ts := eventsTestServer(t, hub)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}

	sc := bufio.NewScanner(resp.Body) // one scanner: its buffer may hold the next event
	readEvent := func() EventsSnapshot {
		t.Helper()
		var data string
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data:") {
				data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
			if line == "" && data != "" {
				break
			}
		}
		if data == "" {
			t.Fatalf("stream ended without an event: %v", sc.Err())
		}
		var snap EventsSnapshot
		if err := json.Unmarshal([]byte(data), &snap); err != nil {
			t.Fatal(err)
		}
		return snap
	}

	if snap := readEvent(); snap.WAF != "v1" {
		t.Fatalf("initial event WAF = %q, want v1", snap.WAF)
	}
	version.Store("v2")
	if snap := readEvent(); snap.WAF != "v2" {
		t.Fatalf("change event WAF = %q, want v2", snap.WAF)
	}
}

func TestHandleEventsPingIntervalFloor(t *testing.T) {
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{WAF: "v"} })
	hub.PingInterval = 0 // a zeroed env knob must degrade to the default, not panic NewTicker
	ts := eventsTestServer(t, hub)

	req, _ := http.NewRequest("GET", ts.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// The initial event must arrive (the handler survived the zero interval).
	buf := make([]byte, 16)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("initial event not readable: %v", err)
	}
}

func TestHandleEventsShedsOverCap(t *testing.T) {
	hub := NewEventsHub(func() EventsSnapshot { return EventsSnapshot{} })
	hub.MaxSubscribers = 1
	ts := eventsTestServer(t, hub)

	open := func() *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/events", nil)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := open()
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first stream status = %d, want 200", first.StatusCode)
	}
	// Wait for the first stream's initial event so its Subscribe has happened.
	buf := make([]byte, 1)
	if _, err := first.Body.Read(buf); err != nil {
		t.Fatal(err)
	}

	second := open()
	defer second.Body.Close()
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over-cap stream status = %d, want 503", second.StatusCode)
	}
	if second.Header.Get("Retry-After") == "" {
		t.Fatal("shed 503 must carry Retry-After")
	}
}
