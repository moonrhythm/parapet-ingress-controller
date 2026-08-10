package wafevent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPushRequestWireShape pins the hand-written collector.setWAFEvents body
// against a golden string. The field names — including projectId's ,string
// encoding — mirror github.com/deploys-app/api's CollectorSetWAFEvents /
// CollectorWAFEventItem JSON tags exactly; this repo must not import that
// module, so this test is the wire contract. If it fails, one side drifted.
func TestPushRequestWireShape(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(pushRequest{
		Location: "gke.cluster-rcf2",
		List: []*pushItem{{
			ID:        "01JZWXYZ0123456789ABCDEFGH",
			ProjectID: 42,
			RuleID:    "42-abcd",
			Action:    "block",
			Status:    403,
			At:        1752000000,
			ClientIP:  "203.0.113.7",
			Country:   "TH",
			ASN:       4750,
			Method:    "POST",
			Host:      "example.com",
			Path:      "/wp-login.php",
		}},
	})
	require.NoError(t, err)
	assert.Equal(t,
		`{"location":"gke.cluster-rcf2","list":[`+
			`{"id":"01JZWXYZ0123456789ABCDEFGH","projectId":"42","ruleId":"42-abcd",`+
			`"action":"block","status":403,"at":1752000000,"clientIp":"203.0.113.7",`+
			`"country":"TH","asn":4750,"method":"POST","host":"example.com","path":"/wp-login.php"}]}`,
		string(body))
}

func TestParseProjectID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ruleID string
		want   int64
		ok     bool
	}{
		{"42-abcd", 42, true},
		{"1234-x", 1234, true},
		{"0-x", 0, true},
		{"abcd", 0, false},
		{"-abcd", 0, false},
		{"42", 0, false}, // digits but no dash
		{"42x-a", 0, false},
		{"", 0, false},
		{"99999999999999999999-x", 0, false}, // overflows int64
	}
	for _, c := range cases {
		got, ok := parseProjectID(c.ruleID)
		assert.Equal(t, c.ok, ok, c.ruleID)
		assert.Equal(t, c.want, got, c.ruleID)
	}
}

// pushServer is a fake collector.setWAFEvents endpoint recording each call.
type pushServer struct {
	*httptest.Server
	mu       chan struct{} // 1-slot semaphore keeps appends test-side simple
	requests []pushRequest
	auth     []string
	fail     atomic.Bool // respond 500 while set
	okFalse  atomic.Bool // respond 200 {"ok":false} while set
}

func newPushServer(t *testing.T) *pushServer {
	t.Helper()
	ps := &pushServer{mu: make(chan struct{}, 1)}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body pushRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		ps.mu <- struct{}{}
		ps.requests = append(ps.requests, body)
		ps.auth = append(ps.auth, r.Header.Get("Authorization"))
		<-ps.mu
		if ps.fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if ps.okFalse.Load() {
			_, _ = w.Write([]byte(`{"ok":false,"error":{"message":"nope"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	t.Cleanup(ps.Close)
	return ps
}

func newTestFlusher(b *Buffer, ps *pushServer) *Flusher {
	return &Flusher{
		Buffer:   b,
		URL:      ps.URL,
		Token:    "secret-token",
		Location: "gke.cluster-rcf2",
		Client:   ps.Client(),
	}
}

func TestFlusherPushAdvancesMark(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	require.True(t, b.Append(blockEvent("ns/z", "42-r1"), nil))
	require.True(t, b.Append(logEvent("ns/z", "42-r2"), nil))

	ps := newPushServer(t)
	f := newTestFlusher(b, ps)
	pushed := 0
	f.OnPush = func(n int) { pushed += n }

	f.flush(context.Background())
	require.Len(t, ps.requests, 1)
	req := ps.requests[0]
	assert.Equal(t, "Bearer secret-token", ps.auth[0])
	assert.Equal(t, "gke.cluster-rcf2", req.Location)
	require.Len(t, req.List, 2)
	assert.Equal(t, int64(42), req.List[0].ProjectID)
	assert.Equal(t, "42-r1", req.List[0].RuleID)
	assert.Equal(t, "block", req.List[0].Action)
	assert.Len(t, req.List[0].ID, 26)
	assert.NotZero(t, req.List[0].At)
	assert.Equal(t, 2, pushed)

	// Mark advanced: an immediate re-flush sends nothing.
	f.flush(context.Background())
	assert.Len(t, ps.requests, 1)

	// New events resume past the mark, not from the tail.
	require.True(t, b.Append(blockEvent("ns/z", "42-r3"), nil))
	f.flush(context.Background())
	require.Len(t, ps.requests, 2)
	require.Len(t, ps.requests[1].List, 1)
	assert.Equal(t, "42-r3", ps.requests[1].List[0].RuleID)
	assert.Equal(t, 3, pushed)
}

func TestFlusherFailureKeepsMarkAndRetries(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	require.True(t, b.Append(blockEvent("ns/z", "42-r1"), nil))

	ps := newPushServer(t)
	f := newTestFlusher(b, ps)

	// HTTP 500: failure — the mark must not advance (no hot retry either:
	// exactly one POST per flush attempt).
	ps.fail.Store(true)
	f.flush(context.Background())
	f.flush(context.Background())
	require.Len(t, ps.requests, 2, "one POST per tick, no in-tick retry")
	assert.Equal(t, 2, f.failures)

	// 200 {"ok":false}: still a failure.
	ps.fail.Store(false)
	ps.okFalse.Store(true)
	f.flush(context.Background())
	require.Len(t, ps.requests, 3)
	assert.Equal(t, 3, f.failures)

	// Recovery: the same events are redelivered (at-least-once; the ingest
	// dedupes on the ULID) and the failure streak resets.
	ps.okFalse.Store(false)
	f.flush(context.Background())
	require.Len(t, ps.requests, 4)
	require.Len(t, ps.requests[3].List, 1)
	assert.Equal(t, ps.requests[0].List[0].ID, ps.requests[3].List[0].ID, "same event resent after failure")
	assert.Zero(t, f.failures)

	f.flush(context.Background())
	assert.Len(t, ps.requests, 4, "drained after success")
}

func TestFlusherBatchCapLoops(t *testing.T) {
	t.Parallel()

	// 5001 admitted events must drain as two POSTs in one flush (5000 + 1):
	// the batch cap mirrors api.WAFEventsMaxBatch.
	b, clock := newTestBuffer(8192)
	for range maxBatch + 1 {
		clock.advance(time.Minute) // fresh sampling window per append
		require.True(t, b.Append(blockEvent("ns/z", "42-r1"), nil))
	}

	ps := newPushServer(t)
	f := newTestFlusher(b, ps)
	f.flush(context.Background())

	require.Len(t, ps.requests, 2)
	assert.Len(t, ps.requests[0].List, maxBatch)
	assert.Len(t, ps.requests[1].List, 1)

	f.flush(context.Background())
	assert.Len(t, ps.requests, 2, "drained")
}

func TestFlusherSkipsUnattributableEvents(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	require.True(t, b.Append(blockEvent("ns/z", "no-project-prefix"), nil))
	require.True(t, b.Append(blockEvent("ns/z", "42-good"), nil))

	ps := newPushServer(t)
	f := newTestFlusher(b, ps)
	f.flush(context.Background())

	require.Len(t, ps.requests, 1)
	require.Len(t, ps.requests[0].List, 1, "unparseable rule id is skipped, not sent")
	assert.Equal(t, "42-good", ps.requests[0].List[0].RuleID)

	// A range that is entirely unattributable advances the mark without a POST.
	require.True(t, b.Append(blockEvent("ns/z", "also-bad"), nil))
	f.flush(context.Background())
	assert.Len(t, ps.requests, 1, "nothing to send — and no empty-list POST")
	events, _ := b.Read(f.mark, 10)
	assert.Empty(t, events, "mark advanced past the skipped event")
}

func TestFlusherRunStopsOnCancel(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(16)
	require.True(t, b.Append(blockEvent("ns/z", "42-r1"), nil))

	ps := newPushServer(t)
	f := newTestFlusher(b, ps)
	f.Interval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()

	// Wait for at least one flush to land, then cancel; Run must return.
	require.Eventually(t, func() bool {
		ps.mu <- struct{}{}
		n := len(ps.requests)
		<-ps.mu
		return n >= 1
	}, 5*time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
}
