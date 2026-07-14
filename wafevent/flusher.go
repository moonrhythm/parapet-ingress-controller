package wafevent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"time"
)

// DefaultFlushInterval is how often the flusher drains the ring. A constant
// band of 30–60s is fine (SPEC-waf-events §F); 30s halves the worst-case
// console lag for free. Overridable via WAF_EVENTS_PUSH_INTERVAL.
const DefaultFlushInterval = 30 * time.Second

const (
	// maxBatch caps one collector.setWAFEvents call's list. Mirrors
	// api.WAFEventsMaxBatch in github.com/deploys-app/api (not imported —
	// see the wire-shape note below).
	maxBatch = 5000

	// pushTimeout bounds one POST end to end (what the deploys-app
	// collector's own HTTP client uses).
	pushTimeout = 10 * time.Second
)

// pushRequest / pushItem are the collector.setWAFEvents request body —
// hand-written mirrors of github.com/deploys-app/api's CollectorSetWAFEvents /
// CollectorWAFEventItem. This repo deliberately does not import that module;
// the JSON field names (including projectId's string encoding) are pinned by
// TestPushRequestWireShape and must match the api structs' tags exactly.
type pushRequest struct {
	Location string      `json:"location"`
	List     []*pushItem `json:"list"`
}

type pushItem struct {
	ID        string `json:"id"`               // controller ULID, dedupe key
	ProjectID int64  `json:"projectId,string"` // parsed from the RuleID prefix
	RuleID    string `json:"ruleId"`           // full generated id (<projectID>-<rand>)
	Action    string `json:"action"`           // log|allow|block
	Status    int    `json:"status"`
	At        int64  `json:"at"` // unix second (event time at the engine)
	ClientIP  string `json:"clientIp"`
	Country   string `json:"country"`
	ASN       int64  `json:"asn"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
}

// pushResponse is the arpc envelope; only ok matters to the flusher.
type pushResponse struct {
	OK bool `json:"ok"`
}

// Flusher drains a Buffer past a pod-local high-water mark and POSTs batches
// directly to the deploys-app apiserver's collector.setWAFEvents RPC
// (SPEC-waf-events §F). One Flusher per pod; N replicas are N independent
// pushers needing zero coordination — per-pod rings, per-pod marks, per-pod
// ULIDs. Delivery is at-least-once into an idempotent (ULID-deduped) sink:
// the mark advances only on a confirmed ok response, a response lost after
// the DB commit resends one already-stored batch, and drop-oldest ring
// eviction bounds memory when the apiserver is unreachable.
type Flusher struct {
	Buffer   *Buffer
	URL      string        // WAF_EVENTS_PUSH_URL — the collector.setWAFEvents endpoint
	Token    string        // WAF_EVENTS_PUSH_TOKEN — the location's collector token (Bearer)
	Location string        // WAF_EVENTS_PUSH_LOCATION — sent as the request's location
	Interval time.Duration // 0 → DefaultFlushInterval
	Client   *http.Client  // nil → a client with pushTimeout

	// OnPush, when set, is called with the number of events confirmed stored
	// after each successful POST (the controller wires it to the
	// parapet_waf_event_pushed metric).
	OnPush func(n int)

	mark     uint64 // Seq of the last event confirmed stored (pod-local, in-memory)
	failures int    // consecutive failed flush attempts, for rate-limited logging
}

// Run flushes every Interval until ctx is cancelled. A small random startup
// delay de-phases N replicas. Call in its own goroutine.
func (f *Flusher) Run(ctx context.Context) {
	interval := f.Interval
	if interval <= 0 {
		interval = DefaultFlushInterval
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(mrand.Int64N(int64(interval)))):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.flush(ctx)
		}
	}
}

// flush drains the ring: read one batch past the mark, POST it, advance the
// mark only on success, and loop while more remain. On failure the mark stays
// put and the next tick retries — no retry within a tick, so a struggling
// apiserver never sees a hot loop. Events whose rule id carries no parseable
// project prefix cannot be attributed and are skipped (the mark still
// advances past them; resending cannot fix a malformed id).
func (f *Flusher) flush(ctx context.Context) {
	for {
		events, next := f.Buffer.Read(f.mark, maxBatch)
		if len(events) == 0 {
			return
		}
		batch := make([]*pushItem, 0, len(events))
		for i := range events {
			if it, ok := toPushItem(&events[i]); ok {
				batch = append(batch, it)
			}
		}
		if len(batch) > 0 {
			if err := f.post(ctx, batch); err != nil {
				f.failures++
				if f.failures == 1 {
					// Rate-limited: one warn per consecutive-failure streak,
					// not per tick — the recovery line below closes the streak.
					slog.Warn("waf: match-event push failed; high-water mark kept, retrying next flush",
						"url", f.URL, "events", len(batch), "error", err)
				}
				return
			}
			if f.OnPush != nil {
				f.OnPush(len(batch))
			}
		}
		if f.failures > 0 {
			slog.Info("waf: match-event push recovered", "failed_attempts", f.failures)
			f.failures = 0
		}
		f.mark = next
	}
}

// post sends one collector.setWAFEvents call and returns nil only for an
// HTTP 2xx carrying {"ok":true} — anything else (network error, non-2xx,
// ok:false) is a failure and the caller keeps its mark.
func (f *Flusher) post(ctx context.Context, batch []*pushItem) error {
	body, err := json.Marshal(pushRequest{Location: f.Location, List: batch})
	if err != nil {
		return err
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: pushTimeout}
	}
	// A per-attempt deadline even when a caller-supplied client has none,
	// while staying cancellable on shutdown via ctx.
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.Token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) // keep the connection reusable
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	var pr pushResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !pr.OK {
		return fmt.Errorf("rpc returned ok=false")
	}
	return nil
}

// toPushItem maps a ring event to the wire item, parsing the numeric project
// id from the rule id's <projectID>- prefix (the same attribution parse the
// deploys-app collector applies for setWAFUsage; the apiserver re-checks the
// pairing server-side). ok is false when the prefix is missing or overflows.
func toPushItem(e *Event) (*pushItem, bool) {
	projectID, ok := parseProjectID(e.RuleID)
	if !ok {
		return nil, false
	}
	return &pushItem{
		ID:        e.ID,
		ProjectID: projectID,
		RuleID:    e.RuleID,
		Action:    e.Action,
		Status:    e.Status,
		At:        e.At,
		ClientIP:  e.ClientIP,
		Country:   e.Country,
		ASN:       e.ASN,
		Method:    e.Method,
		Host:      e.Host,
		Path:      e.Path,
	}, true
}

// parseProjectID extracts the leading ^(\d+)- of a project-prefixed rule id.
func parseProjectID(ruleID string) (int64, bool) {
	var n int64
	i := 0
	for ; i < len(ruleID) && ruleID[i] >= '0' && ruleID[i] <= '9'; i++ {
		d := int64(ruleID[i] - '0')
		if n > (1<<63-1-d)/10 {
			return 0, false // overflow
		}
		n = n*10 + d
	}
	if i == 0 || i >= len(ruleID) || ruleID[i] != '-' {
		return 0, false
	}
	return n, true
}
