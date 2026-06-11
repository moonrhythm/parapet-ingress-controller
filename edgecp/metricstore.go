package edgecp

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/moonrhythm/parapet/pkg/prom"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// maxEdgeMetricsBody bounds one POST /v1/metrics body. A full edge registry
// (request/host/backend vecs + edge_* gauges + go_*/process_*) is tens-to-hundreds
// of KiB; 8 MiB is generous headroom without letting a compromised edge OOM the CP.
const maxEdgeMetricsBody = 8 << 20

// maxInstanceLen bounds the self-reported X-Edge-Instance header (it becomes a
// label value, so it must stay sane).
const maxInstanceLen = 128

// maxEdgeMetricsInstances bounds DISTINCT instances stored per edge_id. The
// instance id is self-reported, so without this one token could mint unbounded
// instance ids (each holding a parsed multi-MiB snapshot) and OOM the CP long
// before the TTL fires. At the cap a NEW instance evicts that identity's STALEST
// one (counted) — legitimate instance-id churn self-heals instead of hard-failing,
// and total memory stays bounded at tokens x cap x snapshot.
const maxEdgeMetricsInstances = 128

// MetricsStore holds the last pushed metrics snapshot per edge INSTANCE. Multiple
// edge processes can run under one edge_id (a scaled fleet behind one token), so
// snapshots are keyed by (edge_id, instance) — edge_id alone would have replicas
// clobbering each other. Snapshots are parsed and edge_id/edge_instance-labelled at
// push time, so a scrape only flattens maps. A snapshot not refreshed within ttl is
// lazily evicted at read time (no janitor goroutine): a dead instance's series
// disappear instead of being served stale forever, and instance-id churn (random
// hostnames across reboots) stays bounded.
type MetricsStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	edges map[string]edgeMetricsSnapshot // edge_id + "/" + instance -> snapshot
	now   func() time.Time               // injectable for tests
}

type edgeMetricsSnapshot struct {
	edgeID     string
	instance   string
	families   map[string]*dto.MetricFamily
	receivedAt time.Time
}

// NewMetricsStore builds a store whose snapshots expire ttl after their last push
// (recommend >= 3x the fleet's push interval). ttl <= 0 falls back to 5 minutes.
func NewMetricsStore(ttl time.Duration) *MetricsStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MetricsStore{
		ttl:   ttl,
		edges: make(map[string]edgeMetricsSnapshot),
		now:   time.Now,
	}
}

// Ingest parses one text-exposition body and replaces the (edgeID, instance)
// snapshot. Every metric gets edge_id and edge_instance labels injected — OVERRIDING
// any self-reported value, so the label is always the server-derived identity
// (edgeID comes from the bearer token's id grant, never the body). A parse error
// stores nothing (the last-good snapshot is kept).
func (s *MetricsStore) Ingest(edgeID, instance string, r io.Reader) error {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(r)
	if err != nil {
		return fmt.Errorf("parse metrics: %w", err)
	}
	for _, mf := range families {
		for _, m := range mf.Metric {
			setLabel(m, "edge_id", edgeID)
			setLabel(m, "edge_instance", instance)
		}
	}
	now := s.now()
	key := edgeID + "/" + instance
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.edges[key]; !exists {
		s.evictAtCapLocked(edgeID)
	}
	s.edges[key] = edgeMetricsSnapshot{
		edgeID:     edgeID,
		instance:   instance,
		families:   families,
		receivedAt: now,
	}
	edgeMetricsLastPush.WithLabelValues(edgeID, instance).Set(float64(now.Unix()))
	return nil
}

// evictAtCapLocked makes room for one NEW instance under edgeID: while the
// identity is at maxEdgeMetricsInstances, its stalest instance is evicted
// (freshness series deleted with it, eviction counted). Callers hold s.mu.
func (s *MetricsStore) evictAtCapLocked(edgeID string) {
	for {
		count := 0
		var oldestKey string
		var oldest time.Time
		for k, snap := range s.edges {
			if snap.edgeID != edgeID {
				continue
			}
			count++
			if oldestKey == "" || snap.receivedAt.Before(oldest) {
				oldestKey, oldest = k, snap.receivedAt
			}
		}
		if count < maxEdgeMetricsInstances {
			return
		}
		snap := s.edges[oldestKey]
		edgeMetricsLastPush.DeleteLabelValues(snap.edgeID, snap.instance)
		delete(s.edges, oldestKey)
		edgeMetricsInstanceEvicted.Inc()
	}
}

// setLabel sets (or overrides) one label on a metric, keeping the pair list sorted
// by name — the dto contract expfmt encoders and Prometheus expect.
func setLabel(m *dto.Metric, name, value string) {
	for _, lp := range m.Label {
		if lp.GetName() == name {
			lp.Value = &value
			return
		}
	}
	m.Label = append(m.Label, &dto.LabelPair{Name: &name, Value: &value})
	sort.Slice(m.Label, func(i, j int) bool { return m.Label[i].GetName() < m.Label[j].GetName() })
}

// families returns every live (non-expired) instance's metric families, evicting
// expired snapshots and deleting their freshness series on the way. Deterministic
// order (sorted by instance key) so merged output is stable across scrapes.
func (s *MetricsStore) families() []*dto.MetricFamily {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.edges))
	for k, snap := range s.edges {
		if now.Sub(snap.receivedAt) > s.ttl {
			edgeMetricsLastPush.DeleteLabelValues(snap.edgeID, snap.instance)
			delete(s.edges, k)
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*dto.MetricFamily
	for _, k := range keys {
		snap := s.edges[k]
		names := make([]string, 0, len(snap.families))
		for name := range snap.families {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out = append(out, snap.families[name])
		}
	}
	return out
}

// MetricsHandler serves the CP's own registry MERGED with every live pushed edge
// snapshot as one text-exposition response — the single scrape target for the CP +
// the edge fleet. Mount it on the (NetworkPolicy-restricted) CP_METRICS_LISTEN.
func MetricsHandler(store *MetricsStore) http.Handler {
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		own, err := prom.Registry().Gather()
		if err != nil && len(own) == 0 {
			http.Error(w, "gather failed", http.StatusInternalServerError)
			return
		}
		merged := mergeFamilies(own, store.families())
		w.Header().Set("Content-Type", string(format))
		enc := expfmt.NewEncoder(w, format)
		for _, mf := range merged {
			_ = enc.Encode(mf)
		}
	})
}

// mergeFamilies merges edge families into the CP's own, BY FAMILY NAME, so each
// family is encoded exactly once (one # HELP/# TYPE block, all label sets — the
// CP's series plus one per edge instance). The first family seen for a name wins
// HELP/TYPE (own comes first, so the CP is authoritative); a later family with a
// conflicting TYPE is dropped whole (counted) rather than emitting an invalid
// exposition. Inputs are never mutated — merged entries are fresh copies — so a
// scrape can't corrupt a stored snapshot. Output is sorted by family name.
func mergeFamilies(own, edge []*dto.MetricFamily) []*dto.MetricFamily {
	idx := make(map[string]*dto.MetricFamily, len(own)+len(edge))
	out := make([]*dto.MetricFamily, 0, len(own)+len(edge))
	add := func(mf *dto.MetricFamily) {
		if base, ok := idx[mf.GetName()]; ok {
			if base.GetType() != mf.GetType() {
				edgeMetricsFamilyDropped.Inc()
				return
			}
			base.Metric = append(base.Metric, mf.Metric...)
			return
		}
		cp := &dto.MetricFamily{
			Name:   mf.Name,
			Help:   mf.Help,
			Type:   mf.Type,
			Metric: append([]*dto.Metric{}, mf.Metric...),
		}
		idx[cp.GetName()] = cp
		out = append(out, cp)
	}
	for _, mf := range own {
		add(mf)
	}
	for _, mf := range edge {
		add(mf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return out
}
