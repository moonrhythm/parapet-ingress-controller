package converge

import (
	"context"
	"fmt"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// Querier is the minimal Prometheus instant-query surface Snapshot needs. The real impl
// wraps the client_golang v1 API; tests inject a fake returning canned vectors — so the
// reader is fully testable WITHOUT a live Prometheus.
type Querier interface {
	Query(ctx context.Context, query string, ts time.Time) (model.Vector, error)
}

// NewPromQuerier dials a Prometheus HTTP API at base (e.g. http://prometheus:9090).
func NewPromQuerier(base string) (Querier, error) {
	c, err := promapi.NewClient(promapi.Config{Address: base})
	if err != nil {
		return nil, fmt.Errorf("prometheus client: %w", err)
	}
	return &promQuerier{api: promv1.NewAPI(c)}, nil
}

type promQuerier struct{ api promv1.API }

func (p *promQuerier) Query(ctx context.Context, query string, ts time.Time) (model.Vector, error) {
	v, _, err := p.api.Query(ctx, query, ts)
	if err != nil {
		return nil, err
	}
	vec, ok := v.(model.Vector)
	if !ok {
		return nil, fmt.Errorf("query %q: expected an instant vector, got %s", query, v.Type())
	}
	return vec, nil
}

// Snapshot collects the cross-plane Observations from Prometheus. The plane of a series
// is identified by WHICH metric it is (CP-only / core-only / edge-only metric names), so
// no job-label config is needed. It does NOT run the revoked-token probe — that is an
// HTTP call the CLI performs and stamps onto the returned Observations. A query error is
// returned (fail-closed: the caller renders NO converged verdict on a Prometheus outage).
//
// `up` is joined by `instance` for CP/core (Prometheus stamps it automatically) and by
// `edge_id` for edges (the scrape config must relabel edge_id onto the edge targets).
func Snapshot(ctx context.Context, q Querier, freshness time.Duration, now time.Time) (Observations, error) {
	fw := model.Duration(freshness).String()
	get := func(query string) (model.Vector, error) { return q.Query(ctx, query, now) }

	upByInstance, err := boolByLabel(get, "up", "instance", func(f float64) bool { return f == 1 })
	if err != nil {
		return Observations{}, err
	}
	upByEdge, err := boolByLabel(get, "up", "edge_id", func(f float64) bool { return f == 1 })
	if err != nil {
		return Observations{}, err
	}

	var obs Observations

	// ---- CP plane (edge_ca_* metrics) ----
	signerFP, err := labelByInstance(get, "parapet_edge_ca_signer_fingerprint", "ca_id")
	if err != nil {
		return Observations{}, err
	}
	targetCAID, err := labelByInstance(get, "parapet_edge_ca_target_ca_id", "ca_id")
	if err != nil {
		return Observations{}, err
	}
	signerGen, err := valueByInstance(get, "parapet_edge_ca_signer_generation")
	if err != nil {
		return Observations{}, err
	}
	bundleCerts, err := valueByInstance(get, "parapet_edge_ca_bundle_certs")
	if err != nil {
		return Observations{}, err
	}
	authzGen, err := valueByInstance(get, "parapet_edge_authz_generation")
	if err != nil {
		return Observations{}, err
	}
	for inst, fp := range signerFP {
		obs.CP = append(obs.CP, CPReplica{
			Instance: inst, Up: upByInstance[inst],
			SignerCAID: fp, TargetCAID: targetCAID[inst],
			SignerGen: uint64(signerGen[inst]), BundleCerts: int(bundleCerts[inst]), AuthzGen: authzGen[inst],
		})
	}

	// ---- Core plane (trust_bundle_* metrics) ----
	heldCAID, err := labelByInstance(get, "parapet_trust_bundle_generation", "ca_id")
	if err != nil {
		return Observations{}, err
	}
	for inst, ca := range heldCAID {
		obs.Core = append(obs.Core, CoreReplica{Instance: inst, Up: upByInstance[inst], HeldCAID: ca})
	}

	// ---- Edge plane (edge_clientcert_* / edge_refresh_* metrics, keyed by edge_id) ----
	liveCAID, err := labelByLabel(get, "parapet_edge_clientcert_ca_id", "edge_id", "ca_id")
	if err != nil {
		return Observations{}, err
	}
	observedTarget, err := labelByLabel(get, "parapet_edge_cp_target_ca_id", "edge_id", "ca_id")
	if err != nil {
		return Observations{}, err
	}
	refreshed, err := boolByLabel(get, fmt.Sprintf("increase(parapet_edge_refresh_total[%s])", fw), "edge_id", func(f float64) bool { return f >= 1 })
	if err != nil {
		return Observations{}, err
	}
	failed, err := boolByLabel(get, fmt.Sprintf(`increase(parapet_edge_clientcert_remint_total{result!="ok"}[%s])`, fw), "edge_id", func(f float64) bool { return f > 0 })
	if err != nil {
		return Observations{}, err
	}
	for id, ca := range liveCAID {
		obs.Edges = append(obs.Edges, EdgeReporter{
			EdgeID: id, Up: upByEdge[id], LiveCAID: ca,
			ObservedTarget: observedTarget[id], RefreshedInWindow: refreshed[id], FailedRemints: failed[id],
		})
	}

	// ---- Expected-edge set (edge_registry_total == 1) ----
	reg, err := get("parapet_edge_registry_total == 1")
	if err != nil {
		return Observations{}, err
	}
	for _, s := range reg {
		if id := string(s.Metric["edge_id"]); id != "" {
			obs.ExpectedEdges = append(obs.ExpectedEdges, id)
		}
	}

	return obs, nil
}

// labelByInstance maps instance -> the value of `label` on each sample of `query`.
func labelByInstance(get func(string) (model.Vector, error), query, label string) (map[string]string, error) {
	return labelByLabel(get, query, "instance", label)
}

// labelByLabel maps the `key` label -> the `val` label across the query's samples.
func labelByLabel(get func(string) (model.Vector, error), query, key, val string) (map[string]string, error) {
	vec, err := get(query)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(vec))
	for _, s := range vec {
		if k := string(s.Metric[model.LabelName(key)]); k != "" {
			m[k] = string(s.Metric[model.LabelName(val)])
		}
	}
	return m, nil
}

// valueByInstance maps instance -> the sample value.
func valueByInstance(get func(string) (model.Vector, error), query string) (map[string]float64, error) {
	vec, err := get(query)
	if err != nil {
		return nil, err
	}
	m := make(map[string]float64, len(vec))
	for _, s := range vec {
		if inst := string(s.Metric["instance"]); inst != "" {
			m[inst] = float64(s.Value)
		}
	}
	return m, nil
}

// boolByLabel maps the `key` label -> pred(value) across the query's samples.
func boolByLabel(get func(string) (model.Vector, error), query, key string, pred func(float64) bool) (map[string]bool, error) {
	vec, err := get(query)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(vec))
	for _, s := range vec {
		if k := string(s.Metric[model.LabelName(key)]); k != "" {
			m[k] = pred(float64(s.Value))
		}
	}
	return m, nil
}
