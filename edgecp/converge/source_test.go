package converge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/common/model"
)

// fakeQuerier returns canned vectors per query (so Snapshot is tested with NO live
// Prometheus). An unmapped query returns an empty vector; queryErr forces an error.
type fakeQuerier struct {
	byQuery  map[string]model.Vector
	queryErr error
}

func (f *fakeQuerier) Query(_ context.Context, q string, _ time.Time) (model.Vector, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.byQuery[q], nil
}

func sample(labels map[string]string, v float64) *model.Sample {
	m := model.Metric{}
	for k, val := range labels {
		m[model.LabelName(k)] = model.LabelValue(val)
	}
	return &model.Sample{Metric: m, Value: model.SampleValue(v)}
}

func TestSnapshotMapsAllPlanes(t *testing.T) {
	const target = "T"
	q := &fakeQuerier{byQuery: map[string]model.Vector{
		"up": {
			sample(map[string]string{"instance": "cp-0"}, 1),
			sample(map[string]string{"instance": "core-0"}, 1),
			sample(map[string]string{"edge_id": "e1"}, 1),
		},
		"parapet_edge_ca_signer_fingerprint":                               {sample(map[string]string{"instance": "cp-0", "ca_id": target}, 1)},
		"parapet_edge_ca_target_ca_id":                                     {sample(map[string]string{"instance": "cp-0", "ca_id": target}, 1)},
		"parapet_edge_ca_signer_generation":                                {sample(map[string]string{"instance": "cp-0", "ca_id": target}, 4242)},
		"parapet_edge_ca_bundle_certs":                                     {sample(map[string]string{"instance": "cp-0", "ca_id": target}, 2)},
		"parapet_edge_authz_generation":                                    {sample(map[string]string{"instance": "cp-0"}, 777)},
		"parapet_trust_bundle_generation":                                  {sample(map[string]string{"instance": "core-0", "ca_id": target}, 4242)},
		"parapet_edge_clientcert_ca_id":                                    {sample(map[string]string{"edge_id": "e1", "ca_id": target}, 1)},
		"parapet_edge_cp_target_ca_id":                                     {sample(map[string]string{"edge_id": "e1", "ca_id": target}, 1)},
		"increase(parapet_edge_refresh_total[5m])":                         {sample(map[string]string{"edge_id": "e1"}, 3)},
		`increase(parapet_edge_clientcert_remint_total{result!="ok"}[5m])`: {sample(map[string]string{"edge_id": "e1"}, 0)},
		"parapet_edge_registry_total == 1":                                 {sample(map[string]string{"edge_id": "e1"}, 1)},
	}}

	obs, err := Snapshot(context.Background(), q, 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.CP) != 1 || obs.CP[0].SignerCAID != target || obs.CP[0].SignerGen != 4242 || obs.CP[0].BundleCerts != 2 || !obs.CP[0].Up || obs.CP[0].AuthzGen != 777 {
		t.Errorf("CP mapping wrong: %+v", obs.CP)
	}
	if len(obs.Core) != 1 || obs.Core[0].HeldCAID != target || !obs.Core[0].Up {
		t.Errorf("core mapping wrong: %+v", obs.Core)
	}
	if len(obs.Edges) != 1 || obs.Edges[0].EdgeID != "e1" || obs.Edges[0].LiveCAID != target || !obs.Edges[0].RefreshedInWindow || obs.Edges[0].FailedRemints || !obs.Edges[0].Up {
		t.Errorf("edge mapping wrong: %+v", obs.Edges)
	}
	if len(obs.ExpectedEdges) != 1 || obs.ExpectedEdges[0] != "e1" {
		t.Errorf("expected-edges wrong: %v", obs.ExpectedEdges)
	}

	// And the mapped snapshot evaluates as converged (end-to-end sanity).
	obs.RevokedProbeRan, obs.RevokedProbeStatus = true, 403
	if r := Evaluate(obs, Config{ExpectedCP: 1, ExpectedCore: 1, MinEdges: 1, Freshness: 5 * time.Minute}, time.Now()); !r.Converged {
		t.Errorf("mapped snapshot should converge; blockers=%v", r.Blockers)
	}
}

// A Prometheus query error must propagate (fail-closed: the caller renders no verdict).
func TestSnapshotPropagatesQueryError(t *testing.T) {
	q := &fakeQuerier{queryErr: errors.New("prometheus unreachable")}
	if _, err := Snapshot(context.Background(), q, 5*time.Minute, time.Now()); err == nil {
		t.Error("a query error must propagate, not be swallowed")
	}
}
