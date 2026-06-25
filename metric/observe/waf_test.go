package observe

import (
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wafEvalSampleCount(t *testing.T, outcome, scope string) uint64 {
	t.Helper()
	h, err := _wafEval.vec.GetMetricWith(prometheus.Labels{"outcome": outcome, "scope": scope})
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, h.(prometheus.Metric).Write(&m))
	return m.GetHistogram().GetSampleCount()
}

func TestWAFEval(t *testing.T) {
	const scope = "waf-eval-test"
	obs := WAFEval(scope)

	obs(waf.EvalEvent{Outcome: waf.OutcomePass, Duration: 40 * time.Microsecond})
	obs(waf.EvalEvent{Outcome: waf.OutcomePass, Duration: 60 * time.Microsecond})
	obs(waf.EvalEvent{Outcome: waf.OutcomeBlock, Duration: time.Millisecond})
	// an outcome outside waf's closed set must be dropped, not panic or
	// mint a series from request-path input
	obs(waf.EvalEvent{Outcome: waf.Outcome(200), Duration: time.Millisecond})

	assert.EqualValues(t, 2, wafEvalSampleCount(t, "pass", scope))
	assert.EqualValues(t, 1, wafEvalSampleCount(t, "block", scope))
	assert.EqualValues(t, 0, wafEvalSampleCount(t, "allow", scope))
	assert.EqualValues(t, 0, wafEvalSampleCount(t, "error", scope))
}

func TestWAFEvalScopesAreDistinct(t *testing.T) {
	global := WAFEval("waf-eval-scope-g")
	zone := WAFEval("waf-eval-scope-z")

	global(waf.EvalEvent{Outcome: waf.OutcomePass, Duration: time.Microsecond})
	zone(waf.EvalEvent{Outcome: waf.OutcomePass, Duration: time.Microsecond})
	zone(waf.EvalEvent{Outcome: waf.OutcomePass, Duration: time.Microsecond})

	assert.EqualValues(t, 1, wafEvalSampleCount(t, "pass", "waf-eval-scope-g"))
	assert.EqualValues(t, 2, wafEvalSampleCount(t, "pass", "waf-eval-scope-z"))
}

func wafMatchCount(t *testing.T, ruleID, action, scope string) float64 {
	t.Helper()
	h, err := _wafMatch.vec.GetMetricWith(prometheus.Labels{"rule_id": ruleID, "action": action, "scope": scope})
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, h.(prometheus.Metric).Write(&m))
	return m.GetCounter().GetValue()
}

func TestWAFMatch(t *testing.T) {
	const scope = "waf-match-test"
	onMatch := WAFMatch(scope)

	onMatch(waf.MatchEvent{RuleID: "1001", Action: waf.ActionBlock})
	onMatch(waf.MatchEvent{RuleID: "1001", Action: waf.ActionBlock})
	onMatch(waf.MatchEvent{RuleID: "1002", Action: waf.ActionLog})

	assert.EqualValues(t, 2, wafMatchCount(t, "1001", waf.ActionBlock.String(), scope))
	assert.EqualValues(t, 1, wafMatchCount(t, "1002", waf.ActionLog.String(), scope))
}

func TestWAFMatchScopesAreDistinct(t *testing.T) {
	global := WAFMatch("waf-match-scope-g")
	zone := WAFMatch("waf-match-scope-z")

	global(waf.MatchEvent{RuleID: "2001", Action: waf.ActionBlock})
	zone(waf.MatchEvent{RuleID: "2001", Action: waf.ActionBlock})
	zone(waf.MatchEvent{RuleID: "2001", Action: waf.ActionBlock})

	assert.EqualValues(t, 1, wafMatchCount(t, "2001", waf.ActionBlock.String(), "waf-match-scope-g"))
	assert.EqualValues(t, 2, wafMatchCount(t, "2001", waf.ActionBlock.String(), "waf-match-scope-z"))
}
