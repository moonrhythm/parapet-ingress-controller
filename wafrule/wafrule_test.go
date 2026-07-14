package wafrule_test

import (
	"testing"

	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/wafrule"
)

func TestParseAction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want waf.Action
		err  bool
	}{
		{"", waf.ActionLog, false},
		{"log", waf.ActionLog, false},
		{"LOG", waf.ActionLog, false},
		{" allow ", waf.ActionAllow, false},
		{"block", waf.ActionBlock, false},
		{"deny", 0, true},
	}
	for _, tc := range cases {
		got, err := wafrule.ParseAction(tc.in)
		if tc.err {
			assert.Error(t, err, "in=%q", tc.in)
			continue
		}
		require.NoError(t, err, "in=%q", tc.in)
		assert.Equal(t, tc.want, got, "in=%q", tc.in)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("single document", func(t *testing.T) {
		rules, err := wafrule.Parse(`
rules:
  - id: block-admin
    description: block admin paths
    expression: request.path.startsWith("/admin")
    action: block
    status: 401
    message: nope
    priority: 5
`)
		require.NoError(t, err)
		require.Len(t, rules, 1)
		assert.Equal(t, "block-admin", rules[0].ID)
		assert.Equal(t, waf.ActionBlock, rules[0].Action)
		assert.Equal(t, 401, rules[0].Status)
		assert.Equal(t, "nope", rules[0].Message)
		assert.Equal(t, 5, rules[0].Priority)
	})

	t.Run("concatenates multiple documents", func(t *testing.T) {
		rules, err := wafrule.Parse(
			"rules:\n  - id: a\n    expression: \"true\"\n    action: log",
			"rules:\n  - id: b\n    expression: \"false\"\n    action: block",
		)
		require.NoError(t, err)
		require.Len(t, rules, 2)
		assert.Equal(t, "a", rules[0].ID)
		assert.Equal(t, waf.ActionLog, rules[0].Action)
		assert.Equal(t, "b", rules[1].ID)
		assert.Equal(t, waf.ActionBlock, rules[1].Action)
	})

	t.Run("empty action defaults to log", func(t *testing.T) {
		rules, err := wafrule.Parse("rules:\n  - id: a\n    expression: \"true\"")
		require.NoError(t, err)
		require.Len(t, rules, 1)
		assert.Equal(t, waf.ActionLog, rules[0].Action)
	})

	t.Run("blank documents skipped", func(t *testing.T) {
		rules, err := wafrule.Parse("", "   \n", "rules:\n  - id: a\n    expression: \"true\"")
		require.NoError(t, err)
		assert.Len(t, rules, 1)
	})

	t.Run("bad action reported", func(t *testing.T) {
		_, err := wafrule.Parse("rules:\n  - id: a\n    expression: \"true\"\n    action: nuke")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown action")
	})

	t.Run("invalid yaml reported", func(t *testing.T) {
		_, err := wafrule.Parse("rules: [ this is : not : valid")
		require.Error(t, err)
	})

	t.Run("wrong root key yields zero rules and errors", func(t *testing.T) {
		// A rate-limit "limits:" document that landed in a WAF ConfigMap unmarshals
		// to zero rules with no YAML error; without the zero-rules guard it would
		// wipe the last-good ruleset. It must error so SetRules keeps the previous
		// rules, and the good doc alongside it still parses (per-doc collection).
		rules, err := wafrule.Parse(
			"limits:\n  - id: a\n    rate: 1\n    window: 1s",
			"rules:\n  - id: ok\n    expression: \"true\"",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no rules")
		require.Len(t, rules, 1)
		assert.Equal(t, "ok", rules[0].ID)
	})

	t.Run("whitespace-only docs stay skipped (no error)", func(t *testing.T) {
		rules, err := wafrule.Parse("", "   \n\t")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("rules feed waf.SetRules", func(t *testing.T) {
		rules, err := wafrule.Parse(`
rules:
  - id: r1
    expression: request.method == "GET"
    action: block
`)
		require.NoError(t, err)
		w := waf.New()
		require.NoError(t, w.SetRules(rules))
		assert.Equal(t, []string{"r1"}, w.Rules())
	})
}
