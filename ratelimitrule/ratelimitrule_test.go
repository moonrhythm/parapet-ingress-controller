package ratelimitrule_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("concatenates documents in order", func(t *testing.T) {
		limits, err := ratelimitrule.Parse(`
limits:
  - id: a
    rate: 1
    window: 1s
`, `
limits:
  - id: b
    rate: 2
    window: 2s
`)
		require.NoError(t, err)
		require.Len(t, limits, 2)
		assert.Equal(t, "a", limits[0].ID)
		assert.Equal(t, "b", limits[1].ID)
	})

	t.Run("empty and whitespace documents are skipped", func(t *testing.T) {
		limits, err := ratelimitrule.Parse("", "   \n\t", `
limits:
  - id: a
    rate: 1
    window: 1s
`)
		require.NoError(t, err)
		require.Len(t, limits, 1)
	})

	t.Run("a broken document errors but others still parse", func(t *testing.T) {
		limits, err := ratelimitrule.Parse(`{not yaml`, `
limits:
  - id: ok
    rate: 1
    window: 1s
`)
		require.Error(t, err)
		// The caller (SetLimits via the controller reload) rejects the whole
		// batch on error; the partial result just mirrors wafrule.Parse.
		require.Len(t, limits, 1)
		assert.Equal(t, "ok", limits[0].ID)
	})

	t.Run("all fields map", func(t *testing.T) {
		limits, err := ratelimitrule.Parse(`
limits:
  - id: per-ip
    key: ip-host
    rate: 100
    window: 1m
    algorithm: sliding
    mode: shadow
    status: 503
    message: slow down
    exclude:
      - 10.0.0.0/8
      - 192.168.0.0/16
`)
		require.NoError(t, err)
		require.Len(t, limits, 1)
		l := limits[0]
		assert.Equal(t, "per-ip", l.ID)
		assert.Equal(t, ratelimitrule.Keys{"ip-host"}, l.Key)
		assert.Equal(t, 100, l.Rate)
		assert.Equal(t, "1m", l.Window)
		assert.Equal(t, "sliding", l.Algorithm)
		assert.Equal(t, "shadow", l.Mode)
		assert.Equal(t, 503, l.Status)
		assert.Equal(t, "slow down", l.Message)
		assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, l.Exclude)
	})
}

func TestParse_KeyForms(t *testing.T) {
	t.Parallel()

	limits, err := ratelimitrule.Parse(`
limits:
  - id: scalar
    rate: 1
    window: 1s
    key: asn
  - id: list
    rate: 1
    window: 1s
    key: [ip, header:x-api-key, country]
  - id: defaulted
    rate: 1
    window: 1s
`)
	require.NoError(t, err)
	require.Len(t, limits, 3)
	assert.Equal(t, ratelimitrule.Keys{"asn"}, limits[0].Key)
	assert.Equal(t, ratelimitrule.Keys{"ip", "header:x-api-key", "country"}, limits[1].Key)
	assert.Nil(t, limits[2].Key, "absent key stays nil until SetLimits defaults it")

	_, err = ratelimitrule.Parse(`
limits:
  - id: bad
    rate: 1
    window: 1s
    key: {ip: true}
`)
	assert.Error(t, err, "a mapping is neither a scalar nor a list")
}

func TestParse_EmptyScalarKeyDefaultsToIP(t *testing.T) {
	t.Parallel()

	// The pre-list schema accepted an explicit empty key as the ip default
	// (plausible from templating like `key: {{ .Values.key | default "" }}`);
	// the list schema must keep that spelling working — a rejection would
	// fail the whole batch all-or-nothing.
	for _, doc := range []string{
		"limits:\n  - id: a\n    rate: 1\n    window: 1m\n    key: \"\"\n",
		"limits:\n  - id: a\n    rate: 1\n    window: 1m\n    key:\n",
		"limits:\n  - id: a\n    rate: 1\n    window: 1m\n    key: []\n",
	} {
		limits, err := ratelimitrule.Parse(doc)
		require.NoError(t, err, "doc: %q", doc)
		require.Len(t, limits, 1)

		l := &ratelimitrule.Limiter{}
		require.NoError(t, l.SetLimits(limits), "doc: %q", doc)
		assert.Equal(t, ratelimitrule.Keys{"ip"}, l.Limits()[0].Key, "doc: %q", doc)
	}
}
