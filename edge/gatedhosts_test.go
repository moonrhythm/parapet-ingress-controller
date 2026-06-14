package edge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEdgeGatedHosts_Empty(t *testing.T) {
	h := NewEdgeGatedHosts()
	assert.False(t, h.IsGatedHost("acme.com"))
	assert.Equal(t, "", h.Etag())
	assert.EqualValues(t, 0, h.Generation())
}

func TestEdgeGatedHosts_Update(t *testing.T) {
	h := NewEdgeGatedHosts()
	h.Update(5, []string{"acme.com", "app.acme.com"}, `"g1"`)

	assert.True(t, h.IsGatedHost("acme.com"))
	assert.True(t, h.IsGatedHost("app.acme.com"))
	assert.False(t, h.IsGatedHost("public.com"), "an un-gated host is not bypassed")
	assert.Equal(t, `"g1"`, h.Etag())
	assert.EqualValues(t, 5, h.Generation())

	// A later update swaps the set wholesale.
	h.Update(6, []string{"new.com"}, `"g2"`)
	assert.True(t, h.IsGatedHost("new.com"))
	assert.False(t, h.IsGatedHost("acme.com"), "a no-longer-gated host stops bypassing")
	assert.EqualValues(t, 6, h.Generation())
}
