package edge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEdgeHosts_Empty(t *testing.T) {
	h := NewEdgeHosts()
	assert.False(t, h.IsKnownHost("acme.com"))
	assert.Equal(t, "", h.Etag())
	assert.EqualValues(t, 0, h.Generation())
}

func TestEdgeHosts_Update(t *testing.T) {
	h := NewEdgeHosts()
	h.Update(5, []string{"acme.com", "app.acme.com"}, `"h1"`)

	assert.True(t, h.IsKnownHost("acme.com"))
	assert.True(t, h.IsKnownHost("app.acme.com"))
	assert.False(t, h.IsKnownHost("evil.com"), "undeclared host is unknown (collapses to \"other\")")
	assert.False(t, h.IsKnownHost("other.acme.com"), "a wildcard cert subdomain is NOT known unless an Ingress declares it")
	assert.Equal(t, `"h1"`, h.Etag())
	assert.EqualValues(t, 5, h.Generation())

	// A later update swaps the set wholesale.
	h.Update(6, []string{"new.com"}, `"h2"`)
	assert.True(t, h.IsKnownHost("new.com"))
	assert.False(t, h.IsKnownHost("acme.com"), "removed host is no longer known")
	assert.EqualValues(t, 6, h.Generation())
}
