package hostlabel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOf(t *testing.T) {
	t.Parallel()
	known := func(h string) bool { return h == "a.example.com" }
	assert.Equal(t, "a.example.com", Of("a.example.com", known))
	assert.Equal(t, Other, Of("evil.example.com", known))
	assert.Equal(t, "x", Of("x", nil), "nil isKnown passes through")
}
