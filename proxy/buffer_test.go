package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuffer(t *testing.T) {
	t.Parallel()

	p := newBufferPool()

	assert.NotPanics(t, func() {
		b := p.Get()
		defer p.Put(b)
		assert.NotZero(t, len(b))
		assert.NotZero(t, cap(b))
	})
}
