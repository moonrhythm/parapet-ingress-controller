package debounce

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDebounce(t *testing.T) {
	t.Parallel()

	var cnt int
	d := New(func() {
		cnt++
	}, 10*time.Millisecond)
	assert.Equal(t, 0, cnt)
	d.Call() // block
	assert.Equal(t, 1, cnt)
	d.Call() // non-block
	assert.Equal(t, 1, cnt)
	time.Sleep(15 * time.Millisecond)
	assert.Equal(t, 2, cnt)

	d.Call()
	d.Call()
	d.Call()

	time.Sleep(15 * time.Millisecond)
	assert.Equal(t, 3, cnt)
}
