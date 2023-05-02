package debounce

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDebounce(t *testing.T) {
	t.Parallel()

	var cnt int64
	d := New(func() {
		atomic.AddInt64(&cnt, 1)
	}, 10*time.Millisecond)

	eq := func(v int64) {
		p := atomic.LoadInt64(&cnt)
		assert.Equal(t, v, p)
	}
	eq(0)
	d.Call() // block
	eq(1)
	d.Call() // non-block
	eq(1)
	time.Sleep(15 * time.Millisecond)
	eq(2)

	d.Call()
	d.Call()
	d.Call()

	time.Sleep(15 * time.Millisecond)
	eq(3)
}
