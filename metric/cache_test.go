package metric

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheGetOrCreateCachesPerKey(t *testing.T) {
	c := newCache[string, *int](4)

	var calls int
	mk := func(v int) func() *int {
		return func() *int { calls++; n := v; return &n }
	}

	a1 := c.getOrCreate("a", mk(1))
	a2 := c.getOrCreate("a", mk(99)) // create must not run again for "a"
	b := c.getOrCreate("b", mk(2))

	assert.Same(t, a1, a2)
	assert.Equal(t, 1, *a1)
	assert.NotSame(t, a1, b)
	assert.Equal(t, 2, calls, "create runs once per distinct key")
}

func TestCacheGetOrCreateConcurrentSingleCreate(t *testing.T) {
	c := newCache[string, *int](1)

	var creates int32
	var wg sync.WaitGroup
	results := make([]*int, 100)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = c.getOrCreate("k", func() *int {
				atomic.AddInt32(&creates, 1)
				n := 7
				return &n
			})
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&creates), "create must run exactly once under concurrency")
	for i := 1; i < len(results); i++ {
		assert.Same(t, results[0], results[i], "all callers observe the same cached value")
	}
}
