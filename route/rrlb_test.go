package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRRLB(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		lb := &RRLB{}
		assert.Equal(t, "", lb.Get(nil))
		assert.Equal(t, "", lb.Get(nil))
		assert.Equal(t, "", lb.Get(nil))
	})

	t.Run("Single", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
			},
		}
		assert.Equal(t, "192.168.1.1", lb.Get(nil))
		assert.Equal(t, "192.168.1.1", lb.Get(nil))
		assert.Equal(t, "192.168.1.1", lb.Get(nil))
	})

	t.Run("All Healthy", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
				"192.168.1.2",
				"192.168.1.3",
			},
		}
		assert.Equal(t, "192.168.1.2", lb.Get(nil))
		assert.Equal(t, "192.168.1.3", lb.Get(nil))
		assert.Equal(t, "192.168.1.1", lb.Get(nil))
		assert.Equal(t, "192.168.1.2", lb.Get(nil))
	})

	t.Run("One Bad", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
				"192.168.1.2",
				"192.168.1.3",
			},
		}
		badAddr := badAddrTable{}
		badAddr.MarkBad("192.168.1.3")
		assert.Equal(t, "192.168.1.2", lb.Get(&badAddr))
		assert.Equal(t, "192.168.1.1", lb.Get(&badAddr)) // 3 is bad so 1 is returned
		assert.Equal(t, "192.168.1.1", lb.Get(&badAddr)) // next of 3 is 1
		assert.Equal(t, "192.168.1.2", lb.Get(&badAddr))
	})

	t.Run("All Bad", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
				"192.168.1.2",
				"192.168.1.3",
			},
		}
		badAddr := badAddrTable{}
		badAddr.MarkBad("192.168.1.1")
		badAddr.MarkBad("192.168.1.2")
		badAddr.MarkBad("192.168.1.3")
		assert.Equal(t, "192.168.1.2", lb.Get(&badAddr))
		assert.Equal(t, "192.168.1.3", lb.Get(&badAddr))
		assert.Equal(t, "192.168.1.1", lb.Get(&badAddr))
		assert.Equal(t, "192.168.1.2", lb.Get(&badAddr))
	})
}
