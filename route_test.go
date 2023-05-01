package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRRLB(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		lb := &rrlb{}
		assert.Equal(t, "", lb.Get())
		assert.Equal(t, "", lb.Get())
		assert.Equal(t, "", lb.Get())
	})

	t.Run("Single", func(t *testing.T) {
		lb := &rrlb{
			IPs: []string{
				"192.168.1.1",
			},
		}
		assert.Equal(t, "192.168.1.1", lb.Get())
		assert.Equal(t, "192.168.1.1", lb.Get())
		assert.Equal(t, "192.168.1.1", lb.Get())
	})

	t.Run("All Healthy", func(t *testing.T) {
		lb := &rrlb{
			IPs: []string{
				"192.168.1.1",
				"192.168.1.2",
				"192.168.1.3",
			},
		}
		assert.Equal(t, "192.168.1.2", lb.Get())
		assert.Equal(t, "192.168.1.3", lb.Get())
		assert.Equal(t, "192.168.1.1", lb.Get())
		assert.Equal(t, "192.168.1.2", lb.Get())
	})

	t.Run("One Bad", func(t *testing.T) {
		lb := &rrlb{
			IPs: []string{
				"192.168.2.1",
				"192.168.2.2",
				"192.168.2.3",
			},
		}
		globalBadAddrTable.MarkBad("192.168.2.3")
		assert.Equal(t, "192.168.2.2", lb.Get())
		assert.Equal(t, "192.168.2.1", lb.Get()) // 3 is bad so 1 is returned
		assert.Equal(t, "192.168.2.1", lb.Get()) // next of 3 is 1
		assert.Equal(t, "192.168.2.2", lb.Get())
	})

	t.Run("All Bad", func(t *testing.T) {
		lb := &rrlb{
			IPs: []string{
				"192.168.3.1",
				"192.168.3.2",
				"192.168.3.3",
			},
		}
		globalBadAddrTable.MarkBad("192.168.3.1")
		globalBadAddrTable.MarkBad("192.168.3.2")
		globalBadAddrTable.MarkBad("192.168.3.3")
		assert.Equal(t, "192.168.3.2", lb.Get())
		assert.Equal(t, "192.168.3.3", lb.Get())
		assert.Equal(t, "192.168.3.1", lb.Get())
		assert.Equal(t, "192.168.3.2", lb.Get())
	})
}

func TestBadAddrTable(t *testing.T) {
	t.Parallel()

	globalBadAddrTable.MarkBad("192.168.0.10:8080")
	assert.True(t, globalBadAddrTable.IsBad("192.168.0.10"))
	// clear without expire, should still be bad
	globalBadAddrTable.Clear()
	assert.True(t, globalBadAddrTable.IsBad("192.168.0.10"))

	// mark bad without port
	globalBadAddrTable.MarkBad("192.168.0.11")
	assert.True(t, globalBadAddrTable.IsBad("192.168.0.11"))

	assert.False(t, globalBadAddrTable.IsBad("192.168.0.1"))
}
