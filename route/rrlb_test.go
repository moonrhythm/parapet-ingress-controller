package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRRLB(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		lb := &RRLB{}
		assert.Equal(t, "", nextIP(lb, nil))
		assert.Equal(t, "", nextIP(lb, nil))
		assert.Equal(t, "", nextIP(lb, nil))
	})

	t.Run("Single", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
			},
		}
		assert.Equal(t, "192.168.1.1", nextIP(lb, nil))
		assert.Equal(t, "192.168.1.1", nextIP(lb, nil))
		assert.Equal(t, "192.168.1.1", nextIP(lb, nil))
	})

	t.Run("All Healthy", func(t *testing.T) {
		lb := &RRLB{
			IPs: []string{
				"192.168.1.1",
				"192.168.1.2",
				"192.168.1.3",
			},
		}
		assert.Equal(t, "192.168.1.2", nextIP(lb, nil))
		assert.Equal(t, "192.168.1.3", nextIP(lb, nil))
		assert.Equal(t, "192.168.1.1", nextIP(lb, nil))
		assert.Equal(t, "192.168.1.2", nextIP(lb, nil))
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
		assert.Equal(t, "192.168.1.2", nextIP(lb, &badAddr))
		assert.Equal(t, "192.168.1.1", nextIP(lb, &badAddr)) // 3 is bad so 1 is returned
		assert.Equal(t, "192.168.1.1", nextIP(lb, &badAddr)) // next of 3 is 1
		assert.Equal(t, "192.168.1.2", nextIP(lb, &badAddr))
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
		assert.Equal(t, "192.168.1.2", nextIP(lb, &badAddr))
		assert.Equal(t, "192.168.1.3", nextIP(lb, &badAddr))
		assert.Equal(t, "192.168.1.1", nextIP(lb, &badAddr))
		assert.Equal(t, "192.168.1.2", nextIP(lb, &badAddr))
	})
}
