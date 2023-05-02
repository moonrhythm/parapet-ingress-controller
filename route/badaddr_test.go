package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBadAddrTable(t *testing.T) {
	t.Parallel()

	badAddr := badAddrTable{}
	badAddr.MarkBad("192.168.0.10:8080")
	assert.True(t, badAddr.IsBad("192.168.0.10"))
	// clear without expire, should still be bad
	badAddr.Clear()
	assert.True(t, badAddr.IsBad("192.168.0.10"))

	// mark bad without port
	badAddr.MarkBad("192.168.0.11")
	assert.True(t, badAddr.IsBad("192.168.0.11"))

	assert.False(t, badAddr.IsBad("192.168.0.1"))
}
