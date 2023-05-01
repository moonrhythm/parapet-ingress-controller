package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
