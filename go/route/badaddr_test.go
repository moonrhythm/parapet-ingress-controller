package route

import (
	"testing"
	"time"

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

func TestBadAddrExpiry(t *testing.T) {
	t.Parallel()

	badAddr := badAddrTable{}
	// an entry older than badDuration is no longer bad (backdated to avoid waiting)
	badAddr.addrs.Store("192.168.0.20", time.Now().Add(-2*badDuration))
	assert.False(t, badAddr.IsBad("192.168.0.20"))

	// a fresh entry is bad
	badAddr.addrs.Store("192.168.0.21", time.Now())
	assert.True(t, badAddr.IsBad("192.168.0.21"))
}

func TestBadAddrClearRemovesOnlyExpired(t *testing.T) {
	t.Parallel()

	badAddr := badAddrTable{}
	badAddr.addrs.Store("expired", time.Now().Add(-2*badDuration))
	badAddr.addrs.Store("fresh", time.Now())

	badAddr.Clear()

	_, expiredPresent := badAddr.addrs.Load("expired")
	_, freshPresent := badAddr.addrs.Load("fresh")
	assert.False(t, expiredPresent, "expired entry should be removed")
	assert.True(t, freshPresent, "fresh entry should be kept")
}

func TestBadAddrMarkTransition(t *testing.T) {
	t.Parallel()

	badAddr := badAddrTable{}
	assert.True(t, badAddr.mark("10.0.0.1"), "first mark is a transition")
	assert.False(t, badAddr.mark("10.0.0.1"), "already-bad host is not a transition")

	// once the entry expires, marking again is a fresh transition
	badAddr.addrs.Store("10.0.0.1", time.Now().Add(-2*badDuration))
	assert.True(t, badAddr.mark("10.0.0.1"), "re-mark after expiry is a transition")
}
