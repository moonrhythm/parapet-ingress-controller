package metric

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostLabel(t *testing.T) {
	known := func(h string) bool { return h == "a.example.com" }
	assert.Equal(t, "a.example.com", HostLabel("a.example.com", known), "known host kept")
	assert.Equal(t, "other", HostLabel("evil.example.com", known), "unknown host collapses")
	assert.Equal(t, "x", HostLabel("x", nil), "nil isKnownHost passes through")
}

func TestRejectReason(t *testing.T) {
	assert.Equal(t, "no_route", rejectReason(404))
	assert.Equal(t, "forbidden", rejectReason(403))
	assert.Equal(t, "unauthorized", rejectReason(401))
	assert.Equal(t, "body_limit", rejectReason(413))
	assert.Equal(t, "rate_limit", rejectReason(429))
	assert.Equal(t, "", rejectReason(200), "success is not a rejection")
	assert.Equal(t, "", rejectReason(502), "a backend error is not a tracked edge reason")
}

func TestEdgeRejectReason(t *testing.T) {
	// not reached + tracked status => the edge rejected it
	assert.Equal(t, "no_route", edgeRejectReason(false, 404))
	assert.Equal(t, "rate_limit", edgeRejectReason(false, 429))
	// reached a backend => the status is the backend's, never an edge rejection
	assert.Equal(t, "", edgeRejectReason(true, 404))
	assert.Equal(t, "", edgeRejectReason(true, 429))
	// not reached but not a tracked status (success / backend-style error)
	assert.Equal(t, "", edgeRejectReason(false, 200))
}
