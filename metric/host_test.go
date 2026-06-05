package metric

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKindLabel(t *testing.T) {
	mk := func(upgrade, accept string) http.Header {
		h := http.Header{}
		if upgrade != "" {
			h.Set("Upgrade", upgrade)
		}
		if accept != "" {
			h.Set("Accept", accept)
		}
		return h
	}

	// plain HTTP -> "http" bucket
	assert.Equal(t, "http", kindLabel(mk("", "")))
	assert.Equal(t, "http", kindLabel(mk("", "text/html,application/json")))

	// Upgrade header (case-insensitive / padded) maps to its known token
	assert.Equal(t, "websocket", kindLabel(mk("websocket", "")))
	assert.Equal(t, "websocket", kindLabel(mk("  WebSocket ", "")))
	assert.Equal(t, "h2c", kindLabel(mk("h2c", "")))
	// arbitrary client-supplied Upgrade tokens collapse to one label (card. cap)
	assert.Equal(t, "other", kindLabel(mk("evil-random-123", "")))
	assert.Equal(t, "other", kindLabel(mk("tls/1.2", "")))

	// no Upgrade + Accept: text/event-stream -> sse (what EventSource sends),
	// including among other types and with q-values / casing
	assert.Equal(t, "sse", kindLabel(mk("", "text/event-stream")))
	assert.Equal(t, "sse", kindLabel(mk("", "text/event-stream, */*")))
	assert.Equal(t, "sse", kindLabel(mk("", "Text/Event-Stream;q=0.9")))

	// Upgrade wins over Accept: an upgrade request is never scored as sse
	assert.Equal(t, "websocket", kindLabel(mk("websocket", "text/event-stream")))
}
