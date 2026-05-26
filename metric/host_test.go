package metric

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpgradeLabel(t *testing.T) {
	// caller passes an already lower-cased, trimmed value
	assert.Equal(t, "", upgradeLabel(""), "no Upgrade header -> normal bucket")
	assert.Equal(t, "websocket", upgradeLabel("websocket"))
	assert.Equal(t, "h2c", upgradeLabel("h2c"))
	// arbitrary client-supplied tokens collapse to one label (cardinality cap)
	assert.Equal(t, "other", upgradeLabel("evil-random-123"))
	assert.Equal(t, "other", upgradeLabel("tls/1.2"))
}
