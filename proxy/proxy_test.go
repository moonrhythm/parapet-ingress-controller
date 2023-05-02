package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	assert.True(t, IsRetryable(errBadGateway))
	assert.True(t, IsRetryable(errServiceUnavailable))
}
