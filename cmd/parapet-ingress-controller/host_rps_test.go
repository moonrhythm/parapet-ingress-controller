package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostRPS_EnvOff(t *testing.T) {
	t.Setenv("HOST_RPS", "")
	assert.Nil(t, hostRPS(nil))

	t.Setenv("HOST_RPS", "0")
	assert.Nil(t, hostRPS(nil))

	t.Setenv("HOST_RPS", "-3")
	assert.Nil(t, hostRPS(nil))
}

func TestHostRPS_EnvOn(t *testing.T) {
	t.Setenv("HOST_RPS", "10")
	assert.NotNil(t, hostRPS(nil))
}
