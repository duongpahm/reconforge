package runner

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDryRunner_IsInstalled(t *testing.T) {
	r := NewDryRunner(zerolog.Nop())

	assert.True(t, r.IsInstalled("ls"))
	assert.False(t, r.IsInstalled("nonexistent_xyz_123"))
}
