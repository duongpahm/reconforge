package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSHAddress(t *testing.T) {
	assert.Equal(t, "127.0.0.1:22", sshAddress("127.0.0.1", 22))
	assert.Equal(t, "[2001:db8::1]:2222", sshAddress("2001:db8::1", 2222))
}
