package runner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")

	SetProxyEnv("http://127.0.0.1:8080")

	assert.Equal(t, "http://127.0.0.1:8080", os.Getenv("HTTP_PROXY"))
	assert.Equal(t, "http://127.0.0.1:8080", os.Getenv("HTTPS_PROXY"))
	assert.Equal(t, "http://127.0.0.1:8080", os.Getenv("http_proxy"))
	assert.Equal(t, "http://127.0.0.1:8080", os.Getenv("https_proxy"))
}
