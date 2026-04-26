package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientSupportedAndUnsupported(t *testing.T) {
	client, err := GetClient("hackerone", "token")
	require.NoError(t, err)
	require.NotNil(t, client)

	client, err = GetClient("bc", "token")
	require.NoError(t, err)
	require.NotNil(t, client)

	client, err = GetClient("unknown", "token")
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "unsupported platform")
}

func TestHackerOneClientGetScope(t *testing.T) {
	client := NewHackerOneClient("")
	scope, err := client.GetScope("acme")
	require.Error(t, err)
	assert.Nil(t, scope)
	assert.Contains(t, err.Error(), "H1_TOKEN")

	client = NewHackerOneClient("token")
	scope, err = client.GetScope("acme")
	require.NoError(t, err)
	require.NotNil(t, scope)
	assert.Equal(t, []string{"*.acme.com", "api.acme.com"}, scope.InScope)
	assert.Equal(t, []string{"blog.acme.com"}, scope.OutOfScope)
}

func TestBugcrowdClientGetScope(t *testing.T) {
	client := NewBugcrowdClient("")
	scope, err := client.GetScope("acme")
	require.Error(t, err)
	assert.Nil(t, scope)
	assert.Contains(t, err.Error(), "BUGCROWD_TOKEN")

	client = NewBugcrowdClient("token")
	scope, err = client.GetScope("acme")
	require.NoError(t, err)
	require.NotNil(t, scope)
	assert.Equal(t, []string{"*.acme.net"}, scope.InScope)
	assert.Empty(t, scope.OutOfScope)
}
