package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewURL_Valid(t *testing.T) {
	tests := []struct {
		input  string
		host   string
		scheme string
	}{
		{"https://example.com", "example.com", "https"},
		{"http://example.com", "example.com", "http"},
		{"https://example.com:8080/path", "example.com", "https"},
		{"https://sub.example.com/path?q=1", "sub.example.com", "https"},
		{"example.com", "example.com", "https"}, // auto-add scheme
		{"example.com:8080", "example.com", "https"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			u, err := NewURL(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.host, u.Host())
			assert.Equal(t, tt.scheme, u.Scheme())
		})
	}
}

func TestNewURL_Invalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"", "empty"},
		{"   ", "whitespace"},
		{"ftp://example.com", "unsupported scheme"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := NewURL(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestURL_Port(t *testing.T) {
	u, _ := NewURL("https://example.com:8443/path")
	assert.Equal(t, "8443", u.Port())

	u2, _ := NewURL("https://example.com/path")
	assert.Equal(t, "", u2.Port())
}

func TestURL_Path(t *testing.T) {
	u, _ := NewURL("https://example.com/api/v1")
	assert.Equal(t, "/api/v1", u.Path())
}

func TestURL_Query(t *testing.T) {
	u, _ := NewURL("https://example.com/search?q=test&page=1")
	assert.Equal(t, "q=test&page=1", u.Query())
}

func TestURL_IsHTTPS(t *testing.T) {
	https, _ := NewURL("https://example.com")
	http, _ := NewURL("http://example.com")

	assert.True(t, https.IsHTTPS())
	assert.False(t, http.IsHTTPS())
}

func TestURL_Domain(t *testing.T) {
	u, _ := NewURL("https://sub.example.com/path")
	d, err := u.Domain()
	require.NoError(t, err)
	assert.Equal(t, "sub.example.com", d.String())
}

func TestURL_BaseURL(t *testing.T) {
	u, _ := NewURL("https://example.com:8080/path?q=1")
	assert.Equal(t, "https://example.com:8080", u.BaseURL())
}
