package types

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDomain_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"sub.example.com", "sub.example.com"},
		{"deep.sub.example.com", "deep.sub.example.com"},
		{"example.com.", "example.com"}, // trailing dot
		{"  example.com  ", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"a-b.example.com", "a-b.example.com"},
		{"x1.example.com", "x1.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := NewDomain(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, d.String())
		})
	}
}

func TestNewDomain_Invalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"", "empty"},
		{"   ", "whitespace only"},
		{"-example.com", "starts with hyphen"},
		{"example-.com", "ends with hyphen"},
		{".example.com", "starts with dot"},
		{"example..com", "double dot"},
		{"example", "no TLD"},
		{"example.c", "TLD too short"},
		{"http://example.com", "has scheme"},
		{strings.Repeat("a", 64) + ".com", "label too long"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := NewDomain(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestDomain_TLD(t *testing.T) {
	d, err := NewDomain("sub.example.com")
	require.NoError(t, err)
	assert.Equal(t, "com", d.TLD())
}

func TestDomain_Root(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := NewDomain(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, d.Root())
		})
	}
}

func TestDomain_Depth(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"example.com", 0},
		{"sub.example.com", 1},
		{"deep.sub.example.com", 2},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := NewDomain(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, d.Depth())
		})
	}
}

func TestDomain_IsSubdomainOf(t *testing.T) {
	parent, _ := NewDomain("example.com")
	child, _ := NewDomain("sub.example.com")
	other, _ := NewDomain("other.com")

	assert.True(t, child.IsSubdomainOf(parent))
	assert.False(t, parent.IsSubdomainOf(child))
	assert.False(t, child.IsSubdomainOf(other))
}

func TestDomain_IsSensitive(t *testing.T) {
	gov, _ := NewDomain("agency.gov")
	mil, _ := NewDomain("base.mil")
	edu, _ := NewDomain("university.edu")
	com, _ := NewDomain("example.com")

	assert.True(t, gov.IsSensitiveDomain())
	assert.True(t, mil.IsSensitiveDomain())
	assert.True(t, edu.IsSensitiveDomain())
	assert.False(t, com.IsSensitiveDomain())
}

func TestIsWildcard(t *testing.T) {
	assert.True(t, IsWildcard("*.example.com"))
	assert.True(t, IsWildcard("*.sub.example.com"))
	assert.False(t, IsWildcard("example.com"))
	assert.False(t, IsWildcard("*example.com"))
}

func TestValidateDomain(t *testing.T) {
	assert.NoError(t, ValidateDomain("valid.example.com"))
	assert.Error(t, ValidateDomain("exam ple.com"))
}
