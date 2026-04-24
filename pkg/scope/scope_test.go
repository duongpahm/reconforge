package scope

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScope_NoScopeDefined(t *testing.T) {
	s := &Scope{}
	assert.True(t, s.IsInScope("anything.com"))
}

func TestScope_InScopeExact(t *testing.T) {
	s := &Scope{
		InScope: []string{"example.com", "test.com"},
	}

	assert.True(t, s.IsInScope("example.com"))
	assert.True(t, s.IsInScope("sub.example.com"))
	assert.False(t, s.IsInScope("other.com"))
}

func TestScope_InScopeWildcard(t *testing.T) {
	s := &Scope{
		InScope: []string{"*.example.com"},
	}

	assert.True(t, s.IsInScope("sub.example.com"))
	assert.True(t, s.IsInScope("deep.sub.example.com"))
	assert.False(t, s.IsInScope("example.com")) // wildcard doesn't match root
}

func TestScope_OutOfScope(t *testing.T) {
	s := &Scope{
		InScope:    []string{"example.com"},
		OutOfScope: []string{"admin.example.com"},
	}

	assert.True(t, s.IsInScope("sub.example.com"))
	assert.False(t, s.IsInScope("admin.example.com"))
}

func TestScope_OutOfScopeTakesPrecedence(t *testing.T) {
	s := &Scope{
		InScope:    []string{"*.example.com"},
		OutOfScope: []string{"*.internal.example.com"},
	}

	assert.True(t, s.IsInScope("public.example.com"))
	assert.False(t, s.IsInScope("secret.internal.example.com"))
}

func TestScope_FromFiles(t *testing.T) {
	dir := t.TempDir()

	// Write in-scope file
	inFile := filepath.Join(dir, "in-scope.txt")
	os.WriteFile(inFile, []byte("example.com\n*.test.com\n# comment\n"), 0o644)

	// Write out-of-scope file
	outFile := filepath.Join(dir, "out-scope.txt")
	os.WriteFile(outFile, []byte("admin.example.com\n"), 0o644)

	s, err := NewScope(inFile, outFile)
	require.NoError(t, err)

	assert.True(t, s.IsInScope("sub.example.com"))
	assert.True(t, s.IsInScope("sub.test.com"))
	assert.False(t, s.IsInScope("admin.example.com"))
	assert.False(t, s.IsInScope("other.com"))
}

func TestCheckSensitive(t *testing.T) {
	assert.True(t, CheckSensitive("agency.gov"))
	assert.True(t, CheckSensitive("base.mil"))
	assert.False(t, CheckSensitive("example.com"))
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		expect  bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", "example.com", true},
		{"sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"sub.example.com", ".example.com", true},
		{"example.com", ".example.com", true},
		{"other.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain+"_"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.expect, matchesPattern(tt.domain, tt.pattern))
		})
	}
}
