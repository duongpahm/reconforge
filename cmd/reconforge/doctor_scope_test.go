package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reconforge/reconforge/internal/exitcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctorCommandSmoke(t *testing.T) {
	out := captureStdout(t, func() {
		require.NoError(t, doctorCmd.RunE(doctorCmd, nil))
	})

	assert.Contains(t, out, "Running environment checks...")
	assert.Contains(t, out, "Checking required tools...")
	assert.True(
		t,
		strings.Contains(out, "Environment: OK") || strings.Contains(out, "Environment Issues Found:"),
		"doctor output should report environment status",
	)
}

func TestScopeValidateCommand(t *testing.T) {
	scopeFile := filepath.Join(t.TempDir(), "test.scope")
	content := "example.com\n*.acme.test\n!admin.acme.test\n"
	require.NoError(t, os.WriteFile(scopeFile, []byte(content), 0o644))

	out := captureStdout(t, func() {
		require.NoError(t, scopeValidateCmd.RunE(scopeValidateCmd, []string{scopeFile}))
	})

	assert.Contains(t, out, "is valid")
	assert.Contains(t, out, "In-Scope Items:     2")
	assert.Contains(t, out, "Out-of-Scope Items: 1")
}

func TestScopeTestCommandInAndOutOfScope(t *testing.T) {
	scopeFile := filepath.Join(t.TempDir(), "test.scope")
	content := "example.com\n*.acme.test\n!admin.acme.test\n"
	require.NoError(t, os.WriteFile(scopeFile, []byte(content), 0o644))

	out := captureStdout(t, func() {
		require.NoError(t, scopeTestCmd.RunE(scopeTestCmd, []string{scopeFile, "api.acme.test"}))
	})
	assert.Contains(t, out, "IN SCOPE")

	err := scopeTestCmd.RunE(scopeTestCmd, []string{scopeFile, "admin.acme.test"})
	require.Error(t, err)
	assert.Equal(t, exitcode.ScopeInvalid, exitcode.Code(err))
	assert.Contains(t, err.Error(), "out of scope")
}

func TestScopeSyncRequiresFlags(t *testing.T) {
	oldFrom, oldProgram, oldOut := syncFrom, syncProgram, syncOut
	t.Cleanup(func() {
		syncFrom = oldFrom
		syncProgram = oldProgram
		syncOut = oldOut
	})

	syncFrom = ""
	syncProgram = ""
	syncOut = ""

	err := scopeSyncCmd.RunE(scopeSyncCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--from, --program, and -o are required")
}
