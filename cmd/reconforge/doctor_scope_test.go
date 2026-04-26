package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/exitcode"
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

func TestDoctorWarnsOnWorldReadableSecretConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
general:
  output_dir: ./Recon
  max_workers: 4
  checkpoint_freq: 1
dns:
  resolver: auto
ratelimit:
  min_rate: 10
  max_rate: 500
export:
  format: all
  notify:
    slack_webhook: https://hooks.slack.test/secret
ai:
  report_profile: bughunter
`), 0o644))

	oldCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = oldCfgFile })
	cfgFile = cfgPath

	out := captureStdout(t, func() {
		require.NoError(t, doctorCmd.RunE(doctorCmd, nil))
	})

	assert.Contains(t, out, "WARNING: config file contains secrets")
}

func TestActiveConfigPathFindsExplicitConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

	got, ok := activeConfigPath(path)
	require.True(t, ok)
	assert.Equal(t, path, got)
}

func TestActiveConfigPathSearchesDefaults(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldWd) }()

	root := t.TempDir()
	require.NoError(t, os.Chdir(root))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "configs"), 0o755))
	defaultPath := filepath.Join(root, "configs", "default.yaml")
	require.NoError(t, os.WriteFile(defaultPath, []byte(""), 0o600))

	got, ok := activeConfigPath("")
	require.True(t, ok)
	assert.Equal(t, filepath.Join("configs", "default.yaml"), got)
}

var _ = config.MaskSecret
