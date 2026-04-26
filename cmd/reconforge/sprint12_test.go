package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/reconforge/reconforge/internal/exitcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteInitConfigCreatesExpectedDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	require.NoError(t, writeInitConfig(configPath, "./Recon", "quick", "none"))

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "output_dir: ./Recon")
	assert.Contains(t, string(data), "default_profile: quick")
	assert.Contains(t, string(data), "channel: none")

	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestExitCodeMapping(t *testing.T) {
	assert.Equal(t, exitcode.ConfigInvalid, exitcode.Code(exitcode.Config(assert.AnError)))
	assert.Equal(t, exitcode.ScopeInvalid, exitcode.Code(exitcode.Scope(assert.AnError)))
	assert.Equal(t, exitcode.UsageError, exitcode.Code(exitcode.Usage(assert.AnError)))
	assert.Equal(t, exitcode.ScanFailed, exitcode.Code(assert.AnError))
}

func TestCompletionCommandIncludesShells(t *testing.T) {
	shells := completionCmd.ValidArgs
	assert.Contains(t, shells, "bash")
	assert.Contains(t, shells, "zsh")
	assert.Contains(t, shells, "fish")
	assert.Contains(t, shells, "powershell")
}

func TestScanCommandHasSkipMissingToolsFlag(t *testing.T) {
	flag := scanCmd.Flags().Lookup("skip-missing-tools")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}
