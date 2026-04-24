package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var nopLogger = zerolog.Nop()

func TestLoad_Defaults(t *testing.T) {
	// No config file → should load defaults successfully
	cfg, err := Load("", nopLogger)
	require.NoError(t, err)
	assert.Equal(t, 4, cfg.General.MaxWorkers)
	assert.Equal(t, "virtualbox", cfg.VM.Provider)
	assert.Equal(t, "kali-reconforge", cfg.VM.Name)
	assert.Equal(t, 50, cfg.VM.DiskGB)
	assert.Equal(t, "kali-rolling", cfg.VM.Image)
	assert.Equal(t, "auto", cfg.DNS.Resolver)
	assert.Equal(t, "all", cfg.Export.Format)
	assert.Equal(t, "bughunter", cfg.AI.ReportProfile)
	assert.True(t, cfg.Web.PortScan)
	assert.True(t, cfg.Web.URLChecks)
	assert.True(t, cfg.Web.URLGF)
}

func TestLoad_FromFile(t *testing.T) {
	yaml := `
general:
  max_workers: 8
  verbose: true
vm:
  provider: qemu
  memory: 8192
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o644))

	cfg, err := Load(cfgPath, nopLogger)
	require.NoError(t, err)
	assert.Equal(t, 8, cfg.General.MaxWorkers)
	assert.True(t, cfg.General.Verbose)
	assert.Equal(t, "qemu", cfg.VM.Provider)
	assert.Equal(t, 8192, cfg.VM.Memory)
}

func TestLoad_InvalidFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml", nopLogger)
	assert.Error(t, err)
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("general: [invalid yaml {{"), 0o644))

	_, err := Load(cfgPath, nopLogger)
	assert.Error(t, err)
}

func TestLoad_ValidationFails(t *testing.T) {
	yaml := `
general:
  max_workers: 200
  output_dir: ./Recon
vm:
  provider: virtualbox
  memory: 4096
  cpus: 2
  ssh_port: 2222
dns:
  resolver: auto
ratelimit:
  min_rate: 10
  max_rate: 500
export:
  format: all
ai:
  report_profile: bughunter
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o644))

	_, err := Load(cfgPath, nopLogger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config validation")
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	result := expandHome("~/Tools")
	assert.Equal(t, filepath.Join(home, "Tools"), result)

	result = expandHome("/absolute/path")
	assert.Equal(t, "/absolute/path", result)

	result = expandHome("relative/path")
	assert.Equal(t, "relative/path", result)

	result = expandHome("~")
	assert.Equal(t, "~", result) // no trailing slash → not expanded
}

func TestLoad_ExpandsHomePaths(t *testing.T) {
	cfg, err := Load("", nopLogger)
	require.NoError(t, err)

	home, _ := os.UserHomeDir()
	assert.True(t, strings.HasPrefix(cfg.General.ToolsDir, home), "ToolsDir should expand ~")
}

func TestListProfiles(t *testing.T) {
	profiles := ListProfiles()
	assert.Contains(t, profiles, ProfileQuick)
	assert.Contains(t, profiles, ProfileFull)
	assert.Contains(t, profiles, ProfileStealth)
	assert.Contains(t, profiles, ProfileDeep)
}

func TestLoadProfile_EmptyName(t *testing.T) {
	cfg := &Config{General: GeneralConfig{MaxWorkers: 4, OutputDir: "./Recon"}}
	result, err := LoadProfile("", cfg, nopLogger)
	require.NoError(t, err)
	assert.Equal(t, cfg, result)
}

func TestLoadProfile_NotFound(t *testing.T) {
	cfg := &Config{}
	_, err := LoadProfile("nonexistent-profile", cfg, nopLogger)
	assert.Error(t, err)
}
