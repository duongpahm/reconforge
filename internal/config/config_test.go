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
	assert.EqualValues(t, 1, cfg.General.CheckpointFreq)
	assert.EqualValues(t, 0, cfg.General.MemoryLimitMB)
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
  checkpoint_freq: 3
  memory_limit_mb: 256
  verbose: true
target:
  scope_file: ./test.scope
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o644))

	cfg, err := Load(cfgPath, nopLogger)
	require.NoError(t, err)
	assert.Equal(t, 8, cfg.General.MaxWorkers)
	assert.EqualValues(t, 3, cfg.General.CheckpointFreq)
	assert.EqualValues(t, 256, cfg.General.MemoryLimitMB)
	assert.True(t, cfg.General.Verbose)
	assert.Equal(t, "./test.scope", cfg.Target.ScopeFile)
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
  checkpoint_freq: 0
  output_dir: ./Recon
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
	assert.Contains(t, err.Error(), "general.checkpoint_freq")
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

func TestBundledProfilesExistAndLoad(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(oldWd)
	}()

	require.NoError(t, os.Chdir(filepath.Join("..", "..")))

	base := &Config{}
	for _, profileName := range []string{ProfileQuick, ProfileStealth, ProfileFull, ProfileDeep} {
		t.Run(profileName, func(t *testing.T) {
			_, err := LoadProfile(profileName, base, nopLogger)
			require.NoError(t, err)
		})
	}
}

func TestLoad_MergesHomeConfigOverDefaults(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(oldWd)
	}()

	oldHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("HOME", oldHome)
	}()

	root := t.TempDir()
	require.NoError(t, os.Chdir(root))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "configs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "configs", "default.yaml"), []byte(`
general:
  output_dir: ./RepoRecon
  max_workers: 4
dns:
  resolver: auto
ratelimit:
  min_rate: 10
  max_rate: 500
export:
  format: all
ai:
  report_profile: bughunter
`), 0o644))

	home := filepath.Join(root, "home")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".reconforge"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".reconforge", "config.yaml"), []byte(`
general:
  output_dir: ./UserRecon
  max_workers: 9
`), 0o644))
	require.NoError(t, os.Setenv("HOME", home))

	cfg, err := Load("", nopLogger)
	require.NoError(t, err)
	assert.Equal(t, "./UserRecon", cfg.General.OutputDir)
	assert.Equal(t, 9, cfg.General.MaxWorkers)
	assert.Equal(t, "auto", cfg.DNS.Resolver)
}

func TestLoad_ResolvesSecretRefs(t *testing.T) {
	t.Setenv("SLACK_HOOK", "https://hooks.slack.test/example")
	t.Setenv("TG_TOKEN", "secret-token")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
export:
  notify:
    slack_webhook: ${SLACK_HOOK}
    telegram_token: ${TG_TOKEN}
`), 0o644))

	cfg, err := Load(cfgPath, nopLogger)
	require.NoError(t, err)
	assert.Equal(t, "https://hooks.slack.test/example", cfg.Export.Notify.SlackWebhook)
	assert.Equal(t, "secret-token", cfg.Export.Notify.TelegramToken)
}

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "", MaskSecret(""))
	assert.Equal(t, "****", MaskSecret("secret"))
}
