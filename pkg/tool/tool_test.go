package tool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryRegisterGetAndByPhase(t *testing.T) {
	r := NewRegistry()

	require.Error(t, r.Register(&Tool{}))
	require.NoError(t, r.Register(&Tool{Name: "subfinder", Binary: "subfinder", Phase: "subdomain"}))
	require.Error(t, r.Register(&Tool{Name: "subfinder", Binary: "subfinder"}))

	tool, ok := r.Get("subfinder")
	require.True(t, ok)
	assert.Equal(t, "subfinder", tool.Name)

	phaseTools := r.ByPhase("subdomain")
	require.Len(t, phaseTools, 1)
	assert.Equal(t, "subfinder", phaseTools[0].Name)
}

func TestRegistryHealthCheckAndCheckAll(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\necho v1.2.3\n"), 0o755))
	t.Setenv("PATH", dir)

	r := NewRegistry()
	require.NoError(t, r.Register(&Tool{
		Name:        "mytool",
		Binary:      "mytool",
		Phase:       "web",
		Required:    true,
		HealthCheck: "mytool",
	}))
	require.NoError(t, r.Register(&Tool{
		Name:     "missingtool",
		Binary:   "missingtool",
		Phase:    "web",
		Required: false,
	}))

	version, err := r.HealthCheck(context.Background(), "mytool")
	require.NoError(t, err)
	assert.Equal(t, "v1.2.3", version)

	_, err = r.HealthCheck(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	status := r.CheckAll(context.Background())
	assert.True(t, status["mytool"].Installed)
	assert.True(t, status["mytool"].Healthy)
	assert.Equal(t, "v1.2.3", status["mytool"].Version)
	assert.False(t, status["missingtool"].Installed)
	assert.False(t, status["missingtool"].Healthy)
}

func TestRegistryHealthCheckWithoutCommand(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Tool{Name: "nohc", Binary: "nohc"}))

	_, err := r.HealthCheck(context.Background(), "nohc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no health check defined")
}

func TestDefaultRegistryContainsKnownTools(t *testing.T) {
	r := DefaultRegistry()

	if tool, ok := r.Get("subfinder"); assert.True(t, ok) {
		assert.Equal(t, "subdomain", tool.Phase)
		assert.True(t, tool.Required)
	}
	if tool, ok := r.Get("nuclei"); assert.True(t, ok) {
		assert.Equal(t, "vuln", tool.Phase)
		assert.NotEmpty(t, tool.Install.Go)
	}
}

func TestVersionTrackerRecordLoadAndNeedsUpdate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "versions.json")

	vt, err := NewVersionTracker(dbPath)
	require.NoError(t, err)
	assert.True(t, vt.NeedsUpdate("subfinder", time.Hour))

	require.NoError(t, vt.Record("subfinder", "1.0.0", "/tmp/subfinder"))
	info, ok := vt.Get("subfinder")
	require.True(t, ok)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "/tmp/subfinder", info.InstallPath)
	assert.False(t, vt.NeedsUpdate("subfinder", time.Hour))

	vtReloaded, err := NewVersionTracker(dbPath)
	require.NoError(t, err)
	info, ok = vtReloaded.Get("subfinder")
	require.True(t, ok)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "/tmp/subfinder", info.InstallPath)

	info.UpdatedAt = time.Now().Add(-2 * time.Hour)
	assert.True(t, vtReloaded.NeedsUpdate("subfinder", time.Hour))
}

func TestInstallerWithoutMethods(t *testing.T) {
	installer := NewInstaller(zerolog.Nop())
	err := installer.Install(context.Background(), &Tool{Name: "custom"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no install method available")
}
