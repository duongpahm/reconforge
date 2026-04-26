package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsInstalledFromPATH(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("PATH", dir)
	t.Setenv("HOME", t.TempDir())

	manager := NewManager()
	installed, path := manager.IsInstalled("mytool")
	assert.True(t, installed)
	assert.Equal(t, bin, path)
}

func TestIsInstalledFallsBackToGoBin(t *testing.T) {
	home := t.TempDir()
	goBinDir := filepath.Join(home, "go", "bin")
	require.NoError(t, os.MkdirAll(goBinDir, 0o755))

	fallback := filepath.Join(goBinDir, "fallbacktool")
	require.NoError(t, os.WriteFile(fallback, []byte("binary"), 0o644))

	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", home)

	manager := NewManager()
	installed, path := manager.IsInstalled("fallbacktool")
	assert.True(t, installed)
	assert.Equal(t, fallback, path)
}

func TestInstallUnregisteredTool(t *testing.T) {
	manager := NewManager()
	err := manager.Install("definitely-missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestInstallWithoutCommand(t *testing.T) {
	const name = "no-install-tool"
	original, existed := Registry[name]
	Registry[name] = Tool{Name: name}
	t.Cleanup(func() {
		if existed {
			Registry[name] = original
		} else {
			delete(Registry, name)
		}
	})

	manager := NewManager()
	err := manager.Install(name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no automated installation")
}

func TestListIncludesRegisteredTools(t *testing.T) {
	manager := NewManager()
	statuses := manager.List()

	assert.Len(t, statuses, len(Registry))
	seen := make(map[string]bool, len(statuses))
	for _, status := range statuses {
		seen[status.Name] = true
	}
	for name := range Registry {
		assert.True(t, seen[name], "expected tool %s in list", name)
	}
}

func TestCheckEnvironmentCreatesReconforgeDir(t *testing.T) {
	home := t.TempDir()
	binDir := t.TempDir()
	goBin := filepath.Join(binDir, "go")
	pythonBin := filepath.Join(binDir, "python3")

	require.NoError(t, os.WriteFile(goBin, []byte("#!/bin/sh\necho go version go1.25.0 test\n"), 0o755))
	require.NoError(t, os.WriteFile(pythonBin, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("HOME", home)
	t.Setenv("PATH", binDir)

	manager := NewManager()
	issues := manager.CheckEnvironment()
	assert.Empty(t, issues)

	info, err := os.Stat(filepath.Join(home, ".reconforge"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestInstallRecordsChecksumAndDetectsTampering(t *testing.T) {
	const toolName = "fakeinstall"

	original, existed := Registry[toolName]
	t.Cleanup(func() {
		if existed {
			Registry[toolName] = original
		} else {
			delete(Registry, toolName)
		}
	})

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	goBin := filepath.Join(home, "go", "bin")
	require.NoError(t, os.MkdirAll(goBin, 0o755))

	Registry[toolName] = Tool{
		Name: toolName,
		InstallCmd: []string{
			"/bin/sh", "-c",
			"printf '#!/bin/sh\\necho original\\n' > \"$HOME/go/bin/fakeinstall\" && /bin/chmod 755 \"$HOME/go/bin/fakeinstall\"",
		},
		Type:    "binary",
		DocsURL: "https://example.com/fakeinstall",
	}

	manager := NewManager()
	require.NoError(t, manager.Install(toolName))

	manifestPath, err := manager.checksumManifestPath()
	require.NoError(t, err)
	manifestData, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	assert.Contains(t, string(manifestData), toolName)

	binPath := filepath.Join(goBin, toolName)
	f, err := os.OpenFile(binPath, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteString("tampered")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	err = manager.Install(toolName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}
