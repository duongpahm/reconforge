package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestState(t *testing.T) *StateManager {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test-state.db")
	sm, err := NewStateManager(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { sm.Close() })
	return sm
}

func TestStateManager_StartScan(t *testing.T) {
	sm := newTestState(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)
	assert.Contains(t, scanID, "example.com")
}

func TestStateManager_GetScanState(t *testing.T) {
	sm := newTestState(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)

	state, err := sm.GetScanState(scanID)
	require.NoError(t, err)
	assert.Equal(t, "example.com", state.Target)
	assert.Equal(t, "full", state.Mode)
	assert.Equal(t, StatusRunning, state.Status)
}

func TestStateManager_UpdateModule(t *testing.T) {
	sm := newTestState(t)

	scanID, _ := sm.StartScan("example.com", "full")

	err := sm.UpdateModule(scanID, "subfinder", StatusComplete, 42, 5.5, "")
	require.NoError(t, err)

	state, err := sm.GetScanState(scanID)
	require.NoError(t, err)
	require.Len(t, state.Modules, 1)
	assert.Equal(t, "subfinder", state.Modules[0].Name)
	assert.Equal(t, StatusComplete, state.Modules[0].Status)
	assert.Equal(t, 42, state.Modules[0].Findings)
}

func TestStateManager_MarkComplete(t *testing.T) {
	sm := newTestState(t)

	scanID, _ := sm.StartScan("example.com", "full")
	sm.UpdateModule(scanID, "subfinder", StatusComplete, 10, 2.0, "")
	sm.UpdateModule(scanID, "httpx", StatusComplete, 5, 1.0, "")

	err := sm.MarkComplete(scanID)
	require.NoError(t, err)

	state, err := sm.GetScanState(scanID)
	require.NoError(t, err)
	assert.Equal(t, StatusComplete, state.Status)
	assert.Equal(t, 15, state.Findings) // sum of modules
	assert.NotNil(t, state.CompletedAt)
}

func TestStateManager_GetLastScan(t *testing.T) {
	sm := newTestState(t)

	sm.StartScan("example.com", "quick")
	scanID2, _ := sm.StartScan("example.com", "full")

	state, err := sm.GetLastScan("example.com")
	require.NoError(t, err)
	assert.Equal(t, scanID2, state.ID)
}

func TestStateManager_GetLastScan_NoHistory(t *testing.T) {
	sm := newTestState(t)

	state, err := sm.GetLastScan("nonexistent.com")
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestStateManager_Checkpoint(t *testing.T) {
	sm := newTestState(t)

	scanID, _ := sm.StartScan("example.com", "full")

	// Save checkpoint
	checkpoint := map[string]interface{}{
		"completed_modules": []string{"subfinder", "httpx"},
		"pending_modules":   []string{"nuclei"},
	}
	err := sm.SaveCheckpoint(scanID, checkpoint)
	require.NoError(t, err)

	// Load checkpoint
	var loaded map[string]interface{}
	err = sm.LoadCheckpoint(scanID, &loaded)
	require.NoError(t, err)
	assert.Contains(t, loaded, "completed_modules")
}

func TestStateManager_Checkpoint_NotFound(t *testing.T) {
	sm := newTestState(t)

	var loaded map[string]interface{}
	err := sm.LoadCheckpoint("nonexistent", &loaded)
	assert.Error(t, err)
}

func TestStateManager_NotFound(t *testing.T) {
	sm := newTestState(t)

	_, err := sm.GetScanState("nonexistent-id")
	assert.Error(t, err)
}

func TestStateManager_DBPath(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "dir")
	os.MkdirAll(nested, 0o755)
	dbPath := filepath.Join(nested, "state.db")

	sm, err := NewStateManager(dbPath)
	require.NoError(t, err)
	defer sm.Close()

	_, err = sm.StartScan("test.com", "quick")
	require.NoError(t, err)
}
