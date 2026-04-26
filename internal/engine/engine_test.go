package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/duongpahm/ReconForge/internal/config"
)

func newTestEngine(t *testing.T) (*Engine, *StateManager) {
	t.Helper()
	dir := t.TempDir()
	sm, err := NewStateManager(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sm.Close() })

	cfg := &config.Config{
		General: config.GeneralConfig{MaxWorkers: 2},
	}
	return NewEngine(cfg, sm, zerolog.Nop()), sm
}

func TestEngine_Run_NoPipeline(t *testing.T) {
	eng, _ := newTestEngine(t)
	err := eng.Run(context.Background(), "example.com", "full")
	assert.ErrorContains(t, err, "no pipeline configured")
}

func TestEngine_Run_EmptyPipeline_Success(t *testing.T) {
	eng, sm := newTestEngine(t)

	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)

	err := eng.Run(context.Background(), "example.com", "full")
	require.NoError(t, err)

	state, err := sm.GetLastScan("example.com")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, StatusComplete, state.Status)
}

func TestEngine_Run_PipelineError(t *testing.T) {
	eng, sm := newTestEngine(t)

	p := NewPipeline()
	// Module listed but no handler registered → execution error
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{"missing_mod"}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)

	err := eng.Run(context.Background(), "example.com", "full")
	assert.Error(t, err)

	// Scan should be marked failed
	state, err := sm.GetLastScan("example.com")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, StatusFailed, state.Status)
}

func TestEngine_GetScanState_NoActiveScan(t *testing.T) {
	eng, _ := newTestEngine(t)
	_, err := eng.GetScanState()
	assert.ErrorContains(t, err, "no active scan")
}

func TestEngine_Summary_NoActiveScan(t *testing.T) {
	eng, _ := newTestEngine(t)
	_, err := eng.Summary()
	assert.Error(t, err)
}

func TestEngine_Summary_AfterRun(t *testing.T) {
	eng, _ := newTestEngine(t)

	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)

	err := eng.Run(context.Background(), "example.com", "full")
	require.NoError(t, err)

	summary, err := eng.Summary()
	require.NoError(t, err)
	assert.Equal(t, "example.com", summary.Target)
	assert.Equal(t, "full", summary.Mode)
	assert.Equal(t, StatusComplete, summary.Status)
}

func TestEngine_Resume_AlreadyComplete(t *testing.T) {
	eng, sm := newTestEngine(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)
	require.NoError(t, sm.MarkComplete(scanID))

	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)

	err = eng.Resume(context.Background(), scanID)
	assert.ErrorContains(t, err, "already completed")
}

func TestEngine_Resume_NoPipeline(t *testing.T) {
	eng, sm := newTestEngine(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)

	err = eng.Resume(context.Background(), scanID)
	assert.ErrorContains(t, err, "no pipeline configured")
}

func TestEngine_Resume_AllModulesComplete(t *testing.T) {
	eng, sm := newTestEngine(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)
	require.NoError(t, sm.UpdateModule(scanID, "mod1", StatusComplete, 5, 1.0, ""))

	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{"mod1"}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)

	err = eng.Resume(context.Background(), scanID)
	require.NoError(t, err)
}

func TestEngine_Resume_NonexistentScan(t *testing.T) {
	eng, _ := newTestEngine(t)

	p := NewPipeline()
	eng.SetPipeline(p)

	err := eng.Resume(context.Background(), "nonexistent-scan-id")
	assert.Error(t, err)
}

func TestStateManager_MarkFailed(t *testing.T) {
	sm := newTestState(t)

	scanID, err := sm.StartScan("example.com", "full")
	require.NoError(t, err)

	err = sm.MarkFailed(scanID)
	require.NoError(t, err)

	state, err := sm.GetScanState(scanID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, state.Status)
}

func TestParsePhase(t *testing.T) {
	cases := []struct {
		input   string
		want    Phase
		wantErr bool
	}{
		{"osint", PhaseOSINT, false},
		{"subdomain", PhaseSubdomain, false},
		{"web", PhaseWeb, false},
		{"vuln", PhaseVuln, false},
		{"unknown", 0, true},
		{"", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParsePhase(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestPhase_String(t *testing.T) {
	assert.Equal(t, "osint", PhaseOSINT.String())
	assert.Equal(t, "subdomain", PhaseSubdomain.String())
	assert.Equal(t, "web", PhaseWeb.String())
	assert.Equal(t, "vuln", PhaseVuln.String())
	assert.Equal(t, "unknown", Phase(99).String())
}

func TestPipeline_GetStage(t *testing.T) {
	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Phase: PhaseOSINT}))

	stage, ok := p.GetStage("osint")
	assert.True(t, ok)
	assert.Equal(t, "osint", stage.Name)

	_, ok = p.GetStage("nonexistent")
	assert.False(t, ok)
}

func TestPipeline_Validate_EmptyPipeline(t *testing.T) {
	p := NewPipeline()
	err := p.Validate()
	assert.ErrorContains(t, err, "no stages")
}

func TestEngine_ScanSummary_WithModules(t *testing.T) {
	eng, sm := newTestEngine(t)

	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "osint", Modules: []string{}, Phase: PhaseOSINT}))
	eng.SetPipeline(p)
	require.NoError(t, eng.Run(context.Background(), "target.com", "passive"))

	// Add some module results manually to test summary counting
	scanState, err := eng.GetScanState()
	require.NoError(t, err)
	require.NoError(t, sm.UpdateModule(scanState.ID, "dorks", StatusComplete, 2, 1.0, ""))
	require.NoError(t, sm.UpdateModule(scanState.ID, "leaks", StatusFailed, 0, 0.5, "connection refused"))

	summary, err := eng.Summary()
	require.NoError(t, err)
	assert.Equal(t, "target.com", summary.Target)
	assert.GreaterOrEqual(t, summary.Modules, 2)
}
