package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDashboardUpdateTracksStageModuleAndFindings(t *testing.T) {
	dash := NewDashboard("example.com", "recon", "scan-test-123456")
	dash.Stages = []StageDisplay{{
		Name:   "Web analysis",
		Status: "pending",
		Modules: []ModuleStatus{{
			Name:   "httpx_probe",
			Status: "pending",
		}},
	}}
	dash.TotalModules = 1

	model, _ := dash.Update(StageStartMsg{Stage: "Web analysis"})
	dash = model.(Dashboard)
	require.Equal(t, "running", dash.Stages[0].Status)

	model, _ = dash.Update(ModuleStartMsg{Stage: "Web analysis", Module: "httpx_probe"})
	dash = model.(Dashboard)
	require.Equal(t, "running", dash.Stages[0].Modules[0].Status)

	model, _ = dash.Update(ModuleCompleteMsg{
		Stage:    "Web analysis",
		Module:   "httpx_probe",
		Status:   "complete",
		Findings: 3,
		Duration: 50 * time.Millisecond,
	})
	dash = model.(Dashboard)

	assert.Equal(t, 1, dash.Completed)
	assert.Equal(t, 0, dash.Failed)
	assert.Equal(t, 3, dash.Findings)
	assert.Equal(t, "complete", dash.Stages[0].Modules[0].Status)
	assert.Equal(t, 50*time.Millisecond, dash.Stages[0].Modules[0].Duration)
}

func TestDashboardUpdateQuitKeys(t *testing.T) {
	dash := NewDashboard("example.com", "recon", "scan-test")

	_, cmd := dash.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	require.NotNil(t, cmd)

	msg := cmd()
	assert.Equal(t, tea.Quit(), msg)
}

func TestDashboardAdapterRegisterStages(t *testing.T) {
	p := engine.NewPipeline()
	require.NoError(t, p.AddStage(&engine.Stage{
		Name:    "web_probe",
		Phase:   engine.PhaseWeb,
		Modules: []string{"httpx_probe"},
	}))
	require.NoError(t, p.AddStage(&engine.Stage{
		Name:      "web_analysis",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"crawler", "nuclei_check"},
		DependsOn: []string{"web_probe"},
	}))

	dash := NewDashboard("example.com", "web", "scan-test")
	adapter := NewDashboardAdapter(&dash, nil, module.NewScanResults())
	adapter.RegisterStages(p)

	snapshot := adapter.Snapshot()
	require.Len(t, snapshot.Stages, 2)
	assert.Equal(t, "Web probe", snapshot.Stages[0].Name)
	assert.Equal(t, "Web analysis", snapshot.Stages[1].Name)
	assert.Equal(t, 3, snapshot.TotalModules)
	assert.Equal(t, "pending", snapshot.Stages[1].Modules[0].Status)
}

func TestProgressBarRenderBounds(t *testing.T) {
	rendered := ProgressBar{Total: 2, Current: 5, Width: 8, Label: "Progress", ShowPct: true}.Render()
	assert.Contains(t, rendered, "Progress")
	assert.True(t, strings.Contains(rendered, "250%") || strings.Contains(rendered, "100%"))
}
