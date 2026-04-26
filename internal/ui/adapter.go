package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
)

// DashboardAdapter bridges the orchestrator execution with the TUI dashboard.
// It receives callbacks from the pipeline executor and converts them to
// Dashboard-compatible data structures for real-time display.
type DashboardAdapter struct {
	mu        sync.RWMutex
	dashboard *Dashboard
	program   *tea.Program
	results   *module.ScanResults

	stageOrder []string
	stageIndex map[string]int
}

// NewDashboardAdapter creates a new adapter that will populate the given dashboard.
func NewDashboardAdapter(dash *Dashboard, program *tea.Program, results *module.ScanResults) *DashboardAdapter {
	return &DashboardAdapter{
		dashboard:  dash,
		program:    program,
		results:    results,
		stageIndex: make(map[string]int),
	}
}

// RegisterStages pre-populates the dashboard with stages in execution order.
func (da *DashboardAdapter) RegisterStages(pipeline *engine.Pipeline) {
	da.mu.Lock()
	defer da.mu.Unlock()

	stages, _ := pipeline.TopologicalOrder()
	da.dashboard.Stages = make([]StageDisplay, len(stages))
	da.dashboard.TotalModules = 0

	for i, stage := range stages {
		da.stageOrder = append(da.stageOrder, stage.Name)
		da.stageIndex[stage.Name] = i

		modules := make([]ModuleStatus, len(stage.Modules))
		for j, m := range stage.Modules {
			modules[j] = ModuleStatus{
				Name:   m,
				Status: "pending",
			}
		}

		da.dashboard.Stages[i] = StageDisplay{
			Name:    formatStageName(stage.Name),
			Status:  "pending",
			Modules: modules,
		}

		da.dashboard.TotalModules += len(stage.Modules)
	}
}

// OnStageStart is the callback for when a pipeline stage begins.
func (da *DashboardAdapter) OnStageStart(stage string) {
	if da.program != nil {
		da.program.Send(StageStartMsg{Stage: formatStageName(stage)})
	}
}

// OnStageComplete is the callback for when a pipeline stage finishes.
func (da *DashboardAdapter) OnStageComplete(stage string, result *engine.StageResult) {
	if da.program != nil {
		status := "complete"
		if result.Status != engine.StatusComplete {
			status = "failed"
		}
		da.program.Send(StageCompleteMsg{Stage: formatStageName(stage), Status: status})
	}
}

// OnModuleStart is the callback for when a module begins execution.
func (da *DashboardAdapter) OnModuleStart(stage, moduleName string) {
	if da.program != nil {
		da.program.Send(ModuleStartMsg{Stage: formatStageName(stage), Module: moduleName})
	}
}

// OnModuleComplete is the callback for when a module finishes execution.
func (da *DashboardAdapter) OnModuleComplete(stage, moduleName string, result *engine.ModuleResult) {
	if da.program != nil {
		status := "complete"
		if result.Status != engine.StatusComplete {
			status = "failed"
		}
		da.program.Send(ModuleCompleteMsg{
			Stage:    formatStageName(stage),
			Module:   moduleName,
			Status:   status,
			Findings: result.Findings,
			Duration: result.Duration,
		})
	}
}

// Snapshot returns a copy of the current dashboard state for rendering.
func (da *DashboardAdapter) Snapshot() Dashboard {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return *da.dashboard
}

func formatStageName(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

// RenderCompact returns a compact single-line progress summary for non-TUI mode.
func RenderCompact(target string, completed, total, findings int, elapsed time.Duration) string {
	pct := 0
	if total > 0 {
		pct = (completed * 100) / total
	}

	return fmt.Sprintf(
		"\r[*] %s | %d/%d modules (%d%%) | %d findings | %s",
		target, completed, total, pct, findings, elapsed.Round(time.Second),
	)
}
