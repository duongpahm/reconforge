// Package engine provides the scan engine orchestrator.
package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/duongpahm/ReconForge/internal/config"
)

// Engine orchestrates the entire scan lifecycle.
type Engine struct {
	config   *config.Config
	state    *StateManager
	pipeline *Pipeline
	executor *PipelineExecutor
	logger   zerolog.Logger

	scanID string
}

// NewEngine creates a new scan engine.
func NewEngine(cfg *config.Config, stateMgr *StateManager, logger zerolog.Logger) *Engine {
	return &Engine{
		config: cfg,
		state:  stateMgr,
		logger: logger,
	}
}

// SetPipeline sets the execution pipeline.
func (e *Engine) SetPipeline(p *Pipeline) {
	e.pipeline = p
}

// Run executes a scan against the given target.
func (e *Engine) Run(ctx context.Context, target, mode string) error {
	// Validate pipeline
	if e.pipeline == nil {
		return fmt.Errorf("no pipeline configured")
	}
	if err := e.pipeline.Validate(); err != nil {
		return fmt.Errorf("pipeline validation: %w", err)
	}

	// Start scan
	scanID, err := e.state.StartScan(target, mode)
	if err != nil {
		return fmt.Errorf("start scan: %w", err)
	}
	e.scanID = scanID

	e.logger.Info().
		Str("scan_id", scanID).
		Str("target", target).
		Str("mode", mode).
		Msg("Scan started")

	// Create executor
	e.executor = NewPipelineExecutor(e.pipeline, e.config.General.MaxWorkers, e.logger)

	// Wire callbacks to state manager
	e.executor.OnModuleStart = func(stage, module string) {
		e.state.UpdateModule(scanID, module, StatusRunning, 0, 0, "")
	}

	e.executor.OnModuleComplete = func(stage, module string, result *ModuleResult) {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		e.state.UpdateModule(scanID, module, result.Status, result.Findings, result.Duration.Seconds(), errMsg)
	}

	// Execute pipeline
	_, err = e.executor.Execute(ctx)
	if err != nil {
		e.state.MarkFailed(scanID)
		return fmt.Errorf("pipeline execution: %w", err)
	}

	// Mark complete
	if err := e.state.MarkComplete(scanID); err != nil {
		return fmt.Errorf("mark complete: %w", err)
	}

	// Log summary
	scanState, _ := e.state.GetScanState(scanID)
	if scanState != nil {
		e.logger.Info().
			Str("scan_id", scanID).
			Str("status", string(scanState.Status)).
			Int("findings", scanState.Findings).
			Msg("Scan completed")
	}

	return nil
}

// Resume resumes a previously interrupted scan.
func (e *Engine) Resume(ctx context.Context, scanID string) error {
	state, err := e.state.GetScanState(scanID)
	if err != nil {
		return fmt.Errorf("get scan state: %w", err)
	}

	if state.Status == StatusComplete {
		return fmt.Errorf("scan %q already completed", scanID)
	}

	e.logger.Info().
		Str("scan_id", scanID).
		Str("target", state.Target).
		Msg("Resuming scan")

	// Determine which modules have already completed
	completedModules := make(map[string]bool)
	for _, m := range state.Modules {
		if m.Status == StatusComplete {
			completedModules[m.Name] = true
		}
	}

	e.logger.Info().
		Int("completed", len(completedModules)).
		Msg("Skipping completed modules")

	if e.pipeline == nil {
		return fmt.Errorf("no pipeline configured for resume")
	}

	// Build a filtered pipeline: remove completed modules from each stage
	filteredPipeline := NewPipeline()
	for _, stage := range e.pipeline.Stages {
		var remainingModules []string
		for _, m := range stage.Modules {
			if !completedModules[m] {
				remainingModules = append(remainingModules, m)
			}
		}

		// Skip stages where all modules are done
		if len(remainingModules) == 0 {
			e.logger.Debug().Str("stage", stage.Name).Msg("Stage fully completed, skipping")
			continue
		}

		// Re-add with filtered modules, preserving dependencies that still exist
		var validDeps []string
		for _, dep := range stage.DependsOn {
			if _, exists := filteredPipeline.GetStage(dep); exists {
				validDeps = append(validDeps, dep)
			}
		}

		filteredPipeline.AddStage(&Stage{
			Name:      stage.Name,
			Phase:     stage.Phase,
			Modules:   remainingModules,
			Parallel:  stage.Parallel,
			MaxJobs:   stage.MaxJobs,
			DependsOn: validDeps,
		})
	}

	if len(filteredPipeline.Stages) == 0 {
		e.logger.Info().Msg("All modules already completed, nothing to resume")
		return e.state.MarkComplete(scanID)
	}

	e.scanID = scanID

	// Create executor for filtered pipeline
	e.executor = NewPipelineExecutor(filteredPipeline, e.config.General.MaxWorkers, e.logger)

	// Wire callbacks
	e.executor.OnModuleStart = func(stage, module string) {
		e.state.UpdateModule(scanID, module, StatusRunning, 0, 0, "")
	}

	e.executor.OnModuleComplete = func(stage, module string, result *ModuleResult) {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		e.state.UpdateModule(scanID, module, result.Status, result.Findings, result.Duration.Seconds(), errMsg)
	}

	// Execute filtered pipeline
	_, err = e.executor.Execute(ctx)
	if err != nil {
		e.state.MarkFailed(scanID)
		return fmt.Errorf("resumed pipeline execution: %w", err)
	}

	return e.state.MarkComplete(scanID)
}

// GetScanState returns the current state of the active scan.
func (e *Engine) GetScanState() (*ScanState, error) {
	if e.scanID == "" {
		return nil, fmt.Errorf("no active scan")
	}
	return e.state.GetScanState(e.scanID)
}

// ScanSummary holds a human-readable scan summary.
type ScanSummary struct {
	ScanID     string
	Target     string
	Mode       string
	Status     ScanStatus
	StartedAt  time.Time
	Duration   time.Duration
	Stages     int
	Modules    int
	Completed  int
	Failed     int
	Findings   int
}

// Summary generates a scan summary.
func (e *Engine) Summary() (*ScanSummary, error) {
	state, err := e.GetScanState()
	if err != nil {
		return nil, err
	}

	summary := &ScanSummary{
		ScanID:   state.ID,
		Target:   state.Target,
		Mode:     state.Mode,
		Status:   state.Status,
		StartedAt: state.StartedAt,
		Modules:  len(state.Modules),
		Findings: state.Findings,
	}

	if state.CompletedAt != nil {
		summary.Duration = state.CompletedAt.Sub(state.StartedAt)
	}

	for _, m := range state.Modules {
		switch m.Status {
		case StatusComplete:
			summary.Completed++
		case StatusFailed:
			summary.Failed++
		}
	}

	return summary, nil
}
