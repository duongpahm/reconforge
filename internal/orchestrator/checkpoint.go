package orchestrator

import (
	"time"

	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
)

const checkpointSchemaVersion = 1

type ScanCheckpoint struct {
	Version    int                `json:"version"`
	ScanID     string             `json:"scan_id"`
	Target     string             `json:"target"`
	Mode       string             `json:"mode"`
	OutputDir  string             `json:"output_dir"`
	UpdatedAt  time.Time          `json:"updated_at"`
	Findings   int                `json:"findings"`
	Subdomains int                `json:"subdomains"`
	LiveHosts  int                `json:"live_hosts"`
	URLs       int                `json:"urls"`
	Completed  int                `json:"completed"`
	Failed     int                `json:"failed"`
	Modules    []ModuleCheckpoint `json:"modules"`
}

type ModuleCheckpoint struct {
	Name      string            `json:"name"`
	Status    engine.ScanStatus `json:"status"`
	Findings  int               `json:"findings"`
	Duration  float64           `json:"duration_secs"`
	Error     string            `json:"error,omitempty"`
	StartedAt time.Time         `json:"started_at,omitempty"`
}

func buildCheckpoint(scanID, target, mode, outputDir string, results *module.ScanResults, state *engine.ScanState) *ScanCheckpoint {
	cp := &ScanCheckpoint{
		Version:   checkpointSchemaVersion,
		ScanID:    scanID,
		Target:    target,
		Mode:      mode,
		OutputDir: outputDir,
		UpdatedAt: time.Now().UTC(),
	}
	if results != nil {
		cp.Findings = len(results.GetFindings())
		cp.Subdomains = results.SubdomainCount()
		cp.LiveHosts = len(results.GetLiveHosts())
		cp.URLs = len(results.GetURLs())
	}
	if state == nil {
		return cp
	}

	cp.Modules = make([]ModuleCheckpoint, 0, len(state.Modules))
	for _, mod := range state.Modules {
		if mod.Status == engine.StatusComplete {
			cp.Completed++
		}
		if mod.Status == engine.StatusFailed {
			cp.Failed++
		}
		cp.Modules = append(cp.Modules, ModuleCheckpoint{
			Name:      mod.Name,
			Status:    mod.Status,
			Findings:  mod.Findings,
			Duration:  mod.Duration,
			Error:     mod.Error,
			StartedAt: mod.StartedAt,
		})
	}

	return cp
}

func persistCheckpoint(stateMgr *engine.StateManager, scanID, target, mode, outputDir string, results *module.ScanResults) error {
	state, err := stateMgr.GetScanState(scanID)
	if err != nil {
		return err
	}
	return stateMgr.SaveCheckpoint(scanID, buildCheckpoint(scanID, target, mode, outputDir, results, state))
}

func shouldPersistCheckpoint(stateMgr *engine.StateManager, scanID string, every int, force bool) bool {
	if force || every <= 1 {
		return true
	}

	state, err := stateMgr.GetScanState(scanID)
	if err != nil {
		return true
	}

	completed := 0
	for _, mod := range state.Modules {
		if mod.Status == engine.StatusComplete || mod.Status == engine.StatusFailed {
			completed++
		}
	}

	return completed > 0 && completed%every == 0
}
