package vuln

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// Spraying performs password spraying against discovered services using brutespray.
type Spraying struct{}

func (m *Spraying) Name() string           { return "spraying" }
func (m *Spraying) Description() string    { return "Password spraying via brutespray" }
func (m *Spraying) Phase() engine.Phase    { return engine.PhaseVuln }
func (m *Spraying) Dependencies() []string { return []string{"port_scan"} }
func (m *Spraying) RequiredTools() []string { return []string{"brutespray"} }

func (m *Spraying) Validate(cfg *config.Config) error {
	if !cfg.Vuln.Spray {
		return fmt.Errorf("spraying disabled")
	}
	return nil
}

func (m *Spraying) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns", "brutespray")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create spraying output dir: %w", err)
	}

	gnmapFile := filepath.Join(hostsDir, "portscan_active.gnmap")
	if _, err := os.Stat(gnmapFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No portscan_active.gnmap; spraying skipped")
		return nil
	}

	scan.Logger.Info().Msg("Running brutespray password spraying")

	_, err := scan.Runner.Run(ctx, "brutespray", []string{
		"-f", gnmapFile,
		"-T", "5",
		"-o", vulnsDir,
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("brutespray failed (non-fatal)")
		return nil
	}

	entries, _ := os.ReadDir(vulnsDir)
	scan.Logger.Info().Int("output_files", len(entries)).Msg("spraying complete")
	return nil
}
