package osint

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

// APILeaks searches for leaked API keys and credentials in public API directories.
type APILeaks struct{}

func (m *APILeaks) Name() string            { return "api_leaks" }
func (m *APILeaks) Description() string     { return "API leaks via porch-pirate and SwaggerSpy" }
func (m *APILeaks) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *APILeaks) Dependencies() []string  { return nil }
func (m *APILeaks) RequiredTools() []string { return []string{"porch-pirate"} }

func (m *APILeaks) Validate(cfg *config.Config) error {
	if !cfg.OSINT.APILeaks {
		return fmt.Errorf("api_leaks disabled")
	}
	return nil
}

func (m *APILeaks) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running porch-pirate API leak scan")

	// Try with --dump first, fall back without it
	outFile := filepath.Join(osintDir, "postman_leaks.txt")
	result, err := scan.Runner.Run(ctx, "porch-pirate", []string{
		"-s", scan.Target, "-l", "25", "--dump",
	}, runner.RunOpts{Timeout: 15 * time.Minute})
	if err != nil || len(result.Stdout) == 0 {
		scan.Logger.Warn().Msg("porch-pirate --dump failed; retrying without --dump")
		result, err = scan.Runner.Run(ctx, "porch-pirate", []string{
			"-s", scan.Target, "-l", "25",
		}, runner.RunOpts{Timeout: 10 * time.Minute})
		if err != nil {
			scan.Logger.Warn().Err(err).Msg("porch-pirate failed (non-fatal)")
		}
	}

	if result != nil && len(result.Stdout) > 0 {
		os.WriteFile(outFile, result.Stdout, 0o644)
		scan.Logger.Info().Msg("api_leaks complete")
	}
	return nil
}
