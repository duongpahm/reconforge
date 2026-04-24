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

// SpoofCheck checks if the domain is vulnerable to email spoofing via Spoofy.
type SpoofCheck struct{}

func (m *SpoofCheck) Name() string            { return "spoof_check" }
func (m *SpoofCheck) Description() string     { return "Email spoofing check via Spoofy" }
func (m *SpoofCheck) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *SpoofCheck) Dependencies() []string  { return nil }
func (m *SpoofCheck) RequiredTools() []string { return []string{"spoofy"} }

func (m *SpoofCheck) Validate(cfg *config.Config) error {
	if !cfg.OSINT.Spoof {
		return fmt.Errorf("spoof check disabled")
	}
	return nil
}

func (m *SpoofCheck) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running Spoofy email spoofing check")

	outFile := filepath.Join(osintDir, "spoof.txt")
	result, err := scan.Runner.Run(ctx, "spoofy", []string{"-d", scan.Target},
		runner.RunOpts{Timeout: 10 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("spoofy failed (non-fatal)")
		return nil
	}

	if len(result.Stdout) > 0 {
		os.WriteFile(outFile, result.Stdout, 0o644)
		scan.Logger.Info().Msg("spoof_check complete")
	}
	return nil
}
