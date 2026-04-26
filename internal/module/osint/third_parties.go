package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// ThirdPartyMisconfigs scans for misconfigurations in 3rd party services.
type ThirdPartyMisconfigs struct{}

func (m *ThirdPartyMisconfigs) Name() string            { return "third_parties" }
func (m *ThirdPartyMisconfigs) Description() string     { return "Scan for third-party misconfigurations" }
func (m *ThirdPartyMisconfigs) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *ThirdPartyMisconfigs) Dependencies() []string  { return []string{} }
func (m *ThirdPartyMisconfigs) RequiredTools() []string { return []string{"misconfig-mapper"} }

func (m *ThirdPartyMisconfigs) Validate(cfg *config.Config) error {
	if !cfg.OSINT.ThirdParties {
		return fmt.Errorf("third_parties disabled")
	}
	return nil
}

func (m *ThirdPartyMisconfigs) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	scan.Logger.Info().Msg("Scanning for third-party misconfigurations...")

	outFile := filepath.Join(outDir, "3rdparts_misconfigurations.txt")

	result, err := scan.Runner.Run(ctx, "misconfig-mapper", []string{
		"-target", scan.Target,
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("misconfig-mapper failed")
		return nil
	}

	if len(result.Stdout) > 0 {
		_ = os.WriteFile(outFile, result.Stdout, 0o644)
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				scan.Results.AddFindings([]module.Finding{{
					Module:   m.Name(),
					Type:     "info",
					Severity: "low",
					Target:   scan.Target,
					Detail:   fmt.Sprintf("Misconfig: %s", line),
				}})
			}
		}
	}

	scan.Logger.Info().Msg("third_parties complete")
	return nil
}
