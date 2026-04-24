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

// CRLFCheck tests for CRLF injection vulnerabilities using crlfuzz.
type CRLFCheck struct{}

func (m *CRLFCheck) Name() string          { return "crlf_check" }
func (m *CRLFCheck) Description() string   { return "CRLF injection testing via crlfuzz" }
func (m *CRLFCheck) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *CRLFCheck) Dependencies() []string { return []string{"httpx_probe"} }
func (m *CRLFCheck) RequiredTools() []string { return []string{"crlfuzz"} }

func (m *CRLFCheck) Validate(cfg *config.Config) error {
	if !cfg.Vuln.CRLF {
		return fmt.Errorf("CRLF checks disabled")
	}
	return nil
}

func (m *CRLFCheck) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Warn().Msg("No web targets for CRLF checks; skipping")
		return nil
	}

	// Skip if too many targets and not in deep mode
	if !scan.Config.General.Deep && len(targets) > 500 {
		scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many targets for CRLF scan; skipping (use deep mode)")
		return nil
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running crlfuzz")

	outFile := filepath.Join(vulnsDir, "crlf.txt")
	_, err = scan.Runner.Run(ctx, "crlfuzz", []string{
		"-l", websAllFile,
		"-o", outFile,
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("crlfuzz failed (non-fatal)")
		return nil
	}

	found, _ := readLines(outFile)
	if len(found) > 0 {
		for _, f := range found {
			scan.Results.AddFindings([]module.Finding{{
				Module:   "crlf_check",
				Type:     "vuln",
				Severity: "medium",
				Target:   f,
				Detail:   "CRLF injection via crlfuzz",
			}})
		}
		scan.Logger.Info().Int("vulnerabilities", len(found)).Msg("CRLF check complete")
	}
	return nil
}
