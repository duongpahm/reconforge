package subdomain

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

// Takeover detects subdomain takeover vulnerabilities using dnstake.
type Takeover struct{}

func (m *Takeover) Name() string            { return "takeover" }
func (m *Takeover) Description() string     { return "Subdomain takeover detection via dnstake" }
func (m *Takeover) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *Takeover) Dependencies() []string  { return []string{"dns_brute", "permutations"} }
func (m *Takeover) RequiredTools() []string { return []string{"dnstake"} }

func (m *Takeover) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Takeover {
		return fmt.Errorf("subdomain takeover scanning disabled")
	}
	return nil
}

func (m *Takeover) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		scan.Logger.Info().Msg("No subdomains to check for takeover, skipping")
		return nil
	}

	// Write subdomains to input file
	inputFile := filepath.Join(subsDir, "takeover_input.txt")
	writeLines(inputFile, currentSubs)

	outFile := filepath.Join(subsDir, "takeover_results.txt")

	args := []string{
		"-f", inputFile,
		"-o", outFile,
		"-c", "50", // concurrency
		"-s", // silent
	}

	scan.Logger.Info().
		Int("subdomains", len(currentSubs)).
		Msg("Checking for subdomain takeover vulnerabilities")

	result, err := scan.Runner.Run(ctx, "dnstake", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("dnstake failed (non-fatal)")
		return nil
	}

	// Parse dnstake results for vulnerable entries
	vulnerable, _ := readLines(outFile)

	// Record findings for each vulnerable domain
	for _, v := range vulnerable {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "takeover",
			Type:     "vuln",
			Severity: "high",
			Target:   v,
			Detail:   "Potential subdomain takeover vulnerability detected",
		}})
	}

	scan.Logger.Info().
		Int("checked", len(currentSubs)).
		Int("vulnerable", len(vulnerable)).
		Dur("duration", result.Duration).
		Msg("Subdomain takeover scan completed")

	return nil
}

var _ module.Module = (*Takeover)(nil)
