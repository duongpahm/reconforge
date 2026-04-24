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

// SubRegexPermut generates regex-based permutations of existing subdomains using gotator.
type SubRegexPermut struct{}

func (m *SubRegexPermut) Name() string { return "sub_regex_permut" }
func (m *SubRegexPermut) Description() string {
	return "Generate regex permutations from discovered subdomains"
}
func (m *SubRegexPermut) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SubRegexPermut) Dependencies() []string  { return []string{} }
func (m *SubRegexPermut) RequiredTools() []string { return []string{"gotator"} }

func (m *SubRegexPermut) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.RegexPermut {
		return fmt.Errorf("sub_regex_permut disabled")
	}
	return nil
}

func (m *SubRegexPermut) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	inputFile := filepath.Join(outDir, "subdomains.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No subdomains input for regex permutation; skipping")
		return nil
	}

	outFile := filepath.Join(outDir, "regex_permut.txt")

	_, err := scan.Runner.Run(ctx, "gotator", []string{"-i", inputFile, "-o", outFile}, runner.RunOpts{Timeout: 10 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("gotator failed")
		return nil
	}

	scan.Logger.Info().Msg("sub_regex_permut complete")
	return nil
}
