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

// SubIAPermut generates AI-assisted subdomain permutations with subwiz.
type SubIAPermut struct{}

func (m *SubIAPermut) Name() string            { return "sub_ia_permut" }
func (m *SubIAPermut) Description() string     { return "Generate AI-assisted subdomain permutations" }
func (m *SubIAPermut) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SubIAPermut) Dependencies() []string  { return []string{"dns_resolve"} }
func (m *SubIAPermut) RequiredTools() []string { return []string{"subwiz"} }

func (m *SubIAPermut) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.SubIAPermut {
		return fmt.Errorf("sub_ia_permut disabled")
	}
	return nil
}

func (m *SubIAPermut) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create subdomains dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	inputFile := filepath.Join(subsDir, "subdomains.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No seed subdomains for sub_ia_permut; skipping")
		return nil
	}

	generatedFile := filepath.Join(tmpDir, "subwiz.txt")
	resolvedFile := filepath.Join(tmpDir, "subwiz_resolved.txt")
	outFile := filepath.Join(subsDir, "sub_ia_permut.txt")

	if _, err := scan.Runner.Run(ctx, "subwiz", []string{"-i", inputFile, "--no-resolve", "-o", generatedFile}, runner.RunOpts{Timeout: 15 * time.Minute}); err != nil {
		scan.Logger.Warn().Err(err).Msg("subwiz failed")
		return nil
	}

	candidates, err := readLines(generatedFile)
	if err != nil || len(candidates) == 0 {
		return nil
	}

	if scan.Runner.IsInstalled("dnsx") {
		if _, err := scan.Runner.Run(ctx, "dnsx", []string{"-l", generatedFile, "-silent", "-o", resolvedFile}, runner.RunOpts{Timeout: 15 * time.Minute}); err != nil {
			scan.Logger.Warn().Err(err).Msg("dnsx resolution for sub_ia_permut failed")
		}
		if resolved, err := readLines(resolvedFile); err == nil && len(resolved) > 0 {
			candidates = resolved
		}
	}

	if err := writeLines(outFile, candidates); err != nil {
		return fmt.Errorf("write sub_ia_permut output: %w", err)
	}
	added := scan.Results.AddSubdomains(candidates)
	scan.Logger.Info().Int("generated", len(candidates)).Int("added", added).Msg("sub_ia_permut complete")
	return nil
}

var _ module.Module = (*SubIAPermut)(nil)
