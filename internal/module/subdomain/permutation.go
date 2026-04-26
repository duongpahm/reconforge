package subdomain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// Permutation generates subdomain permutations using gotator.
type Permutation struct{}

func (m *Permutation) Name() string            { return "permutations" }
func (m *Permutation) Description() string     { return "Subdomain permutation generation via gotator" }
func (m *Permutation) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *Permutation) Dependencies() []string  { return []string{"subfinder", "crt_sh"} }
func (m *Permutation) RequiredTools() []string { return []string{"gotator", "puredns"} }

func (m *Permutation) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Permutations {
		return fmt.Errorf("permutation generation disabled")
	}
	return nil
}

func (m *Permutation) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Write current subdomains to input file
	inputFile := filepath.Join(subsDir, "permutation_input.txt")
	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		scan.Logger.Info().Msg("No subdomains to permute, skipping")
		return nil
	}
	writeLines(inputFile, currentSubs)

	permFile := filepath.Join(subsDir, "gotator_perms.txt")
	permWordsFile := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "permutations.txt")

	// Generate permutations with gotator
	scan.Logger.Info().
		Int("input_subs", len(currentSubs)).
		Msg("Generating permutations with gotator")

	result, err := scan.Runner.Run(ctx, "gotator", []string{
		"-sub", inputFile,
		"-perm", permWordsFile,
		"-depth", "1",
		"-numbers", "10",
		"-mindup",
		"-addn",
	}, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("gotator: %w", err)
	}

	// Write permutations
	perms := parseLines(result.Stdout)
	writeLines(permFile, perms)

	// Resolve permutations with puredns
	resolvedFile := filepath.Join(subsDir, "permutation_resolved.txt")

	scan.Logger.Info().
		Int("permutations", len(perms)).
		Msg("Resolving permutations with puredns")

	_, err = scan.Runner.Run(ctx, "puredns", []string{
		"resolve",
		permFile,
		"-r", filepath.Join(scan.Config.General.ToolsDir, "resolvers.txt"),
		"-w", resolvedFile,
		"--rate-limit", "500",
		"-q",
	}, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Permutation resolution failed (non-fatal)")
		return nil
	}

	resolved, _ := readLines(resolvedFile)
	added := scan.Results.AddSubdomains(resolved)

	scan.Logger.Info().
		Int("generated", len(perms)).
		Int("resolved", len(resolved)).
		Int("new", added).
		Msg("Permutations completed")

	return nil
}

var _ module.Module = (*Permutation)(nil)
