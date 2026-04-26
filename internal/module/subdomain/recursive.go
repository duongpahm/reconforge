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

// Recursive performs recursive subdomain enumeration (passive + brute).
type Recursive struct{}

func (m *Recursive) Name() string            { return "recursive_enum" }
func (m *Recursive) Description() string     { return "Recursive subdomain enumeration (multi-level)" }
func (m *Recursive) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *Recursive) Dependencies() []string  { return []string{"subfinder", "dns_brute"} }
func (m *Recursive) RequiredTools() []string { return []string{"subfinder", "puredns"} }

func (m *Recursive) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.RecursivePassive && !cfg.Subdomain.RecursiveBrute {
		return fmt.Errorf("recursive enumeration disabled")
	}
	return nil
}

func (m *Recursive) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		return nil
	}

	scan.Logger.Info().
		Int("input_subs", len(currentSubs)).
		Bool("passive", scan.Config.Subdomain.RecursivePassive).
		Bool("brute", scan.Config.Subdomain.RecursiveBrute).
		Msg("Starting recursive enumeration")

	totalNew := 0
	maxDepth := 3 // limit recursion depth

	for depth := 1; depth <= maxDepth; depth++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		inputSubs := scan.Results.GetSubdomains()
		beforeCount := len(inputSubs)

		if scan.Config.Subdomain.RecursivePassive {
			// Run subfinder against each discovered subdomain
			inputFile := filepath.Join(subsDir, fmt.Sprintf("recursive_input_d%d.txt", depth))
			outFile := filepath.Join(subsDir, fmt.Sprintf("recursive_passive_d%d.txt", depth))
			writeLines(inputFile, inputSubs)

			_, err := scan.Runner.Run(ctx, "subfinder", []string{
				"-dL", inputFile,
				"-all",
				"-o", outFile,
				"-silent",
			}, runner.RunOpts{
				Timeout: 20 * time.Minute,
			})
			if err != nil {
				scan.Logger.Warn().Int("depth", depth).Err(err).Msg("Recursive passive failed")
			} else {
				subs, _ := readLines(outFile)
				scan.Results.AddSubdomains(subs)
			}
		}

		if scan.Config.Subdomain.RecursiveBrute {
			inputFile := filepath.Join(subsDir, fmt.Sprintf("recursive_brute_input_d%d.txt", depth))
			outFile := filepath.Join(subsDir, fmt.Sprintf("recursive_brute_d%d.txt", depth))
			writeLines(inputFile, inputSubs)

			wordlist := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "subdomains-short.txt")

			_, err := scan.Runner.Run(ctx, "puredns", []string{
				"bruteforce",
				wordlist,
				scan.Target,
				"-r", filepath.Join(scan.Config.General.ToolsDir, "resolvers.txt"),
				"-w", outFile,
				"--rate-limit", "300",
				"-q",
			}, runner.RunOpts{
				Timeout: 30 * time.Minute,
			})
			if err != nil {
				scan.Logger.Warn().Int("depth", depth).Err(err).Msg("Recursive brute failed")
			} else {
				subs, _ := readLines(outFile)
				scan.Results.AddSubdomains(subs)
			}
		}

		afterCount := scan.Results.SubdomainCount()
		newFound := afterCount - beforeCount
		totalNew += newFound

		scan.Logger.Info().
			Int("depth", depth).
			Int("new_found", newFound).
			Int("total", afterCount).
			Msg("Recursive depth completed")

		// Stop if no new subdomains found
		if newFound == 0 {
			scan.Logger.Info().
				Int("depth", depth).
				Msg("No new subdomains, stopping recursion")
			break
		}
	}

	scan.Logger.Info().
		Int("total_new", totalNew).
		Int("total_subs", scan.Results.SubdomainCount()).
		Msg("Recursive enumeration completed")

	return nil
}

var _ module.Module = (*Recursive)(nil)
