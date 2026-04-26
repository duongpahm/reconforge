package web

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

// JSChecks runs subjs, mantra, and getjswords on crawled URLs.
type JSChecks struct{}

func (m *JSChecks) Name() string            { return "jschecks" }
func (m *JSChecks) Description() string     { return "Extract JS assets, secrets, and keywords" }
func (m *JSChecks) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *JSChecks) Dependencies() []string  { return []string{"urlext"} }
func (m *JSChecks) RequiredTools() []string { return []string{"subjs", "mantra", "getjswords"} }

func (m *JSChecks) Validate(cfg *config.Config) error {
	if !cfg.Web.JSAnalysis {
		return fmt.Errorf("js_analysis disabled")
	}
	return nil
}

func (m *JSChecks) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "js")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	inputFile := filepath.Join(scan.OutputDir, "webs", "url_extract.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No input for jschecks (url_extract.txt); skipping")
		return nil
	}

	scan.Logger.Info().Msg("Running JS checks (subjs, mantra, getjswords)...")

	// 1. Run subjs
	jsLinksFile := filepath.Join(outDir, "js_links.txt")
	_, err := scan.Runner.Run(ctx, "subjs", []string{
		"-i", inputFile,
		"-o", jsLinksFile,
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("subjs failed")
	}

	// Wait if there are no js links
	if _, err := os.Stat(jsLinksFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No JS links found; skipping mantra and getjswords")
		return nil
	}

	// 2. Run mantra for secrets on the extracted JS links
	mantraOut := filepath.Join(outDir, "js_secrets.txt")
	ctxMantra, cancelMantra := context.WithTimeout(ctx, 45*time.Minute)
	defer cancelMantra()
	resultMantra, err := scan.Runner.RunPipe(ctxMantra, []runner.PipeCmd{
		{Name: "cat", Args: []string{jsLinksFile}},
		{Name: "mantra", Args: nil},
	})

	if err != nil {
		scan.Logger.Warn().Err(err).Msg("mantra failed")
	} else if len(resultMantra.Stdout) > 0 {
		_ = os.WriteFile(mantraOut, resultMantra.Stdout, 0o644)
		for _, line := range strings.Split(string(resultMantra.Stdout), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				scan.Results.AddFindings([]module.Finding{{
					Module:   m.Name(),
					Type:     "vuln",
					Severity: "high",
					Target:   line,
					Detail:   "Mantra secret found",
				}})
			}
		}
	}

	// Fixed getjswords pipeline
	wordlistOut := filepath.Join(outDir, "js_wordlist.txt")
	ctxWords, cancelWords := context.WithTimeout(ctx, 30*time.Minute)
	defer cancelWords()
	resultJSWords, err := scan.Runner.RunPipe(ctxWords, []runner.PipeCmd{
		{Name: "cat", Args: []string{jsLinksFile}},
		{Name: "getjswords", Args: nil},
	})
	if err == nil && len(resultJSWords.Stdout) > 0 {
		_ = os.WriteFile(wordlistOut, resultJSWords.Stdout, 0o644)
	}

	scan.Logger.Info().Msg("jschecks complete")
	return nil
}
