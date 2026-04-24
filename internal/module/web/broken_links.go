package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// BrokenLinks uses httpx to find 404/410 responses which might be hijackable.
type BrokenLinks struct{}

func (m *BrokenLinks) Name() string { return "broken_links" }
func (m *BrokenLinks) Description() string {
	return "Find broken links (404, 410) for potential hijacking"
}
func (m *BrokenLinks) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *BrokenLinks) Dependencies() []string  { return []string{"crawler"} }
func (m *BrokenLinks) RequiredTools() []string { return []string{"httpx"} }

func (m *BrokenLinks) Validate(cfg *config.Config) error {
	if !cfg.Web.BrokenLinks {
		return fmt.Errorf("broken_links disabled")
	}
	return nil
}

func (m *BrokenLinks) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	inputFile := filepath.Join(outDir, "url_extract.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No crawled URLs found; skipping broken_links")
		return nil
	}

	scan.Logger.Info().Msg("Checking for broken links using httpx...")

	outputFile := filepath.Join(outDir, "broken_links.txt")

	result, err := scan.Runner.Run(ctx, "httpx", []string{
		"-l", inputFile,
		"-mc", "404,410",
		"-o", outputFile,
		"-silent",
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("httpx broken_links failed")
		return nil
	}

	if result.ExitCode == 0 {
		if content, err := os.ReadFile(outputFile); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					scan.Results.AddFindings([]module.Finding{{
						Module:   m.Name(),
						Type:     "url",
						Severity: "info",
						Target:   line,
						Detail:   "Broken link detected",
					}})
				}
			}
		}
	}

	scan.Logger.Info().Msg("broken_links complete")
	return nil
}
