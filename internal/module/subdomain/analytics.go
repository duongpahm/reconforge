package subdomain

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

// AnalyticsEnum discovers subdomains via analytics relationship tracking using analyticsrelationships.
type AnalyticsEnum struct{}

func (m *AnalyticsEnum) Name() string { return "sub_analytics" }
func (m *AnalyticsEnum) Description() string {
	return "Analytics-based subdomain discovery via analyticsrelationships"
}
func (m *AnalyticsEnum) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *AnalyticsEnum) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *AnalyticsEnum) RequiredTools() []string { return []string{"analyticsrelationships"} }

func (m *AnalyticsEnum) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Analytics {
		return fmt.Errorf("sub_analytics disabled")
	}
	return nil
}

func (m *AnalyticsEnum) Run(ctx context.Context, scan *module.ScanContext) error {
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// analyticsrelationships reads from scraped probed URLs
	probedFile := filepath.Join(tmpDir, "probed_tmp_scrap.txt")
	if _, err := os.Stat(probedFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No probed_tmp_scrap.txt; sub_analytics skipped")
		return nil
	}

	probedIn, err := os.Open(probedFile)
	if err != nil {
		return fmt.Errorf("open probed file: %w", err)
	}
	defer probedIn.Close()

	scan.Logger.Info().Msg("Running analyticsrelationships subdomain enumeration")

	result, err := scan.Runner.Run(ctx, "analyticsrelationships", []string{"-ch"},
		runner.RunOpts{
			Timeout: 2 * time.Minute,
			Stdin:   probedIn,
		})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("analyticsrelationships failed (non-fatal)")
		return nil
	}

	var subs []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "|__ ")
		if line == "" || !strings.Contains(line, ".") {
			continue
		}
		if strings.Contains(line, scan.Target) {
			subs = append(subs, line)
		}
	}

	if len(subs) > 0 {
		outFile := filepath.Join(subsDir, "analytics_subs.txt")
		writeLines(outFile, subs)
		added := scan.Results.AddSubdomains(subs)
		scan.Logger.Info().Int("found", len(subs)).Int("new", added).Msg("sub_analytics complete")
	}
	return nil
}
