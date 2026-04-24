package vuln

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

// WebCache tests for web cache poisoning using Web-Cache-Vulnerability-Scanner and toxicache.
type WebCache struct{}

func (m *WebCache) Name() string           { return "webcache" }
func (m *WebCache) Description() string    { return "Web cache poisoning via Web-Cache-Vulnerability-Scanner" }
func (m *WebCache) Phase() engine.Phase    { return engine.PhaseVuln }
func (m *WebCache) Dependencies() []string { return []string{"httpx_probe"} }
func (m *WebCache) RequiredTools() []string { return []string{"Web-Cache-Vulnerability-Scanner"} }

func (m *WebCache) Validate(cfg *config.Config) error {
	if !cfg.Vuln.WebCache {
		return fmt.Errorf("webcache checks disabled")
	}
	return nil
}

func (m *WebCache) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Info().Msg("No web targets for webcache check; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(targets) > 200 {
		scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many targets for webcache; skipping (use deep mode)")
		return nil
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running Web-Cache-Vulnerability-Scanner")

	tmpOut := filepath.Join(tmpDir, "webcache.txt")
	_, err = scan.Runner.Run(ctx, "Web-Cache-Vulnerability-Scanner", []string{
		"-u", "file:" + websAllFile,
		"-v", "0",
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Web-Cache-Vulnerability-Scanner failed (non-fatal)")
	}

	outFile := filepath.Join(vulnsDir, "webcache.txt")
	if found, _ := readLines(tmpOut); len(found) > 0 {
		writeLines(outFile, found)
		for _, f := range found {
			scan.Results.AddFindings([]module.Finding{{
				Module:   "webcache",
				Type:     "vuln",
				Severity: "medium",
				Target:   f,
				Detail:   "Web cache poisoning",
			}})
		}
	}

	// toxicache as secondary engine
	toxOut := filepath.Join(tmpDir, "webcache_toxicache.txt")
	result, err := scan.Runner.Run(ctx, "toxicache", []string{
		"-i", websAllFile,
		"-o", toxOut,
		"-t", "70",
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err == nil && result != nil {
		toxicacheOut := filepath.Join(vulnsDir, "webcache_toxicache.txt")
		if toxLines, _ := readLines(toxOut); len(toxLines) > 0 {
			writeLines(toxicacheOut, toxLines)
			for _, line := range toxLines {
				if l := strings.TrimSpace(line); l != "" {
					scan.Results.AddFindings([]module.Finding{{
						Module:   "webcache",
						Type:     "vuln",
						Severity: "medium",
						Target:   l,
						Detail:   "Web cache poisoning via toxicache",
					}})
				}
			}
		}
	}

	scan.Logger.Info().Msg("webcache check complete")
	return nil
}
