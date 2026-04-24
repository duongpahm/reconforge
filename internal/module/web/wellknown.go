package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// WellKnownPivots probes well-known files to extract endpoints and domains.
type WellKnownPivots struct{}

func (m *WellKnownPivots) Name() string            { return "wellknown_pivots" }
func (m *WellKnownPivots) Description() string     { return "Probe well-known files for new endpoints" }
func (m *WellKnownPivots) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WellKnownPivots) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *WellKnownPivots) RequiredTools() []string { return []string{"httpx"} } // Using httpx for bulk probing instead of curl

func (m *WellKnownPivots) Validate(cfg *config.Config) error {
	if !cfg.Web.WellKnownPivots {
		return fmt.Errorf("wellknown_pivots disabled")
	}
	return nil
}

func (m *WellKnownPivots) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "webs", "wellknown")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	inputFile := filepath.Join(scan.OutputDir, "webs", "webs_all.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No input for wellknown_pivots; skipping")
		return nil
	}

	scan.Logger.Info().Msg("Probing well-known paths...")

	paths := "/.well-known/security.txt,/.well-known/openid-configuration,/sitemap.xml,/robots.txt"
	outputFile := filepath.Join(outDir, "wellknown_responses.txt")

	result, err := scan.Runner.Run(ctx, "httpx", []string{
		"-l", inputFile,
		"-path", paths,
		"-mc", "200",
		"-o", outputFile,
		"-silent",
		"-sr", "-srd", outDir,
	}, runner.RunOpts{Timeout: 30 * time.Minute})

	if err != nil {
		scan.Logger.Warn().Err(err).Msg("httpx well-known failed")
		return nil
	}

	// Parse outputs for new endpoints or domains
	escapedTarget := regexp.QuoteMeta(scan.Target)
	endpointRegex := regexp.MustCompile(`(?i)(?:https?://|/)[a-zA-Z0-9./_-]+\.` + escapedTarget + `[a-zA-Z0-9./_-]*`)

	foundCount := 0
	if result.ExitCode == 0 {
		filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Only parse downloaded body files
			if strings.HasSuffix(path, ".txt") && path != outputFile {
				content, err := os.ReadFile(path)
				if err == nil {
					matches := endpointRegex.FindAllString(string(content), -1)
					for _, match := range matches {
						scan.Results.AddFindings([]module.Finding{{
							Module:   m.Name(),
							Type:     "url",
							Severity: "info",
							Target:   match,
							Detail:   "Extracted from well-known file",
						}})
						foundCount++
					}
				}
			}
			return nil
		})
	}

	scan.Logger.Info().Int("endpoints", foundCount).Msg("wellknown_pivots complete")
	return nil
}
