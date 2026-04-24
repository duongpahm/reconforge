package subdomain

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

// SourceScraping discovers subdomains by scraping URLs from various sources
// using urlfinder and waymore, then extracting domains.
type SourceScraping struct{}

func (m *SourceScraping) Name() string { return "source_scraping" }
func (m *SourceScraping) Description() string {
	return "Subdomain discovery via source code and URL scraping"
}
func (m *SourceScraping) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SourceScraping) Dependencies() []string  { return []string{"subfinder"} }
func (m *SourceScraping) RequiredTools() []string { return []string{"urlfinder"} }

func (m *SourceScraping) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Scraping {
		return fmt.Errorf("source scraping disabled")
	}
	return nil
}

func (m *SourceScraping) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create subdomains dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	var allURLs []string

	// Phase 1: urlfinder
	scan.Logger.Info().Str("target", scan.Target).Msg("Running urlfinder for source scraping")
	urlfinderOut := filepath.Join(tmpDir, "url_extract_tmp.txt")
	result, err := scan.Runner.Run(ctx, "urlfinder", []string{
		"-d", scan.Target,
		"-all",
		"-o", urlfinderOut,
	}, runner.RunOpts{Timeout: 15 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("urlfinder failed (non-fatal)")
	} else if result != nil {
		urls := extractURLDomains(string(result.Stdout), scan.Target)
		allURLs = append(allURLs, urls...)
	}

	// Phase 2: waymore (optional)
	waymoreOut := filepath.Join(tmpDir, "waymore_urls_subs.txt")
	waymoreResult, err := scan.Runner.Run(ctx, "waymore", []string{
		"-i", scan.Target,
		"-mode", "U",
		"-oU", waymoreOut,
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Debug().Err(err).Msg("waymore failed or not installed (non-fatal)")
	} else if waymoreResult != nil {
		urls := extractURLDomains(string(waymoreResult.Stdout), scan.Target)
		allURLs = append(allURLs, urls...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, d := range allURLs {
		d = strings.TrimSpace(d)
		if d != "" && !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}

	if len(unique) > 0 {
		outFile := filepath.Join(tmpDir, "scrap_subs.txt")
		if err := writeLines(outFile, unique); err != nil {
			return fmt.Errorf("write scraping results: %w", err)
		}
		scan.Results.AddSubdomains(unique)
		scan.Logger.Info().Int("found", len(unique)).Msg("Source scraping complete")
	}
	return nil
}

// extractURLDomains extracts domain names from a block of URLs that match the target domain.
func extractURLDomains(output, target string) []string {
	seen := make(map[string]bool)
	var domains []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, target) {
			continue
		}
		// Extract domain portion from URL
		domain := line
		for _, scheme := range []string{"https://", "http://"} {
			if idx := strings.Index(domain, scheme); idx >= 0 {
				domain = domain[idx+len(scheme):]
			}
		}
		// Strip path, port, query
		for _, sep := range []string{"/", ":", "?", "#"} {
			if idx := strings.Index(domain, sep); idx >= 0 {
				domain = domain[:idx]
			}
		}
		// Strip leading wildcard
		domain = strings.TrimPrefix(domain, "*.")
		domain = strings.TrimSpace(domain)
		if domain != "" && strings.HasSuffix(domain, target) && !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains
}
