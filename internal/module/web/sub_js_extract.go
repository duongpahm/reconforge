package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// SubJSExtract extracts subdomains from JS source files.
type SubJSExtract struct{}

func (m *SubJSExtract) Name() string            { return "sub_js_extract" }
func (m *SubJSExtract) Description() string     { return "Extract subdomains from JS files" }
func (m *SubJSExtract) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *SubJSExtract) Dependencies() []string  { return []string{"jschecks"} }
func (m *SubJSExtract) RequiredTools() []string { return []string{"httpx"} }

func (m *SubJSExtract) Validate(cfg *config.Config) error {
	if !cfg.Web.SubJSExtract {
		return fmt.Errorf("sub_js_extract disabled")
	}
	return nil
}

func (m *SubJSExtract) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "js")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	jsLinksFile := filepath.Join(outDir, "js_links.txt")
	if _, err := os.Stat(jsLinksFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No JS links found; skipping sub_js_extract")
		return nil
	}

	scan.Logger.Info().Msg("Extracting subdomains from JS files...")

	// Use httpx to fetch the JS contents
	result, err := scan.Runner.Run(ctx, "httpx", []string{
		"-l", jsLinksFile,
		"-sr", "-srd", filepath.Join(outDir, "js_sources"),
		"-silent",
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("httpx fetch for JS failed")
	}

	// We can parse the fetched bodies or just regex directly.
	// Actually, doing a regex search across the downloaded directory is fast in Go.
	jsSourceDir := filepath.Join(outDir, "js_sources")

	// Create a regex to find subdomains of the target
	// Escape the target domain for regex
	escapedTarget := regexp.QuoteMeta(scan.Target)
	subdomainRegex := regexp.MustCompile(`(?i)[a-zA-Z0-9.-]+\.` + escapedTarget)

	subdomains := make(map[string]struct{})

	if _, err := os.Stat(jsSourceDir); err == nil {
		filepath.Walk(jsSourceDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			content, err := os.ReadFile(path)
			if err == nil {
				matches := subdomainRegex.FindAllString(string(content), -1)
				for _, match := range matches {
					subdomains[strings.ToLower(match)] = struct{}{}
				}
			}
			return nil
		})
	}

	// Also parse httpx output if any JS source was embedded
	matches := subdomainRegex.FindAllString(string(result.Stdout), -1)
	for _, match := range matches {
		subdomains[strings.ToLower(match)] = struct{}{}
	}

	if len(subdomains) == 0 {
		scan.Logger.Info().Msg("No subdomains found in JS files")
		return nil
	}

	outputFile := filepath.Join(outDir, "js_subdomains.txt")
	var subsList []string
	for sub := range subdomains {
		subsList = append(subsList, sub)
		scan.Results.AddFindings([]module.Finding{{
			Module:   m.Name(),
			Type:     "subdomain",
			Severity: "info",
			Target:   sub,
			Detail:   "Extracted from JS file",
		}})
	}

	if err := writeLines(outputFile, subsList); err != nil {
		return fmt.Errorf("write js subdomains: %w", err)
	}

	scan.Logger.Info().Int("count", len(subsList)).Msg("sub_js_extract complete")
	return nil
}
