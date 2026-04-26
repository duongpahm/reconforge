// Package web implements web probing, crawling, and analysis modules.
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

// --- HTTPXProbe ---

// HTTPXProbe discovers live web hosts using httpx.
type HTTPXProbe struct{}

func (m *HTTPXProbe) Name() string            { return "httpx_probe" }
func (m *HTTPXProbe) Description() string     { return "HTTP/HTTPS live host discovery via httpx" }
func (m *HTTPXProbe) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *HTTPXProbe) Dependencies() []string  { return nil } // first web module
func (m *HTTPXProbe) RequiredTools() []string { return []string{"httpx"} }

func (m *HTTPXProbe) Validate(cfg *config.Config) error {
	if !cfg.Web.Probe {
		return fmt.Errorf("web probing disabled")
	}
	return nil
}

func (m *HTTPXProbe) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Input: subdomains from previous phase
	subs := scan.Results.GetSubdomains()
	if len(subs) == 0 {
		scan.Logger.Info().Msg("No subdomains to probe, using target directly")
		subs = []string{scan.Target}
	}

	inputFile := filepath.Join(webDir, "probe_input.txt")
	writeLines(inputFile, subs)

	outFile := filepath.Join(webDir, "httpx_live.txt")
	jsonFile := filepath.Join(webDir, "httpx_full.json")

	ports := scan.Config.Web.Ports.Standard
	if scan.Config.General.Deep {
		ports = ports + "," + scan.Config.Web.Ports.Uncommon
	}

	args := []string{
		"-l", inputFile,
		"-o", outFile,
		"-json", "-output", jsonFile,
		"-ports", ports,
		"-status-code",
		"-title",
		"-tech-detect",
		"-content-length",
		"-follow-redirects",
		"-threads", "50",
		"-silent",
	}

	// Apply rate limit
	if scan.Config.RateLimit.HTTPX > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", scan.Config.RateLimit.HTTPX))
	}

	scan.Logger.Info().
		Int("targets", len(subs)).
		Str("ports", ports).
		Msg("Probing live web hosts with httpx")

	result, err := scan.Runner.Run(ctx, "httpx", args, runner.RunOpts{
		Timeout: 45 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("httpx: %w", err)
	}

	// Parse live hosts
	liveHosts, _ := readLines(outFile)
	scan.Results.AddLiveHosts(liveHosts)

	scan.Logger.Info().
		Int("input", len(subs)).
		Int("live", len(liveHosts)).
		Dur("duration", result.Duration).
		Msg("Web probing completed")

	return nil
}

// --- Screenshots ---

// Screenshots captures visual snapshots of live hosts using gowitness.
type Screenshots struct{}

func (m *Screenshots) Name() string            { return "screenshots" }
func (m *Screenshots) Description() string     { return "Web page screenshot capture via gowitness" }
func (m *Screenshots) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *Screenshots) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *Screenshots) RequiredTools() []string { return []string{"gowitness"} }

func (m *Screenshots) Validate(cfg *config.Config) error {
	if !cfg.Web.Screenshots {
		return fmt.Errorf("screenshots disabled")
	}
	return nil
}

func (m *Screenshots) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	screenshotDir := filepath.Join(webDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0o755); err != nil {
		return fmt.Errorf("create screenshot dir: %w", err)
	}

	liveHosts := scan.Results.GetLiveHosts()
	if len(liveHosts) == 0 {
		scan.Logger.Info().Msg("No live hosts for screenshots, skipping")
		return nil
	}

	inputFile := filepath.Join(webDir, "screenshot_input.txt")
	writeLines(inputFile, liveHosts)

	args := []string{
		"file",
		"-f", inputFile,
		"--screenshot-path", screenshotDir,
		"--threads", "10",
		"--timeout", "30",
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Msg("Capturing screenshots with gowitness")

	result, err := scan.Runner.Run(ctx, "gowitness", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("gowitness failed (non-fatal)")
		return nil
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Dur("duration", result.Duration).
		Msg("Screenshots completed")

	return nil
}

// --- Crawler ---

// Crawler discovers URLs and endpoints via katana.
type Crawler struct{}

func (m *Crawler) Name() string            { return "crawler" }
func (m *Crawler) Description() string     { return "URL and endpoint discovery via katana" }
func (m *Crawler) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *Crawler) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *Crawler) RequiredTools() []string { return []string{"katana"} }

func (m *Crawler) Validate(cfg *config.Config) error {
	if !cfg.Web.Crawl {
		return fmt.Errorf("crawling disabled")
	}
	return nil
}

func (m *Crawler) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	liveHosts := scan.Results.GetLiveHosts()
	if len(liveHosts) == 0 {
		return nil
	}

	inputFile := filepath.Join(webDir, "crawl_input.txt")
	writeLines(inputFile, liveHosts)

	outFile := filepath.Join(webDir, "crawled_urls.txt")

	depth := "3"
	if scan.Config.General.Deep {
		depth = "5"
	}

	args := []string{
		"-list", inputFile,
		"-o", outFile,
		"-d", depth,
		"-jc",        // JavaScript crawling
		"-kf", "all", // known files
		"-ef", "css,png,jpg,gif,svg,woff,woff2,ttf,eot,ico",
		"-c", "20",
		"-silent",
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Str("depth", depth).
		Msg("Crawling web pages with katana")

	result, err := scan.Runner.Run(ctx, "katana", args, runner.RunOpts{
		Timeout: 60 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("katana: %w", err)
	}

	urls, _ := readLines(outFile)
	scan.Results.AddURLs(urls)

	scan.Logger.Info().
		Int("urls_found", len(urls)).
		Dur("duration", result.Duration).
		Msg("Crawling completed")

	return nil
}

// --- JSAnalyzer ---

// JSAnalyzer extracts endpoints and secrets from JavaScript files.
type JSAnalyzer struct{}

func (m *JSAnalyzer) Name() string            { return "js_analysis" }
func (m *JSAnalyzer) Description() string     { return "JavaScript endpoint and secret extraction" }
func (m *JSAnalyzer) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *JSAnalyzer) Dependencies() []string  { return []string{"crawler"} }
func (m *JSAnalyzer) RequiredTools() []string { return []string{"katana"} }

func (m *JSAnalyzer) Validate(cfg *config.Config) error {
	if !cfg.Web.JSAnalysis {
		return fmt.Errorf("JS analysis disabled")
	}
	return nil
}

func (m *JSAnalyzer) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Filter JS URLs from crawled results
	allURLs := scan.Results.GetURLs()
	var jsURLs []string
	for _, u := range allURLs {
		if strings.HasSuffix(u, ".js") || strings.Contains(u, ".js?") {
			jsURLs = append(jsURLs, u)
		}
	}

	if len(jsURLs) == 0 {
		scan.Logger.Info().Msg("No JS files found, skipping analysis")
		return nil
	}

	jsFile := filepath.Join(webDir, "js_urls.txt")
	writeLines(jsFile, jsURLs)

	outFile := filepath.Join(webDir, "js_endpoints.txt")

	// Use katana passive mode for JS parsing
	args := []string{
		"-list", jsFile,
		"-o", outFile,
		"-passive",
		"-jc",
		"-silent",
	}

	scan.Logger.Info().
		Int("js_files", len(jsURLs)).
		Msg("Analyzing JavaScript files")

	result, err := scan.Runner.Run(ctx, "katana", args, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("JS analysis failed (non-fatal)")
		return nil
	}

	endpoints, _ := readLines(outFile)
	scan.Results.AddURLs(endpoints)

	// Check for exposed secrets in JS
	secretPatterns := []string{
		"api_key", "apikey", "secret", "token", "password",
		"aws_access", "private_key", "bearer",
	}
	var secretFindings []module.Finding
	for _, u := range jsURLs {
		for _, pattern := range secretPatterns {
			if strings.Contains(strings.ToLower(u), pattern) {
				secretFindings = append(secretFindings, module.Finding{
					Module:   "js_analysis",
					Type:     "info",
					Severity: "medium",
					Target:   u,
					Detail:   fmt.Sprintf("Potential secret exposure in JS: pattern '%s'", pattern),
				})
			}
		}
	}
	if len(secretFindings) > 0 {
		scan.Results.AddFindings(secretFindings)
	}

	scan.Logger.Info().
		Int("js_files", len(jsURLs)).
		Int("endpoints", len(endpoints)).
		Int("secrets", len(secretFindings)).
		Dur("duration", result.Duration).
		Msg("JS analysis completed")

	return nil
}

// --- WAFDetector ---

// WAFDetector identifies Web Application Firewalls.
type WAFDetector struct{}

func (m *WAFDetector) Name() string            { return "waf_detect" }
func (m *WAFDetector) Description() string     { return "Web Application Firewall detection via wafw00f" }
func (m *WAFDetector) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WAFDetector) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *WAFDetector) RequiredTools() []string { return []string{"wafw00f"} }

func (m *WAFDetector) Validate(cfg *config.Config) error {
	if !cfg.Web.WAFDetect {
		return fmt.Errorf("WAF detection disabled")
	}
	return nil
}

func (m *WAFDetector) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	liveHosts := scan.Results.GetLiveHosts()
	if len(liveHosts) == 0 {
		return nil
	}

	inputFile := filepath.Join(webDir, "waf_input.txt")
	writeLines(inputFile, liveHosts)
	outFile := filepath.Join(webDir, "waf_results.txt")

	args := []string{
		"-i", inputFile,
		"-o", outFile,
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Msg("Detecting WAFs with wafw00f")

	result, err := scan.Runner.Run(ctx, "wafw00f", args, runner.RunOpts{
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("WAF detection failed (non-fatal)")
		return nil
	}

	wafResults, _ := readLines(outFile)
	for _, w := range wafResults {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "waf_detect",
			Type:     "info",
			Severity: "info",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("WAF detected: %s", w),
		}})
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Int("waf_found", len(wafResults)).
		Dur("duration", result.Duration).
		Msg("WAF detection completed")

	return nil
}

// --- ParamDiscovery ---

// ParamDiscovery discovers URL parameters using arjun.
type ParamDiscovery struct{}

func (m *ParamDiscovery) Name() string            { return "param_discovery" }
func (m *ParamDiscovery) Description() string     { return "URL parameter discovery via arjun" }
func (m *ParamDiscovery) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *ParamDiscovery) Dependencies() []string  { return []string{"crawler"} }
func (m *ParamDiscovery) RequiredTools() []string { return []string{"arjun"} }

func (m *ParamDiscovery) Validate(cfg *config.Config) error {
	if !cfg.Web.ParamDiscovery {
		return fmt.Errorf("parameter discovery disabled")
	}
	return nil
}

func (m *ParamDiscovery) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	urls := scan.Results.GetURLs()
	if len(urls) == 0 {
		return nil
	}

	// Take a sample for param discovery (arjun is slow)
	maxURLs := 100
	if len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}

	inputFile := filepath.Join(webDir, "param_input.txt")
	writeLines(inputFile, urls)
	outFile := filepath.Join(webDir, "params.json")

	args := []string{
		"-i", inputFile,
		"-oJ", outFile,
		"-t", "10",
		"--stable",
	}

	scan.Logger.Info().
		Int("urls", len(urls)).
		Msg("Discovering parameters with arjun")

	result, err := scan.Runner.Run(ctx, "arjun", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Parameter discovery failed (non-fatal)")
		return nil
	}

	scan.Logger.Info().
		Int("urls", len(urls)).
		Dur("duration", result.Duration).
		Msg("Parameter discovery completed")

	return nil
}

// Compile-time interface checks.
var (
	_ module.Module = (*HTTPXProbe)(nil)
	_ module.Module = (*Screenshots)(nil)
	_ module.Module = (*Crawler)(nil)
	_ module.Module = (*JSAnalyzer)(nil)
	_ module.Module = (*WAFDetector)(nil)
	_ module.Module = (*ParamDiscovery)(nil)
)
