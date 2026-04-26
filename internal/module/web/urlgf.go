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

// gfPattern maps a GF pattern name to its output filename.
type gfPattern struct {
	name string
	file string
}

var gfPatterns = []gfPattern{
	{name: "xss", file: "xss.txt"},
	{name: "sqli", file: "sqli.txt"},
	{name: "ssrf", file: "ssrf.txt"},
	{name: "ssti", file: "ssti.txt"},
	{name: "lfi", file: "lfi.txt"},
	{name: "rce", file: "rce.txt"},
	{name: "redirect", file: "redirect.txt"},
	{name: "idor", file: "idor.txt"},
	{name: "debug_logic", file: "debug_logic.txt"},
}

// URLChecks collects URLs from katana and waymore for the target.
type URLChecks struct{}

func (m *URLChecks) Name() string            { return "url_checks" }
func (m *URLChecks) Description() string     { return "URL collection via katana and waymore" }
func (m *URLChecks) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *URLChecks) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *URLChecks) RequiredTools() []string { return []string{"katana"} }

func (m *URLChecks) Validate(cfg *config.Config) error {
	if !cfg.Web.URLChecks {
		return fmt.Errorf("URL checks disabled")
	}
	return nil
}

func (m *URLChecks) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		webs, _ := readLines(filepath.Join(websDir, "webs.txt"))
		websUncommon, _ := readLines(filepath.Join(websDir, "webs_uncommon_ports.txt"))
		targets = dedupLines(append(webs, websUncommon...))
		if len(targets) == 0 {
			targets = dedupLines(scan.Results.GetLiveHosts())
		}
		if len(targets) == 0 {
			scan.Logger.Warn().Msg("No web targets for URL collection; skipping")
			return nil
		}
		if err := writeLines(websAllFile, targets); err != nil {
			return fmt.Errorf("write webs_all: %w", err)
		}
	}

	var allURLs []string

	// katana crawl for URL extraction
	scan.Logger.Info().Int("targets", len(targets)).Msg("Running katana for URL extraction")
	katanaArgs := []string{
		"-list", websAllFile,
		"-d", "3",
		"-silent",
		"-jc",
		"-nc",
		"-kf", "all",
	}
	katanaResult, err := scan.Runner.Run(ctx, "katana", katanaArgs, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("katana URL extraction failed (non-fatal)")
	} else if katanaResult != nil {
		for _, line := range strings.Split(string(katanaResult.Stdout), "\n") {
			if u := strings.TrimSpace(line); u != "" {
				allURLs = append(allURLs, u)
			}
		}
	}

	// waymore for historical URLs
	waymoreResult, err := scan.Runner.Run(ctx, "waymore", []string{
		"-i", scan.Target,
		"-mode", "U",
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Debug().Err(err).Msg("waymore failed (non-fatal)")
	} else if waymoreResult != nil {
		for _, line := range strings.Split(string(waymoreResult.Stdout), "\n") {
			if u := strings.TrimSpace(line); u != "" {
				allURLs = append(allURLs, u)
			}
		}
	}

	allURLs = dedupLines(allURLs)

	if len(allURLs) == 0 {
		scan.Logger.Info().Msg("No URLs collected")
		return nil
	}

	urlFile := filepath.Join(websDir, "url_extract.txt")
	if err := writeLines(urlFile, allURLs); err != nil {
		return fmt.Errorf("write URL results: %w", err)
	}

	scan.Logger.Info().Int("urls", len(allURLs)).Msg("URL collection complete")
	return nil
}

// URLGF applies GF patterns to extracted URLs to categorize them by vulnerability type.
type URLGF struct{}

func (m *URLGF) Name() string            { return "url_gf" }
func (m *URLGF) Description() string     { return "URL categorization via GF pattern matching" }
func (m *URLGF) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *URLGF) Dependencies() []string  { return []string{"url_checks"} }
func (m *URLGF) RequiredTools() []string { return []string{"gf"} }

func (m *URLGF) Validate(cfg *config.Config) error {
	if !cfg.Web.URLGF {
		return fmt.Errorf("URL GF pattern matching disabled")
	}
	return nil
}

func (m *URLGF) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	gfDir := filepath.Join(scan.OutputDir, "gf")
	if err := os.MkdirAll(gfDir, 0o755); err != nil {
		return fmt.Errorf("create gf dir: %w", err)
	}

	urlFile := filepath.Join(websDir, "url_extract.txt")
	if _, err := os.Stat(urlFile); os.IsNotExist(err) {
		scan.Logger.Warn().Msg("No url_extract.txt for GF patterns; skipping")
		return nil
	}

	urlFH, err := os.Open(urlFile)
	if err != nil {
		return fmt.Errorf("open url file: %w", err)
	}
	defer urlFH.Close()

	scan.Logger.Info().Msg("Running GF pattern matching on extracted URLs")

	for _, pat := range gfPatterns {
		urlFH.Seek(0, 0)
		result, err := scan.Runner.Run(ctx, "gf", []string{pat.name}, runner.RunOpts{
			Timeout: 5 * time.Minute,
			Stdin:   urlFH,
		})
		if err != nil {
			scan.Logger.Debug().Err(err).Str("pattern", pat.name).Msg("gf pattern failed (non-fatal)")
			continue
		}

		var matches []string
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			if u := strings.TrimSpace(line); u != "" {
				matches = append(matches, u)
			}
		}
		if len(matches) > 0 {
			outFile := filepath.Join(gfDir, pat.file)
			if err := writeLines(outFile, matches); err != nil {
				scan.Logger.Warn().Err(err).Str("pattern", pat.name).Msg("failed to write GF results")
			}
			scan.Logger.Debug().Str("pattern", pat.name).Int("matches", len(matches)).Msg("GF pattern matched")
		}
	}

	scan.Logger.Info().Msg("GF pattern matching complete")
	return nil
}
