package vuln

import (
	"context"
	"encoding/json"
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

// SSTICheck tests for Server-Side Template Injection using TInjA.
// Requires gf/ssti.txt from the url_gf module.
type SSTICheck struct{}

func (m *SSTICheck) Name() string          { return "ssti_check" }
func (m *SSTICheck) Description() string   { return "Server-Side Template Injection testing via TInjA" }
func (m *SSTICheck) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *SSTICheck) Dependencies() []string { return []string{"url_gf"} }
func (m *SSTICheck) RequiredTools() []string { return []string{"TInjA"} }

func (m *SSTICheck) Validate(cfg *config.Config) error {
	if !cfg.Vuln.SSTI {
		return fmt.Errorf("SSTI checks disabled")
	}
	return nil
}

func (m *SSTICheck) Run(ctx context.Context, scan *module.ScanContext) error {
	gfDir := filepath.Join(scan.OutputDir, "gf")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp", "TInjA")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create TInjA tmp dir: %w", err)
	}

	sstiURLs := filepath.Join(gfDir, "ssti.txt")
	if _, err := os.Stat(sstiURLs); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No gf/ssti.txt; SSTI check skipped")
		return nil
	}

	urls, err := readLines(sstiURLs)
	if err != nil || len(urls) == 0 {
		scan.Logger.Info().Msg("gf/ssti.txt is empty; SSTI check skipped")
		return nil
	}

	// Generate FUZZ URLs and write temp file
	tmpSSTI := filepath.Join(scan.OutputDir, ".tmp", "tmp_ssti.txt")
	var fuzzURLs []string
	for _, u := range urls {
		if strings.Contains(u, "=") {
			fuzzURLs = append(fuzzURLs, replaceFUZZ(u))
		}
	}
	if len(fuzzURLs) == 0 {
		scan.Logger.Info().Msg("No SSTI URLs with params; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(fuzzURLs) > 500 {
		scan.Logger.Warn().Int("urls", len(fuzzURLs)).Msg("Too many SSTI URLs; skipping (use deep mode)")
		return nil
	}

	if err := writeLines(tmpSSTI, fuzzURLs); err != nil {
		return fmt.Errorf("write SSTI URLs: %w", err)
	}

	scan.Logger.Info().Int("urls", len(fuzzURLs)).Msg("Running TInjA SSTI scan")

	// Build TInjA command with all URLs
	args := []string{
		"url",
		"--reportpath", tmpDir + "/",
		"--ratelimit", "0",
		"--timeout", "15",
		"--verbosity", "0",
	}
	for _, u := range fuzzURLs {
		args = append(args, "--url", u)
	}

	_, err = scan.Runner.Run(ctx, "TInjA", args, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("TInjA failed (non-fatal)")
		return nil
	}

	// Parse TInjA JSONL report
	var findings []string
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tmpDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				continue
			}
			vuln, _ := obj["isWebpageVulnerable"].(bool)
			if !vuln {
				continue
			}
			url, _ := obj["url"].(string)
			certainty, _ := obj["certainty"].(string)
			if url != "" {
				findings = append(findings, url+" [certainty:"+certainty+"]")
				scan.Results.AddFindings([]module.Finding{{
					Module:   "ssti_check",
					Type:     "vuln",
					Severity: "high",
					Target:   url,
					Detail:   "SSTI certainty:" + certainty,
				}})
			}
		}
	}

	if len(findings) > 0 {
		outFile := filepath.Join(vulnsDir, "ssti.txt")
		writeLines(outFile, findings)
		scan.Logger.Info().Int("vulnerabilities", len(findings)).Msg("SSTI check complete")
	}
	return nil
}
