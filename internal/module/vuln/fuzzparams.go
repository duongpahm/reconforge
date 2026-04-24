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

// FuzzParams tests URL parameters using nuclei DAST fuzzing templates.
type FuzzParams struct{}

func (m *FuzzParams) Name() string           { return "fuzzparams" }
func (m *FuzzParams) Description() string    { return "Parameter fuzzing via nuclei DAST templates" }
func (m *FuzzParams) Phase() engine.Phase    { return engine.PhaseVuln }
func (m *FuzzParams) Dependencies() []string { return []string{"url_checks"} }
func (m *FuzzParams) RequiredTools() []string { return []string{"nuclei"} }

func (m *FuzzParams) Validate(cfg *config.Config) error {
	if !cfg.Vuln.NucleiDAST {
		return fmt.Errorf("fuzzparams/nuclei_dast disabled")
	}
	return nil
}

func (m *FuzzParams) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	urlFile := filepath.Join(websDir, "url_extract_nodupes.txt")
	if _, err := os.Stat(urlFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No url_extract_nodupes.txt; fuzzparams skipped")
		return nil
	}

	urls, err := readLines(urlFile)
	if err != nil || len(urls) == 0 {
		scan.Logger.Info().Msg("Empty URL file; fuzzparams skipped")
		return nil
	}

	if !scan.Config.General.Deep && len(urls) > 500 {
		scan.Logger.Warn().Int("urls", len(urls)).Msg("Too many URLs for fuzzparams; skipping (use deep mode)")
		return nil
	}

	templatesDir := filepath.Join(scan.Config.General.ToolsDir, "nuclei-templates", "dast")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		scan.Logger.Warn().Str("path", templatesDir).Msg("Nuclei DAST templates not found; skipping fuzzparams")
		return nil
	}

	tmpJSON := filepath.Join(tmpDir, "fuzzparams_json.txt")
	scan.Logger.Info().Int("urls", len(urls)).Msg("Running nuclei DAST fuzzparams scan")

	_, err = scan.Runner.Run(ctx, "nuclei", []string{
		"-l", urlFile,
		"-nh",
		"-silent",
		"-retries", "2",
		"-t", templatesDir,
		"-dast",
		"-j",
		"-o", tmpJSON,
	}, runner.RunOpts{Timeout: 120 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("nuclei fuzzparams failed (non-fatal)")
		return nil
	}

	data, err := os.ReadFile(tmpJSON)
	if err != nil || len(data) == 0 {
		return nil
	}

	outFile := filepath.Join(vulnsDir, "fuzzparams.txt")
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if json.Unmarshal([]byte(line), &obj) != nil {
			continue
		}
		templateID, _ := obj["template-id"].(string)
		matchedAt, _ := obj["matched-at"].(string)
		host, _ := obj["host"].(string)
		target := matchedAt
		if target == "" {
			target = host
		}
		severity := "medium"
		if info, ok := obj["info"].(map[string]interface{}); ok {
			if sev, ok := info["severity"].(string); ok {
				severity = sev
			}
		}
		lines = append(lines, fmt.Sprintf("[%s] [%s] %s", templateID, severity, target))
		scan.Results.AddFindings([]module.Finding{{
			Module:   "fuzzparams",
			Type:     "vuln",
			Severity: severity,
			Target:   target,
			Detail:   templateID,
		}})
	}

	if len(lines) > 0 {
		writeLines(outFile, lines)
		scan.Logger.Info().Int("vulnerabilities", len(lines)).Msg("fuzzparams complete")
	}
	return nil
}
