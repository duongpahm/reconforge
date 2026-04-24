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

// NucleiDAST runs nuclei DAST templates against collected URLs and web targets.
type NucleiDAST struct{}

func (m *NucleiDAST) Name() string           { return "nuclei_dast" }
func (m *NucleiDAST) Description() string    { return "Nuclei DAST vulnerability scanning" }
func (m *NucleiDAST) Phase() engine.Phase    { return engine.PhaseVuln }
func (m *NucleiDAST) Dependencies() []string { return []string{"url_checks"} }
func (m *NucleiDAST) RequiredTools() []string { return []string{"nuclei"} }

func (m *NucleiDAST) Validate(cfg *config.Config) error {
	if !cfg.Vuln.NucleiDAST {
		return fmt.Errorf("nuclei_dast disabled")
	}
	return nil
}

func (m *NucleiDAST) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	nucleiDir := filepath.Join(scan.OutputDir, "nuclei_output")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	for _, d := range []string{vulnsDir, nucleiDir, tmpDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	// Collect DAST targets: webs_all.txt + url_extract_nodupes.txt
	targetsFile := filepath.Join(tmpDir, "nuclei_dast_targets.txt")
	var targets []string
	for _, src := range []string{
		filepath.Join(websDir, "webs_all.txt"),
		filepath.Join(websDir, "url_extract_nodupes.txt"),
	} {
		if lines, err := readLines(src); err == nil {
			for _, l := range lines {
				if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
					targets = append(targets, l)
				}
			}
		}
	}
	// Also add GF pattern URLs
	gfDir := filepath.Join(scan.OutputDir, "gf")
	for _, pat := range []string{"xss", "sqli", "ssrf", "ssti", "lfi", "rce"} {
		if lines, err := readLines(filepath.Join(gfDir, pat+".txt")); err == nil {
			targets = append(targets, lines...)
		}
	}

	if len(targets) == 0 {
		scan.Logger.Info().Msg("No DAST targets available; nuclei_dast skipped")
		return nil
	}

	if !scan.Config.General.Deep && len(targets) > 1500 {
		scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many DAST targets; skipping (use deep mode)")
		return nil
	}

	if err := writeLines(targetsFile, targets); err != nil {
		return fmt.Errorf("write dast targets: %w", err)
	}

	templatesDir := filepath.Join(scan.Config.General.ToolsDir, "nuclei-templates", "dast")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		scan.Logger.Warn().Str("path", templatesDir).Msg("Nuclei DAST templates not found; skipping nuclei_dast")
		return nil
	}

	rawJSON := filepath.Join(tmpDir, "nuclei_dast_json_raw.txt")
	scan.Logger.Info().Int("targets", len(targets)).Msg("Running nuclei DAST scan")

	_, err := scan.Runner.Run(ctx, "nuclei", []string{
		"-l", targetsFile,
		"-dast",
		"-nh",
		"-silent",
		"-retries", "2",
		"-t", templatesDir,
		"-j",
		"-o", rawJSON,
	}, runner.RunOpts{Timeout: 120 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("nuclei DAST failed (non-fatal)")
		return nil
	}

	data, err := os.ReadFile(rawJSON)
	if err != nil || len(data) == 0 {
		return nil
	}

	dastJSON := filepath.Join(nucleiDir, "dast_json.txt")
	os.WriteFile(dastJSON, data, 0o644)

	outFile := filepath.Join(vulnsDir, "nuclei_dast.txt")
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
		formatted := fmt.Sprintf("[%s] [%s] %s", templateID, severity, target)
		lines = append(lines, formatted)
		scan.Results.AddFindings([]module.Finding{{
			Module:   "nuclei_dast",
			Type:     "vuln",
			Severity: severity,
			Target:   target,
			Detail:   templateID,
		}})
	}

	if len(lines) > 0 {
		writeLines(outFile, lines)
		scan.Logger.Info().Int("vulnerabilities", len(lines)).Msg("nuclei_dast complete")
	}
	return nil
}
