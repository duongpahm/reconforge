package web

import (
	"bufio"
	"context"
	"encoding/json"
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

// NucleiCheck runs nuclei against discovered web targets and writes per-severity artifacts.
type NucleiCheck struct{}

func (m *NucleiCheck) Name() string            { return "nuclei_check" }
func (m *NucleiCheck) Description() string     { return "Nuclei web checks with per-severity outputs" }
func (m *NucleiCheck) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *NucleiCheck) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *NucleiCheck) RequiredTools() []string { return []string{"nuclei"} }

func (m *NucleiCheck) Validate(cfg *config.Config) error {
	if !cfg.Web.Nuclei {
		return fmt.Errorf("nuclei web checks disabled")
	}
	return nil
}

func (m *NucleiCheck) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	nucleiDir := filepath.Join(scan.OutputDir, "nuclei_output")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	for _, d := range []string{websDir, nucleiDir, tmpDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	if _, err := os.Stat(websAllFile); os.IsNotExist(err) {
		webs, _ := readLines(filepath.Join(websDir, "webs.txt"))
		websUncommon, _ := readLines(filepath.Join(websDir, "webs_uncommon_ports.txt"))
		all := dedupLines(append(webs, websUncommon...))
		if len(all) == 0 {
			all = dedupLines(scan.Results.GetLiveHosts())
		}
		if len(all) == 0 {
			scan.Logger.Info().Msg("No web targets for nuclei_check; skipping")
			return nil
		}
		if err := writeLines(websAllFile, all); err != nil {
			return fmt.Errorf("write webs_all: %w", err)
		}
	}

	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		targets = dedupLines(scan.Results.GetLiveHosts())
		if len(targets) == 0 {
			scan.Logger.Info().Msg("No web targets for nuclei_check; skipping")
			return nil
		}
		if err := writeLines(websAllFile, targets); err != nil {
			return fmt.Errorf("write webs_all: %w", err)
		}
	}

	if !scan.Config.General.Deep && len(targets) > 1500 {
		scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many web targets for nuclei_check; skipping (use deep mode)")
		return nil
	}

	rawJSON := filepath.Join(tmpDir, "nuclei_web_json_raw.txt")
	args := []string{
		"-l", websAllFile,
		"-j",
		"-silent",
		"-severity", "critical,high,medium,low,info",
		"-o", rawJSON,
	}
	if scan.Config.RateLimit.Nuclei > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", scan.Config.RateLimit.Nuclei))
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running nuclei_check")
	_, err = scan.Runner.Run(ctx, "nuclei", args, runner.RunOpts{Timeout: 120 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("nuclei_check failed (non-fatal)")
		return nil
	}

	fh, err := os.Open(rawJSON)
	if err != nil {
		scan.Logger.Debug().Err(err).Msg("No nuclei JSON output for nuclei_check")
		return nil
	}
	defer fh.Close()

	severityJSON := map[string][]string{
		"critical": {},
		"high":     {},
		"medium":   {},
		"low":      {},
		"info":     {},
	}
	severityText := map[string][]string{
		"critical": {},
		"high":     {},
		"medium":   {},
		"low":      {},
		"info":     {},
	}

	findings := make([]module.Finding, 0)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event nucleiCheckEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		severity := normalizeNucleiSeverity(event.Info.Severity)
		target := firstNonEmptyValue(event.MatchedAt, event.Host)
		templateID := strings.TrimSpace(event.TemplateID)
		if templateID == "" {
			templateID = "unknown-template"
		}
		if target == "" {
			continue
		}

		severityJSON[severity] = append(severityJSON[severity], line)
		severityText[severity] = append(severityText[severity], fmt.Sprintf("[%s] [%s] [web] %s", templateID, severity, target))
		findings = append(findings, module.Finding{
			Module:   "nuclei_check",
			Type:     "vuln",
			Severity: severity,
			Target:   target,
			Detail:   templateID,
		})
	}

	if err := scanner.Err(); err != nil {
		scan.Logger.Warn().Err(err).Msg("Failed reading nuclei_check output")
	}

	total := 0
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if lines := severityJSON[severity]; len(lines) > 0 {
			total += len(lines)
			_ = writeLines(filepath.Join(nucleiDir, severity+"_json.txt"), lines)
		}
		if lines := severityText[severity]; len(lines) > 0 {
			_ = writeLines(filepath.Join(nucleiDir, severity+".txt"), lines)
		}
	}

	if len(findings) > 0 {
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Int("findings", total).Msg("nuclei_check complete")
	return nil
}

type nucleiCheckEvent struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Severity string `json:"severity"`
	} `json:"info"`
}

func normalizeNucleiSeverity(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "info"
	}
}

func firstNonEmptyValue(values ...string) string {
	for _, v := range values {
		if vv := strings.TrimSpace(v); vv != "" {
			return vv
		}
	}
	return ""
}

var _ module.Module = (*NucleiCheck)(nil)
