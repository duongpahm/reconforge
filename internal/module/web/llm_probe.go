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

// LLMProbe probes live web services for LLM-related providers and endpoints.
type LLMProbe struct{}

func (m *LLMProbe) Name() string            { return "llm_probe" }
func (m *LLMProbe) Description() string     { return "Probe web services for LLM provider exposure" }
func (m *LLMProbe) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *LLMProbe) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *LLMProbe) RequiredTools() []string { return []string{"julius"} }

func (m *LLMProbe) Validate(cfg *config.Config) error {
	if !cfg.Web.LLMProbe {
		return fmt.Errorf("llm_probe disabled")
	}
	return nil
}

func (m *LLMProbe) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}
	inputFile := filepath.Join(webDir, "webs_all.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No webs_all input for llm_probe; skipping")
		return nil
	}

	result, err := scan.Runner.Run(ctx, "julius", []string{"-o", "jsonl", "-q", "probe", "-f", inputFile}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("julius llm_probe failed")
		return nil
	}

	jsonlFile := filepath.Join(webDir, "llm_probe.jsonl")
	if err := os.WriteFile(jsonlFile, result.Stdout, 0o644); err != nil {
		return fmt.Errorf("write llm_probe jsonl: %w", err)
	}
	summary, findings := parseLLMProbeOutput(result.Stdout)
	if len(summary) > 0 {
		if err := writeLines(filepath.Join(webDir, "llm_probe.txt"), summary); err != nil {
			return fmt.Errorf("write llm_probe summary: %w", err)
		}
		scan.Results.AddFindings(findings)
	}
	scan.Logger.Info().Int("matches", len(summary)).Msg("llm_probe complete")
	return nil
}

func parseLLMProbeOutput(raw []byte) ([]string, []module.Finding) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	var summary []string
	var findings []module.Finding
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		target := firstJSONString(obj, "target", "url")
		provider := firstJSONString(obj, "provider", "service")
		probe := firstJSONString(obj, "probe")
		if target == "" {
			target = "unknown"
		}
		if provider == "" {
			provider = "unknown"
		}
		if probe == "" {
			probe = "n/a"
		}
		summary = append(summary, fmt.Sprintf("%s [%s] [%s]", target, provider, probe))
		findings = append(findings, module.Finding{Module: "llm_probe", Type: "info", Severity: "info", Target: target, Detail: fmt.Sprintf("LLM probe match: %s %s", provider, probe)})
	}
	return summary, findings
}

func firstJSONString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := obj[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var _ module.Module = (*LLMProbe)(nil)
