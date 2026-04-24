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

// HTTPSmuggling tests for HTTP request smuggling vulnerabilities using smugglex.
type HTTPSmuggling struct{}

func (m *HTTPSmuggling) Name() string          { return "http_smuggling" }
func (m *HTTPSmuggling) Description() string   { return "HTTP request smuggling detection via smugglex" }
func (m *HTTPSmuggling) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *HTTPSmuggling) Dependencies() []string { return []string{"httpx_probe"} }
func (m *HTTPSmuggling) RequiredTools() []string { return []string{"smugglex"} }

func (m *HTTPSmuggling) Validate(cfg *config.Config) error {
	if !cfg.Vuln.Smuggling {
		return fmt.Errorf("HTTP smuggling checks disabled")
	}
	return nil
}

func (m *HTTPSmuggling) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns", "smuggling")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create smuggling output dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Warn().Msg("No web targets for smuggling checks; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(targets) > 200 {
		scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many targets for smuggling; skipping (use deep mode)")
		return nil
	}

	websAllIn, err := os.Open(websAllFile)
	if err != nil {
		return fmt.Errorf("open webs_all: %w", err)
	}
	defer websAllIn.Close()

	tmpOut := filepath.Join(tmpDir, "smuggling.txt")

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running smugglex HTTP smuggling check")

	result, err := scan.Runner.Run(ctx, "smugglex", []string{
		"-f", "plain",
		"-o", tmpOut,
	}, runner.RunOpts{
		Timeout: 60 * time.Minute,
		Stdin:   websAllIn,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("smugglex failed (non-fatal)")
		return nil
	}

	// Parse JSONL output
	rawOutput := string(result.Stdout)
	if rawContent, err := os.ReadFile(tmpOut); err == nil {
		rawOutput = string(rawContent)
	}

	outFile := filepath.Join(vulnsDir, "smuggling.txt")
	var findings []string
	for _, line := range strings.Split(rawOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Validate as JSON then save
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			findings = append(findings, line)
			if url, ok := obj["url"].(string); ok {
				scan.Results.AddFindings([]module.Finding{{
					Module:   "http_smuggling",
					Type:     "vuln",
					Severity: "high",
					Target:   url,
					Detail:   "HTTP request smuggling via smugglex",
				}})
			}
		}
	}

	if len(findings) > 0 {
		writeLines(outFile, findings)
		scan.Logger.Info().Int("vulnerabilities", len(findings)).Msg("HTTP smuggling check complete")
	}
	return nil
}
