package vuln

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

// Bypass4xx attempts to bypass 403/4xx HTTP responses using nomore403.
// Requires fuzzing/fuzzing_full.txt from web_fuzz module.
type Bypass4xx struct{}

func (m *Bypass4xx) Name() string          { return "bypass_4xx" }
func (m *Bypass4xx) Description() string   { return "4xx status code bypass via nomore403" }
func (m *Bypass4xx) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *Bypass4xx) Dependencies() []string { return []string{"web_fuzz"} }
func (m *Bypass4xx) RequiredTools() []string { return []string{"nomore403"} }

func (m *Bypass4xx) Validate(cfg *config.Config) error {
	if !cfg.Vuln.Bypass4xx {
		return fmt.Errorf("4xx bypass disabled")
	}
	return nil
}

func (m *Bypass4xx) Run(ctx context.Context, scan *module.ScanContext) error {
	fuzzingDir := filepath.Join(scan.OutputDir, "fuzzing")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// Extract 4xx (non-404) URLs from fuzzing results
	fuzzFull := filepath.Join(fuzzingDir, "fuzzing_full.txt")
	if _, err := os.Stat(fuzzFull); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No fuzzing results for 4xx bypass; skipping")
		return nil
	}

	lines, err := readLines(fuzzFull)
	if err != nil || len(lines) == 0 {
		scan.Logger.Info().Msg("Empty fuzzing results; skipping 4xx bypass")
		return nil
	}

	// Filter: lines starting with 4xx but not 404, extract URL (field 3)
	var bypassTargets []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "4") || strings.HasPrefix(line, "404") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			bypassTargets = append(bypassTargets, fields[2])
		}
	}

	if len(bypassTargets) == 0 {
		scan.Logger.Info().Msg("No 4xx targets found for bypass; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(bypassTargets) > 200 {
		scan.Logger.Warn().Int("targets", len(bypassTargets)).Msg("Too many 4xx targets; skipping (use deep mode)")
		return nil
	}

	tmp403 := filepath.Join(tmpDir, "403test.txt")
	if err := writeLines(tmp403, bypassTargets); err != nil {
		return fmt.Errorf("write 4xx targets: %w", err)
	}

	scan.Logger.Info().Int("targets", len(bypassTargets)).Msg("Running nomore403 bypass")

	tmp403In, err := os.Open(tmp403)
	if err != nil {
		return fmt.Errorf("open 403 targets: %w", err)
	}
	defer tmp403In.Close()

	result, err := scan.Runner.Run(ctx, "nomore403", []string{}, runner.RunOpts{
		Timeout: 30 * time.Minute,
		Stdin:   tmp403In,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("nomore403 failed (non-fatal)")
		return nil
	}

	if result != nil && len(result.Stdout) > 0 {
		outFile := filepath.Join(vulnsDir, "4xxbypass.txt")
		os.WriteFile(outFile, result.Stdout, 0o644)

		var found []string
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			if l := strings.TrimSpace(line); l != "" {
				found = append(found, l)
				scan.Results.AddFindings([]module.Finding{{
					Module:   "bypass_4xx",
					Type:     "vuln",
					Severity: "medium",
					Target:   l,
					Detail:   "4xx bypass via nomore403",
				}})
			}
		}
		scan.Logger.Info().Int("bypassed", len(found)).Msg("4xx bypass complete")
	}
	return nil
}
