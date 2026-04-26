package vuln

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

// CommandInjection tests for OS command injection using commix.
// Requires gf/rce.txt from the url_gf module.
type CommandInjection struct{}

func (m *CommandInjection) Name() string          { return "command_injection" }
func (m *CommandInjection) Description() string   { return "OS command injection testing via commix" }
func (m *CommandInjection) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *CommandInjection) Dependencies() []string { return []string{"url_gf"} }
func (m *CommandInjection) RequiredTools() []string { return []string{"commix"} }

func (m *CommandInjection) Validate(cfg *config.Config) error {
	if !cfg.Vuln.CommandInjection {
		return fmt.Errorf("command injection checks disabled")
	}
	return nil
}

func (m *CommandInjection) Run(ctx context.Context, scan *module.ScanContext) error {
	gfDir := filepath.Join(scan.OutputDir, "gf")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns", "command_injection")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create cmdinj output dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	rceURLs := filepath.Join(gfDir, "rce.txt")
	if _, err := os.Stat(rceURLs); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No gf/rce.txt; command injection check skipped")
		return nil
	}

	urls, err := readLines(rceURLs)
	if err != nil || len(urls) == 0 {
		scan.Logger.Info().Msg("gf/rce.txt is empty; command injection check skipped")
		return nil
	}

	// FUZZ replacement
	var fuzzURLs []string
	for _, u := range urls {
		if strings.Contains(u, "=") {
			fuzzURLs = append(fuzzURLs, replaceFUZZ(u))
		}
	}
	if len(fuzzURLs) == 0 {
		scan.Logger.Info().Msg("No RCE URLs with params; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(fuzzURLs) > 200 {
		scan.Logger.Warn().Int("urls", len(fuzzURLs)).Msg("Too many RCE URLs; skipping (use deep mode)")
		return nil
	}

	tmpRCE := filepath.Join(tmpDir, "tmp_rce.txt")
	if err := writeLines(tmpRCE, fuzzURLs); err != nil {
		return fmt.Errorf("write RCE URLs: %w", err)
	}

	scan.Logger.Info().Int("urls", len(fuzzURLs)).Msg("Running commix command injection scan")

	_, err = scan.Runner.Run(ctx, "commix", []string{
		"--batch",
		"-m", tmpRCE,
		"--output-dir", vulnsDir,
	}, runner.RunOpts{Timeout: 120 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("commix failed (non-fatal)")
		return nil
	}

	// Count findings from output directory
	entries, _ := os.ReadDir(vulnsDir)
	scan.Logger.Info().Int("output_files", len(entries)).Msg("Command injection check complete")
	return nil
}
