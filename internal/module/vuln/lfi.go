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

// LFICheck tests for Local File Inclusion vulnerabilities using ffuf with qsreplace.
// Requires gf/lfi.txt to be populated by the url_gf module.
type LFICheck struct{}

func (m *LFICheck) Name() string          { return "lfi_check" }
func (m *LFICheck) Description() string   { return "Local File Inclusion testing via ffuf + qsreplace" }
func (m *LFICheck) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *LFICheck) Dependencies() []string { return []string{"url_gf"} }
func (m *LFICheck) RequiredTools() []string { return []string{"ffuf", "qsreplace"} }

func (m *LFICheck) Validate(cfg *config.Config) error {
	if !cfg.Vuln.LFI {
		return fmt.Errorf("LFI checks disabled")
	}
	return nil
}

func (m *LFICheck) Run(ctx context.Context, scan *module.ScanContext) error {
	gfDir := filepath.Join(scan.OutputDir, "gf")
	vulnsDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	lfiURLs := filepath.Join(gfDir, "lfi.txt")
	if _, err := os.Stat(lfiURLs); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No gf/lfi.txt found; LFI check skipped")
		return nil
	}

	urls, err := readLines(lfiURLs)
	if err != nil || len(urls) == 0 {
		scan.Logger.Info().Msg("gf/lfi.txt is empty; LFI check skipped")
		return nil
	}

	// Respect deep mode limit
	if !scan.Config.General.Deep && len(urls) > 500 {
		scan.Logger.Warn().Int("urls", len(urls)).Msg("Too many LFI URLs; skipping (use deep mode)")
		return nil
	}

	// qsreplace to inject FUZZ into query params
	tmpLFI := filepath.Join(tmpDir, "tmp_lfi.txt")
	var fuzzURLs []string
	for _, u := range urls {
		// Simple FUZZ replacement: replace each query param value
		if strings.Contains(u, "=") {
			fuzzURLs = append(fuzzURLs, replaceFUZZ(u))
		}
	}
	if len(fuzzURLs) == 0 {
		scan.Logger.Info().Msg("No LFI URLs with query params; skipping")
		return nil
	}
	if err := writeLines(tmpLFI, fuzzURLs); err != nil {
		return fmt.Errorf("write LFI URLs: %w", err)
	}

	wordlist := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "lfi.txt")
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		scan.Logger.Warn().Str("wordlist", wordlist).Msg("LFI wordlist not found; skipping")
		return nil
	}

	scan.Logger.Info().Int("urls", len(fuzzURLs)).Msg("Running ffuf LFI scan")

	outFile := filepath.Join(vulnsDir, "lfi.txt")
	result, err := scan.Runner.Run(ctx, "ffuf", []string{
		"-v",
		"-r",
		"-t", "40",
		"-w", wordlist,
		"-input-file", tmpLFI,
		"-input-mode", "clusterbomb",
		"-mr", "root:",
		"-o", outFile,
		"-of", "json",
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("ffuf LFI scan failed (non-fatal)")
		return nil
	}

	// Parse ffuf JSON output for findings
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.Contains(line, "| URL |") {
			parts := strings.Split(line, "|")
			if len(parts) > 3 {
				url := strings.TrimSpace(parts[3])
				if url != "" {
					scan.Results.AddFindings([]module.Finding{{
						Module:   "lfi_check",
						Type:     "vuln",
						Severity: "high",
						Target:   url,
						Detail:   "LFI via ffuf",
					}})
				}
			}
		}
	}

	scan.Logger.Info().Msg("LFI check complete")
	return nil
}

// replaceFUZZ replaces query param values with FUZZ placeholder.
func replaceFUZZ(u string) string {
	qIdx := strings.Index(u, "?")
	if qIdx < 0 {
		return u
	}
	base := u[:qIdx+1]
	query := u[qIdx+1:]
	var parts []string
	for _, param := range strings.Split(query, "&") {
		eqIdx := strings.Index(param, "=")
		if eqIdx >= 0 {
			parts = append(parts, param[:eqIdx+1]+"FUZZ")
		} else {
			parts = append(parts, param)
		}
	}
	return base + strings.Join(parts, "&")
}
