// Package vuln implements vulnerability scanning modules.
package vuln

import (
	"bufio"
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

// --- Nuclei ---

// Nuclei runs template-based vulnerability scanning.
type Nuclei struct{}

func (m *Nuclei) Name() string         { return "nuclei" }
func (m *Nuclei) Description() string   { return "Template-based vulnerability scanning via nuclei" }
func (m *Nuclei) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *Nuclei) Dependencies() []string { return nil }
func (m *Nuclei) RequiredTools() []string { return []string{"nuclei"} }

func (m *Nuclei) Validate(cfg *config.Config) error {
	if !cfg.Web.Nuclei {
		return fmt.Errorf("nuclei scanning disabled")
	}
	return nil
}

func (m *Nuclei) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	if err := os.MkdirAll(vulnDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	liveHosts := scan.Results.GetLiveHosts()
	if len(liveHosts) == 0 {
		scan.Logger.Info().Msg("No live hosts for nuclei, skipping")
		return nil
	}

	inputFile := filepath.Join(vulnDir, "nuclei_input.txt")
	writeLines(inputFile, liveHosts)

	outFile := filepath.Join(vulnDir, "nuclei_results.txt")
	jsonFile := filepath.Join(vulnDir, "nuclei_results.json")

	args := []string{
		"-l", inputFile,
		"-o", outFile,
		"-json-export", jsonFile,
		"-severity", "low,medium,high,critical",
		"-bulk-size", "25",
		"-c", "25",
		"-silent",
		"-stats",
	}

	if scan.Config.RateLimit.Nuclei > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", scan.Config.RateLimit.Nuclei))
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Msg("Running nuclei vulnerability scan")

	result, err := scan.Runner.Run(ctx, "nuclei", args, runner.RunOpts{
		Timeout: 120 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("nuclei: %w", err)
	}

	// Parse findings
	findings, _ := readLines(outFile)
	for _, f := range findings {
		severity := parseSeverity(f)
		scan.Results.AddFindings([]module.Finding{{
			Module:   "nuclei",
			Type:     "vuln",
			Severity: severity,
			Target:   scan.Target,
			Detail:   f,
		}})
	}

	scan.Logger.Info().
		Int("findings", len(findings)).
		Dur("duration", result.Duration).
		Msg("Nuclei scan completed")

	return nil
}

// --- DalfoxXSS ---

// DalfoxXSS scans for Cross-Site Scripting vulnerabilities.
type DalfoxXSS struct{}

func (m *DalfoxXSS) Name() string         { return "xss_scan" }
func (m *DalfoxXSS) Description() string   { return "XSS vulnerability scanning via dalfox" }
func (m *DalfoxXSS) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *DalfoxXSS) Dependencies() []string { return nil }
func (m *DalfoxXSS) RequiredTools() []string { return []string{"dalfox"} }

func (m *DalfoxXSS) Validate(cfg *config.Config) error {
	if !cfg.Vuln.XSS {
		return fmt.Errorf("XSS scanning disabled")
	}
	return nil
}

func (m *DalfoxXSS) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	os.MkdirAll(vulnDir, 0o755)

	urls := scan.Results.GetURLs()
	// Filter URLs with parameters
	var paramURLs []string
	for _, u := range urls {
		if strings.Contains(u, "=") {
			paramURLs = append(paramURLs, u)
		}
	}

	if len(paramURLs) == 0 {
		scan.Logger.Info().Msg("No URLs with parameters for XSS scanning, skipping")
		return nil
	}

	// Limit to avoid excessive scanning
	maxURLs := 200
	if len(paramURLs) > maxURLs {
		paramURLs = paramURLs[:maxURLs]
	}

	inputFile := filepath.Join(vulnDir, "xss_input.txt")
	writeLines(inputFile, paramURLs)
	outFile := filepath.Join(vulnDir, "xss_results.txt")

	args := []string{
		"file", inputFile,
		"-o", outFile,
		"--silence",
		"-w", "20",
	}

	scan.Logger.Info().
		Int("urls", len(paramURLs)).
		Msg("Scanning for XSS with dalfox")

	result, err := scan.Runner.Run(ctx, "dalfox", args, runner.RunOpts{
		Timeout: 45 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Dalfox failed (non-fatal)")
		return nil
	}

	xssResults, _ := readLines(outFile)
	for _, x := range xssResults {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "xss_scan",
			Type:     "vuln",
			Severity: "high",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("XSS: %s", x),
		}})
	}

	scan.Logger.Info().
		Int("tested", len(paramURLs)).
		Int("vulnerable", len(xssResults)).
		Dur("duration", result.Duration).
		Msg("XSS scanning completed")

	return nil
}

// --- SQLMapScan ---

// SQLMapScan scans for SQL injection vulnerabilities.
type SQLMapScan struct{}

func (m *SQLMapScan) Name() string         { return "sqli_scan" }
func (m *SQLMapScan) Description() string   { return "SQL injection scanning via sqlmap" }
func (m *SQLMapScan) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *SQLMapScan) Dependencies() []string { return nil }
func (m *SQLMapScan) RequiredTools() []string { return []string{"sqlmap"} }

func (m *SQLMapScan) Validate(cfg *config.Config) error {
	if !cfg.Vuln.SQLi {
		return fmt.Errorf("SQLi scanning disabled")
	}
	return nil
}

func (m *SQLMapScan) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	os.MkdirAll(vulnDir, 0o755)

	urls := scan.Results.GetURLs()
	var paramURLs []string
	for _, u := range urls {
		if strings.Contains(u, "=") {
			paramURLs = append(paramURLs, u)
		}
	}

	if len(paramURLs) == 0 {
		scan.Logger.Info().Msg("No URLs with parameters for SQLi scanning, skipping")
		return nil
	}

	maxURLs := 50
	if len(paramURLs) > maxURLs {
		paramURLs = paramURLs[:maxURLs]
	}

	inputFile := filepath.Join(vulnDir, "sqli_input.txt")
	writeLines(inputFile, paramURLs)
	outDir := filepath.Join(vulnDir, "sqlmap_output")

	args := []string{
		"-m", inputFile,
		"--batch",
		"--output-dir", outDir,
		"--level", "2",
		"--risk", "1",
		"--threads", "5",
		"--random-agent",
	}

	scan.Logger.Info().
		Int("urls", len(paramURLs)).
		Msg("Scanning for SQLi with sqlmap")

	result, err := scan.Runner.Run(ctx, "sqlmap", args, runner.RunOpts{
		Timeout: 60 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("sqlmap failed (non-fatal)")
		return nil
	}

	// Check sqlmap output for findings
	sqliLines := parseLines(result.Stdout)
	vulnCount := 0
	for _, line := range sqliLines {
		if strings.Contains(line, "is vulnerable") || strings.Contains(line, "injectable") {
			vulnCount++
			scan.Results.AddFindings([]module.Finding{{
				Module:   "sqli_scan",
				Type:     "vuln",
				Severity: "critical",
				Target:   scan.Target,
				Detail:   fmt.Sprintf("SQLi: %s", truncate(line, 200)),
			}})
		}
	}

	scan.Logger.Info().
		Int("tested", len(paramURLs)).
		Int("vulnerable", vulnCount).
		Dur("duration", result.Duration).
		Msg("SQLi scanning completed")

	return nil
}

// --- SSRFScanner ---

// SSRFScanner tests for Server-Side Request Forgery.
type SSRFScanner struct{}

func (m *SSRFScanner) Name() string         { return "ssrf_scan" }
func (m *SSRFScanner) Description() string   { return "SSRF vulnerability detection" }
func (m *SSRFScanner) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *SSRFScanner) Dependencies() []string { return nil }
func (m *SSRFScanner) RequiredTools() []string { return []string{"nuclei"} }

func (m *SSRFScanner) Validate(cfg *config.Config) error {
	if !cfg.Vuln.SSRF {
		return fmt.Errorf("SSRF scanning disabled")
	}
	return nil
}

func (m *SSRFScanner) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	os.MkdirAll(vulnDir, 0o755)

	liveHosts := scan.Results.GetLiveHosts()
	if len(liveHosts) == 0 {
		return nil
	}

	inputFile := filepath.Join(vulnDir, "ssrf_input.txt")
	writeLines(inputFile, liveHosts)
	outFile := filepath.Join(vulnDir, "ssrf_results.txt")

	args := []string{
		"-l", inputFile,
		"-o", outFile,
		"-tags", "ssrf",
		"-severity", "medium,high,critical",
		"-silent",
	}

	scan.Logger.Info().
		Int("hosts", len(liveHosts)).
		Msg("Scanning for SSRF with nuclei templates")

	result, err := scan.Runner.Run(ctx, "nuclei", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("SSRF scanning failed (non-fatal)")
		return nil
	}

	findings, _ := readLines(outFile)
	for _, f := range findings {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "ssrf_scan",
			Type:     "vuln",
			Severity: "high",
			Target:   scan.Target,
			Detail:   f,
		}})
	}

	scan.Logger.Info().
		Int("findings", len(findings)).
		Dur("duration", result.Duration).
		Msg("SSRF scanning completed")

	return nil
}

// --- SSLAudit ---

// SSLAudit checks for SSL/TLS misconfigurations.
type SSLAudit struct{}

func (m *SSLAudit) Name() string         { return "ssl_audit" }
func (m *SSLAudit) Description() string   { return "SSL/TLS configuration audit via testssl" }
func (m *SSLAudit) Phase() engine.Phase   { return engine.PhaseVuln }
func (m *SSLAudit) Dependencies() []string { return nil }
func (m *SSLAudit) RequiredTools() []string { return []string{"testssl.sh"} }

func (m *SSLAudit) Validate(cfg *config.Config) error {
	if !cfg.Vuln.SSL {
		return fmt.Errorf("SSL audit disabled")
	}
	return nil
}

func (m *SSLAudit) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	os.MkdirAll(vulnDir, 0o755)

	outFile := filepath.Join(vulnDir, "ssl_audit.json")

	args := []string{
		"--jsonfile", outFile,
		"--severity", "LOW",
		"--quiet",
		scan.Target,
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Auditing SSL/TLS with testssl")

	result, err := scan.Runner.Run(ctx, "testssl.sh", args, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("SSL audit failed (non-fatal)")
		return nil
	}

	// Parse stdout for issues
	sslLines := parseLines(result.Stdout)
	issueCount := 0
	for _, line := range sslLines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "not ok") {
			issueCount++
			scan.Results.AddFindings([]module.Finding{{
				Module:   "ssl_audit",
				Type:     "vuln",
				Severity: "medium",
				Target:   scan.Target,
				Detail:   fmt.Sprintf("SSL issue: %s", truncate(line, 200)),
			}})
		}
	}

	scan.Logger.Info().
		Int("issues", issueCount).
		Dur("duration", result.Duration).
		Msg("SSL audit completed")

	return nil
}

// --- Helpers ---

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func parseLines(data []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func parseSeverity(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "[critical]"):
		return "critical"
	case strings.Contains(lower, "[high]"):
		return "high"
	case strings.Contains(lower, "[medium]"):
		return "medium"
	case strings.Contains(lower, "[low]"):
		return "low"
	default:
		return "info"
	}
}

// Compile-time interface checks.
var (
	_ module.Module = (*Nuclei)(nil)
	_ module.Module = (*DalfoxXSS)(nil)
	_ module.Module = (*SQLMapScan)(nil)
	_ module.Module = (*SSRFScanner)(nil)
	_ module.Module = (*SSLAudit)(nil)
)
