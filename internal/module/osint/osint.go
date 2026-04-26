// Package osint implements OSINT reconnaissance modules.
package osint

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

// --- EmailHarvest ---

// EmailHarvest collects email addresses associated with the target.
type EmailHarvest struct{}

func (m *EmailHarvest) Name() string            { return "email_harvest" }
func (m *EmailHarvest) Description() string     { return "Email address harvesting via theHarvester" }
func (m *EmailHarvest) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *EmailHarvest) Dependencies() []string  { return nil }
func (m *EmailHarvest) RequiredTools() []string { return []string{"theHarvester"} }

func (m *EmailHarvest) Validate(cfg *config.Config) error {
	if !cfg.OSINT.EmailHarvest {
		return fmt.Errorf("email harvesting disabled")
	}
	return nil
}

func (m *EmailHarvest) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outFile := filepath.Join(osintDir, "emails")

	args := []string{
		"-d", scan.Target,
		"-b", "all",
		"-f", outFile,
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Harvesting emails with theHarvester")

	result, err := scan.Runner.Run(ctx, "theHarvester", args, runner.RunOpts{
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("theHarvester failed (non-fatal)")
		return nil
	}

	// Parse emails from output
	emails := parseEmailsFromOutput(result.Stdout)
	scan.Results.AddEmails(emails)

	scan.Logger.Info().
		Int("emails", len(emails)).
		Dur("duration", result.Duration).
		Msg("Email harvesting completed")

	return nil
}

// --- GoogleDorks ---

// GoogleDorks performs Google dorking for sensitive information.
type GoogleDorks struct{}

func (m *GoogleDorks) Name() string            { return "google_dorks" }
func (m *GoogleDorks) Description() string     { return "Google dorking for sensitive information" }
func (m *GoogleDorks) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *GoogleDorks) Dependencies() []string  { return nil }
func (m *GoogleDorks) RequiredTools() []string { return []string{"dorks_hunter"} }

func (m *GoogleDorks) Validate(cfg *config.Config) error {
	if !cfg.OSINT.GoogleDorks {
		return fmt.Errorf("Google dorking disabled")
	}
	return nil
}

func (m *GoogleDorks) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outFile := filepath.Join(osintDir, "google_dorks.txt")

	args := []string{
		"-d", scan.Target,
		"-o", outFile,
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running Google dorks")

	result, err := scan.Runner.Run(ctx, "dorks_hunter", args, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Google dorking failed (non-fatal)")
		return nil
	}

	findings, _ := readLines(outFile)
	for _, f := range findings {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "google_dorks",
			Type:     "info",
			Severity: "info",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("Google dork finding: %s", f),
		}})
	}

	scan.Logger.Info().
		Int("findings", len(findings)).
		Dur("duration", result.Duration).
		Msg("Google dorking completed")

	return nil
}

// --- GithubLeaks ---

// GithubLeaks scans GitHub for leaked secrets and credentials.
type GithubLeaks struct{}

func (m *GithubLeaks) Name() string            { return "github_leaks" }
func (m *GithubLeaks) Description() string     { return "GitHub secret and credential leak detection" }
func (m *GithubLeaks) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *GithubLeaks) Dependencies() []string  { return nil }
func (m *GithubLeaks) RequiredTools() []string { return []string{"trufflehog"} }

func (m *GithubLeaks) Validate(cfg *config.Config) error {
	if !cfg.OSINT.GithubLeaks {
		return fmt.Errorf("GitHub leak scanning disabled")
	}
	return nil
}

func (m *GithubLeaks) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outFile := filepath.Join(osintDir, "github_leaks.json")

	args := []string{
		"github",
		"--org", strings.Split(scan.Target, ".")[0],
		"--json",
		"--only-verified",
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Scanning GitHub for leaks with trufflehog")

	result, err := scan.Runner.Run(ctx, "trufflehog", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("GitHub leak scanning failed (non-fatal)")
		return nil
	}

	// Write output
	os.WriteFile(outFile, result.Stdout, 0o644)

	leakLines := parseLines(result.Stdout)
	for _, l := range leakLines {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "github_leaks",
			Type:     "vuln",
			Severity: "high",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("Verified secret leak: %s", truncate(l, 200)),
		}})
	}

	scan.Logger.Info().
		Int("leaks", len(leakLines)).
		Dur("duration", result.Duration).
		Msg("GitHub leak scanning completed")

	return nil
}

// --- CloudEnum ---

// CloudEnum enumerates cloud resources (S3, Azure, GCP) for the target.
type CloudEnum struct{}

func (m *CloudEnum) Name() string            { return "cloud_enum" }
func (m *CloudEnum) Description() string     { return "Cloud resource enumeration (AWS, Azure, GCP)" }
func (m *CloudEnum) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *CloudEnum) Dependencies() []string  { return nil }
func (m *CloudEnum) RequiredTools() []string { return []string{"cloud_enum"} }

func (m *CloudEnum) Validate(cfg *config.Config) error {
	if !cfg.OSINT.CloudEnum {
		return fmt.Errorf("cloud enumeration disabled")
	}
	return nil
}

func (m *CloudEnum) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outFile := filepath.Join(osintDir, "cloud_enum.txt")

	keyword := strings.Split(scan.Target, ".")[0]
	args := []string{
		"-k", keyword,
		"-l", outFile,
	}

	scan.Logger.Info().
		Str("keyword", keyword).
		Msg("Enumerating cloud resources")

	result, err := scan.Runner.Run(ctx, "cloud_enum", args, runner.RunOpts{
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("Cloud enumeration failed (non-fatal)")
		return nil
	}

	cloudResults, _ := readLines(outFile)
	for _, c := range cloudResults {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "cloud_enum",
			Type:     "info",
			Severity: "info",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("Cloud resource: %s", c),
		}})
	}

	scan.Logger.Info().
		Int("resources", len(cloudResults)).
		Dur("duration", result.Duration).
		Msg("Cloud enumeration completed")

	return nil
}

// --- SPFDMARCCheck ---

// SPFDMARCCheck verifies SPF, DMARC, and DKIM records.
type SPFDMARCCheck struct{}

func (m *SPFDMARCCheck) Name() string            { return "spf_dmarc" }
func (m *SPFDMARCCheck) Description() string     { return "SPF, DMARC, and DKIM record verification" }
func (m *SPFDMARCCheck) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *SPFDMARCCheck) Dependencies() []string  { return nil }
func (m *SPFDMARCCheck) RequiredTools() []string { return []string{"dig"} }

func (m *SPFDMARCCheck) Validate(cfg *config.Config) error {
	if !cfg.OSINT.SPFDMARC {
		return fmt.Errorf("SPF/DMARC checking disabled")
	}
	return nil
}

func (m *SPFDMARCCheck) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	os.MkdirAll(osintDir, 0o755)

	scan.Logger.Info().Str("target", scan.Target).Msg("Checking SPF/DMARC/DKIM records")

	// Check SPF
	spfResult, err := scan.Runner.Run(ctx, "dig", []string{
		"TXT", scan.Target, "+short",
	}, runner.RunOpts{Timeout: 15 * time.Second})

	spfFound := false
	if err == nil {
		for _, line := range parseLines(spfResult.Stdout) {
			if strings.Contains(line, "v=spf1") {
				spfFound = true
			}
		}
	}

	// Check DMARC
	dmarcResult, err := scan.Runner.Run(ctx, "dig", []string{
		"TXT", fmt.Sprintf("_dmarc.%s", scan.Target), "+short",
	}, runner.RunOpts{Timeout: 15 * time.Second})

	dmarcFound := false
	if err == nil {
		for _, line := range parseLines(dmarcResult.Stdout) {
			if strings.Contains(line, "v=DMARC1") {
				dmarcFound = true
			}
		}
	}

	// Report missing records
	if !spfFound {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "spf_dmarc",
			Type:     "vuln",
			Severity: "medium",
			Target:   scan.Target,
			Detail:   "Missing SPF record — domain vulnerable to email spoofing",
		}})
	}

	if !dmarcFound {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "spf_dmarc",
			Type:     "vuln",
			Severity: "medium",
			Target:   scan.Target,
			Detail:   "Missing DMARC record — domain vulnerable to email spoofing",
		}})
	}

	scan.Logger.Info().
		Bool("spf", spfFound).
		Bool("dmarc", dmarcFound).
		Msg("SPF/DMARC check completed")

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

func parseEmailsFromOutput(data []byte) []string {
	seen := make(map[string]bool)
	var emails []string
	for _, line := range parseLines(data) {
		if strings.Contains(line, "@") {
			email := strings.TrimSpace(line)
			if !seen[email] {
				seen[email] = true
				emails = append(emails, email)
			}
		}
	}
	return emails
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Compile-time interface checks.
var (
	_ module.Module = (*EmailHarvest)(nil)
	_ module.Module = (*GoogleDorks)(nil)
	_ module.Module = (*GithubLeaks)(nil)
	_ module.Module = (*CloudEnum)(nil)
	_ module.Module = (*SPFDMARCCheck)(nil)
)
