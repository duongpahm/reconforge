package osint

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// MailHygiene collects TXT and DMARC records for mail security review.
type MailHygiene struct{}

func (m *MailHygiene) Name() string            { return "mail_hygiene" }
func (m *MailHygiene) Description() string     { return "Collect SPF and DMARC mail hygiene records" }
func (m *MailHygiene) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *MailHygiene) Dependencies() []string  { return []string{} }
func (m *MailHygiene) RequiredTools() []string { return []string{"dig"} }

func (m *MailHygiene) Validate(cfg *config.Config) error {
	if !cfg.OSINT.MailHygiene {
		return fmt.Errorf("mail_hygiene disabled")
	}
	return nil
}

func (m *MailHygiene) Run(ctx context.Context, scan *module.ScanContext) error {
	if net.ParseIP(scan.Target) != nil {
		scan.Logger.Info().Msg("Target is an IP address; skipping mail_hygiene")
		return nil
	}

	outDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	txt, txtErr := scan.Runner.Run(ctx, "dig", []string{"+short", "TXT", scan.Target}, runner.RunOpts{Timeout: 30 * time.Second})
	dmarc, dmarcErr := scan.Runner.Run(ctx, "dig", []string{"+short", "TXT", "_dmarc." + scan.Target}, runner.RunOpts{Timeout: 30 * time.Second})
	if txtErr != nil {
		scan.Logger.Warn().Err(txtErr).Msg("dig TXT failed")
	}
	if dmarcErr != nil {
		scan.Logger.Warn().Err(dmarcErr).Msg("dig DMARC failed")
	}

	var b strings.Builder
	txtOut := runnerStdout(txt)
	dmarcOut := runnerStdout(dmarc)
	fmt.Fprintf(&b, "Domain: %s\n\nTXT records:\n%s\nDMARC record:\n%s\n", scan.Target, indentDigOutput(txtOut), indentDigOutput(dmarcOut))
	outFile := filepath.Join(outDir, "mail_hygiene.txt")
	if err := os.WriteFile(outFile, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write mail hygiene: %w", err)
	}

	txtBody := strings.ToLower(string(txtOut))
	dmarcBody := strings.ToLower(string(dmarcOut))
	findings := make([]module.Finding, 0, 2)
	if !strings.Contains(txtBody, "v=spf1") {
		findings = append(findings, module.Finding{Module: m.Name(), Type: "info", Severity: "low", Target: scan.Target, Detail: "SPF TXT record not observed"})
	}
	if !strings.Contains(dmarcBody, "v=dmarc1") {
		findings = append(findings, module.Finding{Module: m.Name(), Type: "info", Severity: "low", Target: scan.Target, Detail: "DMARC TXT record not observed"})
	}
	if len(findings) > 0 {
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Msg("mail_hygiene complete")
	return nil
}

func runnerStdout(result *runner.RunResult) []byte {
	if result == nil {
		return nil
	}
	return result.Stdout
}

func indentDigOutput(raw []byte) string {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return "  \n"
	}
	for i, line := range lines {
		lines[i] = "  " + strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n") + "\n"
}

var _ module.Module = (*MailHygiene)(nil)
