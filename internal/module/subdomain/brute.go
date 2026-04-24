package subdomain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// DNSBrute performs DNS brute force subdomain enumeration.
type DNSBrute struct{}

func (m *DNSBrute) Name() string            { return "dns_brute" }
func (m *DNSBrute) Description() string     { return "DNS brute force enumeration using puredns/dnsx" }
func (m *DNSBrute) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *DNSBrute) Dependencies() []string  { return []string{"subfinder", "crt_sh"} }
func (m *DNSBrute) RequiredTools() []string { return []string{"puredns"} }

func (m *DNSBrute) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Brute {
		return fmt.Errorf("DNS brute force disabled")
	}
	return nil
}

func (m *DNSBrute) Run(ctx context.Context, scan *module.ScanContext) error {
	outFile := filepath.Join(scan.OutputDir, "subdomains", "dns_brute.txt")
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Use puredns for DNS brute force with resolvers
	wordlist := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "subdomains.txt")

	args := []string{
		"bruteforce",
		wordlist,
		scan.Target,
		"-r", filepath.Join(scan.Config.General.ToolsDir, "resolvers.txt"),
		"-w", outFile,
		"--rate-limit", "500",
		"-q",
	}

	scan.Logger.Info().
		Str("target", scan.Target).
		Str("wordlist", wordlist).
		Msg("Running puredns brute force")

	result, err := scan.Runner.Run(ctx, "puredns", args, runner.RunOpts{
		Timeout: 60 * time.Minute,
		Retry:   1,
	})
	if err != nil {
		return fmt.Errorf("puredns brute: %w", err)
	}

	subs, _ := readLines(outFile)
	added := scan.Results.AddSubdomains(subs)

	scan.Logger.Info().
		Int("found", len(subs)).
		Int("new", added).
		Dur("duration", result.Duration).
		Msg("DNS brute force completed")

	return nil
}

var _ module.Module = (*DNSBrute)(nil)
