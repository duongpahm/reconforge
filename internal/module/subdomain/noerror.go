package subdomain

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

// SubNoError finds subdomains by probing for NOERROR DNS responses using dnsx.
// This technique detects domains that exist but return NOERROR for any label,
// bypassing NXDOMAIN-based wildcard detection.
type SubNoError struct{}

func (m *SubNoError) Name() string { return "sub_noerror" }
func (m *SubNoError) Description() string {
	return "Subdomain discovery via DNS NOERROR response probing"
}
func (m *SubNoError) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SubNoError) Dependencies() []string  { return []string{"subfinder"} }
func (m *SubNoError) RequiredTools() []string { return []string{"dnsx"} }

func (m *SubNoError) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.NoError {
		return fmt.Errorf("NOERROR subdomain scanning disabled")
	}
	return nil
}

func (m *SubNoError) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create subdomains dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// First check for DNSSEC black lies: a random nonsense subdomain should return NXDOMAIN.
	checkDomain := fmt.Sprintf("totallynotexist99999.%s", scan.Target)
	checkResult, _ := scan.Runner.Run(ctx, "dnsx", []string{
		"-d", checkDomain,
		"-rcode", "noerror,nxdomain",
		"-retry", "3",
		"-silent",
	}, runner.RunOpts{Timeout: 30 * time.Second})

	if checkResult != nil && strings.Contains(string(checkResult.Stdout), "[NOERROR]") {
		scan.Logger.Warn().Msg("DNSSEC black lies detected, skipping NOERROR technique")
		return nil
	}

	wordlist := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "subdomains.txt")
	if scan.Config.General.Deep {
		wordlist = filepath.Join(scan.Config.General.ToolsDir, "wordlists", "subdomains_big.txt")
	}
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		scan.Logger.Warn().Str("wordlist", wordlist).Msg("wordlist not found, skipping NOERROR scan")
		return nil
	}

	outFile := filepath.Join(tmpDir, "subs_noerror.txt")
	scan.Logger.Info().Str("target", scan.Target).Msg("Running dnsx NOERROR probe")

	result, err := scan.Runner.Run(ctx, "dnsx", []string{
		"-d", scan.Target,
		"-rcode", "noerror",
		"-w", wordlist,
		"-silent",
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("dnsx NOERROR failed (non-fatal)")
		return nil
	}

	var subs []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		// dnsx outputs "domain [RCODE]" — extract the domain
		parts := strings.Fields(line)
		if len(parts) > 0 && parts[0] != "" {
			subs = append(subs, parts[0])
		}
	}

	if len(subs) > 0 {
		if err := writeLines(outFile, subs); err != nil {
			return fmt.Errorf("write noerror results: %w", err)
		}
		scan.Results.AddSubdomains(subs)
	}

	scan.Logger.Info().Int("found", len(subs)).Msg("NOERROR probe complete")
	return nil
}
