package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// DomainInfo collects WHOIS and domain registration data.
type DomainInfo struct{}

func (m *DomainInfo) Name() string            { return "domain_info" }
func (m *DomainInfo) Description() string     { return "WHOIS and domain registration info" }
func (m *DomainInfo) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *DomainInfo) Dependencies() []string  { return nil }
func (m *DomainInfo) RequiredTools() []string { return []string{"whois"} }

func (m *DomainInfo) Validate(cfg *config.Config) error {
	if !cfg.OSINT.DomainInfo {
		return fmt.Errorf("domain_info disabled")
	}
	return nil
}

func (m *DomainInfo) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running whois lookup")

	result, err := scan.Runner.Run(ctx, "whois", []string{scan.Target}, runner.RunOpts{
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("whois failed (non-fatal)")
	} else if len(result.Stdout) > 0 {
		outFile := filepath.Join(osintDir, "domain_info_general.txt")
		os.WriteFile(outFile, result.Stdout, 0o644)
		scan.Logger.Info().Msg("domain_info complete")
	}
	return nil
}
