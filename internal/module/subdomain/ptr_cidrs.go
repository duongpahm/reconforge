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

// SubPTRCidrs performs reverse DNS lookups over CIDR ranges using dnsx -ptr.
type SubPTRCidrs struct{}

func (m *SubPTRCidrs) Name() string { return "sub_ptr_cidrs" }
func (m *SubPTRCidrs) Description() string {
	return "Reverse DNS on CIDR ranges to discover subdomains"
}
func (m *SubPTRCidrs) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SubPTRCidrs) Dependencies() []string  { return []string{} }
func (m *SubPTRCidrs) RequiredTools() []string { return []string{"dnsx"} }

func (m *SubPTRCidrs) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.PtrCidrs {
		return fmt.Errorf("sub_ptr_cidrs disabled")
	}
	return nil
}

func (m *SubPTRCidrs) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	inputFile := filepath.Join(scan.OutputDir, "hosts", "asn_cidrs.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No CIDR input for sub_ptr_cidrs; skipping")
		return nil
	}

	outFile := filepath.Join(outDir, "ptr_cidrs.txt")

	_, err := scan.Runner.Run(ctx, "dnsx", []string{"-ptr", "-l", inputFile, "-o", outFile}, runner.RunOpts{Timeout: 15 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("dnsx ptr lookup failed")
		return nil
	}

	scan.Logger.Info().Msg("sub_ptr_cidrs complete")
	return nil
}
