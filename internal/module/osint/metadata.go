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

// Metadata extracts document metadata from public files using metagoofil.
type Metadata struct{}

func (m *Metadata) Name() string            { return "metadata" }
func (m *Metadata) Description() string     { return "Extract metadata from public documents" }
func (m *Metadata) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *Metadata) Dependencies() []string  { return []string{} }
func (m *Metadata) RequiredTools() []string { return []string{"metagoofil"} }

func (m *Metadata) Validate(cfg *config.Config) error {
	if !cfg.OSINT.Metadata {
		return fmt.Errorf("metadata disabled")
	}
	return nil
}

func (m *Metadata) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "osint", "metadata")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	scan.Logger.Info().Msg("Extracting document metadata...")

	// run metagoofil: metagoofil -d example.com -t pdf,doc,xls,ppt,docx,xlsx,pptx -l 200 -n 50 -o outDir -f results.html
	outFile := filepath.Join(outDir, "metadata_results.html")

	_, err := scan.Runner.Run(ctx, "metagoofil", []string{
		"-d", scan.Target,
		"-t", "pdf,doc,xls,ppt,docx,xlsx,pptx",
		"-l", "20", // limit search to avoid getting banned or hanging
		"-n", "20",
		"-o", outDir,
		"-f", outFile,
	}, runner.RunOpts{Timeout: 45 * time.Minute})

	if err != nil {
		scan.Logger.Warn().Err(err).Msg("metagoofil failed")
		return nil
	}

	// We can emit findings here if we want to parse the HTML or stdout,
	// but generally metagoofil generates reports and downloads files.
	if _, err := os.Stat(outFile); err == nil {
		scan.Results.AddFindings([]module.Finding{{
			Module:   m.Name(),
			Type:     "info",
			Severity: "info",
			Target:   scan.Target,
			Detail:   "Metadata extracted to HTML report",
		}})
	}

	scan.Logger.Info().Msg("metadata complete")
	return nil
}
