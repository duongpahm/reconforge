package web

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

// FavireconTech performs favicon-based technology fingerprinting via favirecon.
type FavireconTech struct{}

func (m *FavireconTech) Name() string { return "favirecon_tech" }
func (m *FavireconTech) Description() string {
	return "Favicon technology fingerprinting via favirecon"
}
func (m *FavireconTech) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *FavireconTech) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *FavireconTech) RequiredTools() []string { return []string{"favirecon"} }

func (m *FavireconTech) Validate(cfg *config.Config) error {
	if !cfg.Web.FavireconTech {
		return fmt.Errorf("favirecon_tech disabled")
	}
	return nil
}

func (m *FavireconTech) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Info().Msg("No web targets for favirecon; skipping")
		return nil
	}

	jsonOut := filepath.Join(websDir, "favirecon.json")
	scan.Logger.Info().Int("targets", len(targets)).Msg("Running favirecon favicon fingerprinting")

	_, err = scan.Runner.Run(ctx, "favirecon", []string{
		"-l", websAllFile,
		"-c", "50",
		"-t", "10",
		"-s",
		"-j",
		"-o", jsonOut,
	}, runner.RunOpts{Timeout: 20 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("favirecon failed (non-fatal)")
		return nil
	}

	// Convert JSON to readable text
	data, err := os.ReadFile(jsonOut)
	if err != nil || len(data) == 0 {
		return nil
	}

	var txtLines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		txtLines = append(txtLines, line)
	}

	if len(txtLines) > 0 {
		writeLines(filepath.Join(websDir, "favirecon.txt"), txtLines)
		scan.Logger.Info().Int("results", len(txtLines)).Msg("favirecon_tech complete")
	}
	return nil
}
