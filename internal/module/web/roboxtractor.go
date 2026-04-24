package web

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

// WordlistGenRoboxtractor builds a robots-derived wordlist with roboxtractor.
type WordlistGenRoboxtractor struct{}

func (m *WordlistGenRoboxtractor) Name() string { return "wordlist_gen_roboxtractor" }
func (m *WordlistGenRoboxtractor) Description() string {
	return "Generate robots.txt wordlist with roboxtractor"
}
func (m *WordlistGenRoboxtractor) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WordlistGenRoboxtractor) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *WordlistGenRoboxtractor) RequiredTools() []string { return []string{"roboxtractor"} }

func (m *WordlistGenRoboxtractor) Validate(cfg *config.Config) error {
	if !cfg.Web.RobotsWordlist {
		return fmt.Errorf("wordlist_gen_roboxtractor disabled")
	}
	return nil
}

func (m *WordlistGenRoboxtractor) Run(ctx context.Context, scan *module.ScanContext) error {
	if !scan.Config.General.Deep {
		scan.Logger.Info().Msg("wordlist_gen_roboxtractor requires deep mode; skipping")
		return nil
	}

	webDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}
	inputFile := filepath.Join(webDir, "webs_all.txt")
	in, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			scan.Logger.Info().Msg("No webs_all input for roboxtractor; skipping")
			return nil
		}
		return err
	}
	defer in.Close()

	result, err := scan.Runner.Run(ctx, "roboxtractor", []string{"-m", "1", "-wb"}, runner.RunOpts{Timeout: 20 * time.Minute, Stdin: in})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("roboxtractor failed")
		return nil
	}
	words := parseLines(result.Stdout)
	if len(words) == 0 {
		return nil
	}
	if err := writeLines(filepath.Join(webDir, "robots_wordlist.txt"), words); err != nil {
		return fmt.Errorf("write robots wordlist: %w", err)
	}
	scan.Logger.Info().Int("words", len(words)).Msg("wordlist_gen_roboxtractor complete")
	return nil
}

var _ module.Module = (*WordlistGenRoboxtractor)(nil)
