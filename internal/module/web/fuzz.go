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

// WebFuzz performs directory/path fuzzing using ffuf on all discovered web targets.
type WebFuzz struct{}

func (m *WebFuzz) Name() string            { return "web_fuzz" }
func (m *WebFuzz) Description() string     { return "Web directory fuzzing via ffuf" }
func (m *WebFuzz) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WebFuzz) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *WebFuzz) RequiredTools() []string { return []string{"ffuf"} }

func (m *WebFuzz) Validate(cfg *config.Config) error {
	if !cfg.Web.Fuzzing {
		return fmt.Errorf("web fuzzing disabled")
	}
	return nil
}

func (m *WebFuzz) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	fuzzDir := filepath.Join(scan.OutputDir, "fuzzing")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp", "fuzzing")
	if err := os.MkdirAll(fuzzDir, 0o755); err != nil {
		return fmt.Errorf("create fuzzing dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp fuzzing dir: %w", err)
	}

	// Build unified webs_all.txt from standard and uncommon port targets
	websAllFile := filepath.Join(websDir, "webs_all.txt")
	if _, err := os.Stat(websAllFile); os.IsNotExist(err) {
		webs, _ := readLines(filepath.Join(websDir, "webs.txt"))
		websUncommon, _ := readLines(filepath.Join(websDir, "webs_uncommon_ports.txt"))
		all := dedupLines(append(webs, websUncommon...))
		if len(all) == 0 {
			scan.Logger.Warn().Msg("No web targets for fuzzing; skipping")
			return nil
		}
		writeLines(websAllFile, all)
	}

	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Warn().Msg("No web targets for fuzzing; skipping")
		return nil
	}

	wordlist := filepath.Join(scan.Config.General.ToolsDir, "wordlists", "fuzz.txt")
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		// Fallback to a common wordlist location
		wordlist = "/usr/share/wordlists/dirb/common.txt"
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			scan.Logger.Warn().Msg("No fuzzing wordlist found; skipping")
			return nil
		}
	}

	ffufRate := scan.Config.RateLimit.FFUF
	if ffufRate <= 0 {
		ffufRate = 0 // unlimited by default in reconFTW
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running ffuf directory fuzzing")

	fuzzResultsFile := filepath.Join(fuzzDir, "fuzzing_full.txt")
	var allResults []string

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		// Sanitize target name for output filename
		safeName := strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(target)
		outFile := filepath.Join(fuzzDir, safeName+".txt")

		args := []string{
			"-u", target + "/FUZZ",
			"-w", wordlist,
			"-t", "40",
			"-mc", "200,201,204,301,302,307,401,403,405",
			"-o", outFile,
			"-of", "json",
			"-s",
		}
		if ffufRate > 0 {
			args = append(args, "-rate", fmt.Sprintf("%d", ffufRate))
		}

		result, err := scan.Runner.Run(ctx, "ffuf", args, runner.RunOpts{
			Timeout: 30 * time.Minute,
		})
		if err != nil {
			scan.Logger.Debug().Err(err).Str("target", target).Msg("ffuf failed for target (non-fatal)")
			continue
		}

		// Collect stdout lines for fuzzing_full.txt
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				allResults = append(allResults, line)
			}
		}
	}

	if len(allResults) > 0 {
		writeLines(fuzzResultsFile, allResults)
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Web fuzzing complete")
	return nil
}
