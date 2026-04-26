package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// PasswordDict creates a target-specific password dictionary.
type PasswordDict struct{}

func (m *PasswordDict) Name() string            { return "password_dict" }
func (m *PasswordDict) Description() string     { return "Generate target-specific password dictionary" }
func (m *PasswordDict) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *PasswordDict) Dependencies() []string  { return []string{"wordlist_gen"} }
func (m *PasswordDict) RequiredTools() []string { return []string{} }

func (m *PasswordDict) Validate(cfg *config.Config) error {
	if !cfg.Web.PasswordDict {
		return fmt.Errorf("password_dict disabled")
	}
	return nil
}

func (m *PasswordDict) Run(ctx context.Context, scan *module.ScanContext) error {
	webDir := filepath.Join(scan.OutputDir, "webs")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	outFile := filepath.Join(webDir, "password_dict.txt")
	words := make([]string, 0)
	if scan.Runner.IsInstalled("cewler") {
		words = append(words, runCewlerPasswordWords(ctx, scan, filepath.Join(webDir, "webs_all.txt"))...)
	}
	if len(words) == 0 {
		words = generatePasswordFallback(scan.Target, []string{
			filepath.Join(webDir, "dict.txt"),
			filepath.Join(webDir, "dict_words.txt"),
			filepath.Join(scan.OutputDir, "subdomains", "subdomains.txt"),
		})
	}
	if len(words) == 0 {
		scan.Logger.Info().Msg("No password dictionary words generated")
		return nil
	}
	if err := writeLines(outFile, dedupeBoundedWords(words, 5, 14)); err != nil {
		return fmt.Errorf("write password dict: %w", err)
	}
	scan.Logger.Info().Int("words", len(words)).Msg("password_dict complete")
	return nil
}

func runCewlerPasswordWords(ctx context.Context, scan *module.ScanContext, websFile string) []string {
	targets, err := readLines(websFile)
	if err != nil || len(targets) == 0 {
		return nil
	}
	if !scan.Config.General.Deep && len(targets) > 50 {
		targets = targets[:50]
	}

	var words []string
	for _, target := range targets {
		result, err := scan.Runner.Run(ctx, "cewler", []string{"-d", "1", "-m", "5", "-l", target}, runner.RunOpts{Timeout: 45 * time.Second})
		if err != nil {
			continue
		}
		words = append(words, parseLines(result.Stdout)...)
	}
	return words
}

func generatePasswordFallback(target string, inputs []string) []string {
	var seeds []string
	if base := strings.Split(target, ".")[0]; base != "" {
		seeds = append(seeds, base)
	}
	for _, input := range inputs {
		lines, err := readLines(input)
		if err != nil {
			continue
		}
		seeds = append(seeds, lines...)
	}
	return dedupeBoundedWords(seeds, 5, 14)
}

func dedupeBoundedWords(raw []string, minLen, maxLen int) []string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, item := range raw {
		for _, part := range re.Split(strings.ToLower(item), -1) {
			if len(part) < minLen || len(part) > maxLen || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

var _ module.Module = (*PasswordDict)(nil)
