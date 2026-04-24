package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
)

// WordlistGen aggregates target-specific vocabulary from URLs and subdomains.
type WordlistGen struct{}

func (m *WordlistGen) Name() string            { return "wordlist_gen" }
func (m *WordlistGen) Description() string     { return "Generate a custom wordlist from target data" }
func (m *WordlistGen) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WordlistGen) Dependencies() []string  { return []string{"urlext"} }
func (m *WordlistGen) RequiredTools() []string { return []string{} }

func (m *WordlistGen) Validate(cfg *config.Config) error {
	if !cfg.Web.WordlistGen {
		return fmt.Errorf("wordlist_gen disabled")
	}
	return nil
}

func (m *WordlistGen) Run(ctx context.Context, scan *module.ScanContext) error {
	outDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	scan.Logger.Info().Msg("Generating custom wordlist...")

	inputs := []string{
		filepath.Join(scan.OutputDir, "subdomains", "subdomains.txt"),
		filepath.Join(scan.OutputDir, "webs", "url_extract.txt"),
		filepath.Join(scan.OutputDir, "js", "js_wordlist.txt"),
	}

	wordSet := make(map[string]struct{})
	nonAlphaNum := regexp.MustCompile(`[^a-zA-Z0-9]+`)

	for _, inputFile := range inputs {
		lines, err := readLines(inputFile)
		if err != nil {
			continue
		}
		for _, line := range lines {
			// Extract words
			words := nonAlphaNum.Split(line, -1)
			for _, w := range words {
				w = strings.ToLower(w)
				if len(w) >= 3 && len(w) <= 30 {
					wordSet[w] = struct{}{}
				}
			}
		}
	}

	if len(wordSet) == 0 {
		scan.Logger.Info().Msg("No words extracted; skipping wordlist generation")
		return nil
	}

	var wordlist []string
	for w := range wordSet {
		wordlist = append(wordlist, w)
	}

	outputFile := filepath.Join(outDir, "dict.txt")
	if err := writeLines(outputFile, wordlist); err != nil {
		return fmt.Errorf("write dict: %w", err)
	}

	scan.Logger.Info().Int("words", len(wordlist)).Msg("wordlist_gen complete")
	return nil
}
