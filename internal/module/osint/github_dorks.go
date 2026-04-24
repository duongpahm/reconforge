package osint

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

// GithubDorks runs gitdorks_go to find sensitive information exposed on GitHub.
type GithubDorks struct{}

func (m *GithubDorks) Name() string            { return "github_dorks" }
func (m *GithubDorks) Description() string     { return "GitHub dorks for sensitive info via gitdorks_go" }
func (m *GithubDorks) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *GithubDorks) Dependencies() []string  { return nil }
func (m *GithubDorks) RequiredTools() []string { return []string{"gitdorks_go"} }

func (m *GithubDorks) Validate(cfg *config.Config) error {
	if !cfg.OSINT.GithubDorks {
		return fmt.Errorf("github dorks disabled")
	}
	return nil
}

func (m *GithubDorks) Run(ctx context.Context, scan *module.ScanContext) error {
	osintDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	tokensFile := scan.Config.OSINT.GithubTokensFile
	if tokensFile == "" {
		scan.Logger.Warn().Msg("No GitHub tokens file configured; skipping github_dorks")
		return nil
	}
	if _, err := os.Stat(tokensFile); os.IsNotExist(err) {
		scan.Logger.Warn().Str("file", tokensFile).Msg("GitHub tokens file not found; skipping github_dorks")
		return nil
	}

	dorksFile := "smalldorks.txt"
	if scan.Config.General.Deep {
		dorksFile = "medium_dorks.txt"
	}
	dorksPath := filepath.Join(scan.Config.General.ToolsDir, "gitdorks_go", "Dorks", dorksFile)

	outFile := filepath.Join(osintDir, "gitdorks.txt")
	scan.Logger.Info().Str("dorks", dorksFile).Msg("Running gitdorks_go")

	result, err := scan.Runner.Run(ctx, "gitdorks_go", []string{
		"-gd", dorksPath,
		"-nws", "20",
		"-target", scan.Target,
		"-tf", tokensFile,
		"-ew", "3",
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("gitdorks_go failed (non-fatal)")
		return nil
	}

	if len(result.Stdout) > 0 {
		os.WriteFile(outFile, result.Stdout, 0o644)
		scan.Logger.Info().Msg("github_dorks complete")
	}
	return nil
}
