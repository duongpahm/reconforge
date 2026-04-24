package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// GithubActionsAudit enumerates GitHub Actions artifacts and workflow exposure using gato.
type GithubActionsAudit struct{}

func (m *GithubActionsAudit) Name() string { return "github_actions_audit" }
func (m *GithubActionsAudit) Description() string {
	return "Audit GitHub Actions workflow and artifact exposure"
}
func (m *GithubActionsAudit) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *GithubActionsAudit) Dependencies() []string  { return []string{} }
func (m *GithubActionsAudit) RequiredTools() []string { return []string{"gato"} }

func (m *GithubActionsAudit) Validate(cfg *config.Config) error {
	if !cfg.OSINT.GithubActions {
		return fmt.Errorf("github_actions_audit disabled")
	}
	return nil
}

func (m *GithubActionsAudit) Run(ctx context.Context, scan *module.ScanContext) error {
	if net.ParseIP(scan.Target) != nil {
		scan.Logger.Info().Msg("Target is an IP address; skipping github_actions_audit")
		return nil
	}
	if scan.Config.OSINT.GithubTokensFile == "" {
		scan.Logger.Warn().Msg("GitHub tokens file not configured; skipping github_actions_audit")
		return nil
	}

	tokenBytes, err := os.ReadFile(scan.Config.OSINT.GithubTokensFile)
	if err != nil || strings.TrimSpace(string(tokenBytes)) == "" {
		scan.Logger.Warn().Err(err).Msg("GitHub token missing; skipping github_actions_audit")
		return nil
	}

	outDir := filepath.Join(scan.OutputDir, "osint")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	orgFile := filepath.Join(tmpDir, "gato_orgs.txt")
	if err := os.WriteFile(orgFile, []byte(rootOrgName(scan.Target)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write gato orgs: %w", err)
	}

	jsonOut := filepath.Join(outDir, "github_actions_audit.json")
	args := []string{"e", "--enum_wf_artifacts", "--skip_sh_runner_enum", "-O", orgFile, "-oJ", jsonOut}
	result, err := scan.Runner.Run(ctx, "gato", args, runner.RunOpts{
		Timeout: 20 * time.Minute,
		Env:     []string{"GH_TOKEN=" + firstLine(string(tokenBytes))},
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("gato execution failed")
		return nil
	}
	if _, err := os.Stat(jsonOut); os.IsNotExist(err) && len(result.Stdout) > 0 {
		_ = os.WriteFile(jsonOut, result.Stdout, 0o644)
	}

	raw, err := os.ReadFile(jsonOut)
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	matches := auditKeywordStrings(raw)
	if len(matches) > 0 {
		txtOut := filepath.Join(outDir, "github_actions_audit.txt")
		if err := writeLines(txtOut, matches); err != nil {
			scan.Logger.Warn().Err(err).Msg("write github actions audit summary failed")
		}
		for _, item := range matches {
			scan.Results.AddFindings([]module.Finding{{Module: m.Name(), Type: "info", Severity: "medium", Target: scan.Target, Detail: item}})
		}
	}

	scan.Logger.Info().Int("matches", len(matches)).Msg("github_actions_audit complete")
	return nil
}

func auditKeywordStrings(raw []byte) []string {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	var walk func(interface{})
	walk = func(value interface{}) {
		switch t := value.(type) {
		case map[string]interface{}:
			for _, child := range t {
				walk(child)
			}
		case []interface{}:
			for _, child := range t {
				walk(child)
			}
		case string:
			lower := strings.ToLower(t)
			if strings.Contains(lower, "artifact") || strings.Contains(lower, "workflow") || strings.Contains(lower, "runner") || strings.Contains(lower, "secret") {
				if !seen[t] {
					seen[t] = true
					out = append(out, t)
				}
			}
		}
	}
	walk(v)
	return out
}

func rootOrgName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 || parts[0] == "" {
		return domain
	}
	return parts[0]
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

var _ module.Module = (*GithubActionsAudit)(nil)
