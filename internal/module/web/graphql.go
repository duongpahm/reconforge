package web

import (
	"bufio"
	"context"
	"encoding/json"
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

// GraphQLScan discovers GraphQL endpoints from nuclei output and probes them with gqlspection.
type GraphQLScan struct{}

func (m *GraphQLScan) Name() string            { return "graphql_scan" }
func (m *GraphQLScan) Description() string     { return "GraphQL endpoint discovery and probing" }
func (m *GraphQLScan) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *GraphQLScan) Dependencies() []string  { return []string{"nuclei_check"} }
func (m *GraphQLScan) RequiredTools() []string { return []string{"gqlspection"} }

func (m *GraphQLScan) Validate(cfg *config.Config) error {
	if !cfg.Web.GraphQL {
		return fmt.Errorf("graphql scanning disabled")
	}
	return nil
}

func (m *GraphQLScan) Run(ctx context.Context, scan *module.ScanContext) error {
	nucleiDir := filepath.Join(scan.OutputDir, "nuclei_output")
	vulnGraphQLDir := filepath.Join(scan.OutputDir, "vulns", "graphql")
	for _, d := range []string{nucleiDir, vulnGraphQLDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	severityFiles := []string{
		filepath.Join(nucleiDir, "critical_json.txt"),
		filepath.Join(nucleiDir, "high_json.txt"),
		filepath.Join(nucleiDir, "medium_json.txt"),
		filepath.Join(nucleiDir, "low_json.txt"),
		filepath.Join(nucleiDir, "info_json.txt"),
	}

	endpoints := make([]string, 0)
	endpointSeverity := make(map[string]string)
	for _, file := range severityFiles {
		lines, err := readLines(file)
		if err != nil || len(lines) == 0 {
			continue
		}
		for _, line := range lines {
			var event graphqlNucleiEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				continue
			}
			templateID := strings.ToLower(strings.TrimSpace(event.TemplateID))
			if templateID != "graphql-detect" && !strings.Contains(templateID, "graphql") {
				continue
			}
			ep := firstNonEmptyValue(event.MatchedAt, event.Host)
			if ep == "" {
				continue
			}
			endpoints = append(endpoints, ep)
			severity := normalizeNucleiSeverity(event.Info.Severity)
			if existing, exists := endpointSeverity[ep]; !exists || severityRank(severity) > severityRank(existing) {
				endpointSeverity[ep] = severity
			}
		}
	}

	endpoints = dedupLines(endpoints)
	if len(endpoints) == 0 {
		scan.Logger.Info().Msg("No GraphQL endpoints detected; graphql_scan skipped")
		return nil
	}

	if !scan.Config.General.Deep && len(endpoints) > 200 {
		scan.Logger.Warn().Int("endpoints", len(endpoints)).Msg("Too many GraphQL endpoints; truncating to 200 (use deep mode)")
		endpoints = endpoints[:200]
	}

	graphqlList := filepath.Join(nucleiDir, "graphql.txt")
	if err := writeLines(graphqlList, endpoints); err != nil {
		return fmt.Errorf("write graphql endpoints: %w", err)
	}

	findings := make([]module.Finding, 0, len(endpoints))
	for _, ep := range endpoints {
		sev := endpointSeverity[ep]
		if sev == "" {
			sev = "medium"
		}
		findings = append(findings, module.Finding{
			Module:   "graphql_scan",
			Type:     "vuln",
			Severity: sev,
			Target:   ep,
			Detail:   "GraphQL endpoint detected",
		})
	}

	if scan.Runner.IsInstalled("gqlspection") {
		for _, ep := range endpoints {
			outFile := filepath.Join(vulnGraphQLDir, sanitizeFilename(ep)+".json")
			_, err := scan.Runner.Run(ctx, "gqlspection", []string{"-t", ep, "-o", outFile}, runner.RunOpts{Timeout: 5 * time.Minute})
			if err != nil {
				scan.Logger.Debug().Err(err).Str("endpoint", ep).Msg("gqlspection failed (non-fatal)")
			}
		}
	} else {
		scan.Logger.Warn().Msg("gqlspection not installed; graphql_scan kept detection-only results")
	}

	if len(findings) > 0 {
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Int("endpoints", len(endpoints)).Msg("graphql_scan complete")
	return nil
}

type graphqlNucleiEvent struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Severity string `json:"severity"`
	} `json:"info"`
}

func fileHasContent(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.Size() > 0
}

func readJSONLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

var _ module.Module = (*GraphQLScan)(nil)
