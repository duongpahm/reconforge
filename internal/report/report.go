// Package report generates scan reports in multiple formats.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/module"
)

// ScanReport holds all data for report generation.
type ScanReport struct {
	Target      string          `json:"target"`
	ScanMode    string          `json:"scan_mode"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Duration    time.Duration   `json:"duration"`
	Subdomains  []string        `json:"subdomains"`
	LiveHosts   []string        `json:"live_hosts"`
	URLs        []string        `json:"urls"`
	Emails      []string        `json:"emails"`
	Findings    []module.Finding `json:"findings"`
	Stats       ReportStats     `json:"stats"`
}

// ReportStats summarizes the scan results.
type ReportStats struct {
	SubdomainCount int            `json:"subdomain_count"`
	LiveHostCount  int            `json:"live_host_count"`
	URLCount       int            `json:"url_count"`
	EmailCount     int            `json:"email_count"`
	FindingCount   int            `json:"finding_count"`
	BySeverity     map[string]int `json:"by_severity"`
	ByModule       map[string]int `json:"by_module"`
}

// NewReportFromResults creates a ScanReport from scan results.
func NewReportFromResults(target, mode string, results *module.ScanResults, startedAt time.Time) *ScanReport {
	findings := results.GetFindings()

	bySeverity := make(map[string]int)
	byModule := make(map[string]int)
	for _, f := range findings {
		bySeverity[f.Severity]++
		byModule[f.Module]++
	}

	return &ScanReport{
		Target:      target,
		ScanMode:    mode,
		StartedAt:   startedAt,
		CompletedAt: time.Now(),
		Duration:    time.Since(startedAt),
		Subdomains:  results.GetSubdomains(),
		LiveHosts:   results.GetLiveHosts(),
		URLs:        results.GetURLs(),
		Emails:      results.GetEmails(),
		Findings:    findings,
		Stats: ReportStats{
			SubdomainCount: results.SubdomainCount(),
			LiveHostCount:  len(results.GetLiveHosts()),
			URLCount:       len(results.GetURLs()),
			EmailCount:     len(results.GetEmails()),
			FindingCount:   len(findings),
			BySeverity:     bySeverity,
			ByModule:       byModule,
		},
	}
}

// ExportJSON writes the report as JSON.
func (r *ScanReport) ExportJSON(outputDir string) (string, error) {
	outFile := filepath.Join(outputDir, "report.json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(outFile, data, 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return outFile, nil
}

// ExportMarkdown writes the report as Markdown.
func (r *ScanReport) ExportMarkdown(outputDir string) (string, error) {
	outFile := filepath.Join(outputDir, "report.md")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# ReconForge Report — %s\n\n", r.Target))
	sb.WriteString(fmt.Sprintf("**Mode:** %s  \n", r.ScanMode))
	sb.WriteString(fmt.Sprintf("**Started:** %s  \n", r.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", r.Duration.Round(time.Second)))

	// Stats
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Subdomains | %d |\n", r.Stats.SubdomainCount))
	sb.WriteString(fmt.Sprintf("| Live Hosts | %d |\n", r.Stats.LiveHostCount))
	sb.WriteString(fmt.Sprintf("| URLs | %d |\n", r.Stats.URLCount))
	sb.WriteString(fmt.Sprintf("| Emails | %d |\n", r.Stats.EmailCount))
	sb.WriteString(fmt.Sprintf("| Findings | %d |\n\n", r.Stats.FindingCount))

	// Severity breakdown
	if len(r.Stats.BySeverity) > 0 {
		sb.WriteString("### Findings by Severity\n\n")
		sb.WriteString("| Severity | Count |\n|----------|-------|\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := r.Stats.BySeverity[sev]; ok {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), count))
			}
		}
		sb.WriteString("\n")
	}

	// Findings detail
	if len(r.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		for i, f := range r.Findings {
			icon := severityIcon(f.Severity)
			sb.WriteString(fmt.Sprintf("### %d. %s [%s] %s\n\n", i+1, icon, strings.ToUpper(f.Severity), f.Target))
			sb.WriteString(fmt.Sprintf("**Module:** %s  \n", f.Module))
			sb.WriteString(fmt.Sprintf("**Detail:** %s\n\n", f.Detail))
		}
	}

	// Subdomains
	if len(r.Subdomains) > 0 {
		sb.WriteString("## Subdomains\n\n")
		sb.WriteString("<details><summary>Show all subdomains</summary>\n\n```\n")
		for _, s := range r.Subdomains {
			sb.WriteString(s + "\n")
		}
		sb.WriteString("```\n</details>\n\n")
	}

	// Live Hosts
	if len(r.LiveHosts) > 0 {
		sb.WriteString("## Live Hosts\n\n")
		sb.WriteString("<details><summary>Show all live hosts</summary>\n\n```\n")
		for _, h := range r.LiveHosts {
			sb.WriteString(h + "\n")
		}
		sb.WriteString("```\n</details>\n\n")
	}

	if err := os.WriteFile(outFile, []byte(sb.String()), 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return outFile, nil
}

// ExportHTML writes the report as a self-contained HTML file.
func (r *ScanReport) ExportHTML(outputDir string) (string, error) {
	outFile := filepath.Join(outputDir, "report.html")

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outFile)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, r); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return outFile, nil
}

// ExportAll generates reports in all formats.
func (r *ScanReport) ExportAll(outputDir string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var files []string

	if f, err := r.ExportJSON(outputDir); err == nil {
		files = append(files, f)
	}
	if f, err := r.ExportMarkdown(outputDir); err == nil {
		files = append(files, f)
	}
	if f, err := r.ExportHTML(outputDir); err == nil {
		files = append(files, f)
	}

	return files, nil
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconForge Report — {{.Target}}</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .meta { color: #8b949e; margin-bottom: 2rem; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .stat-card .label { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--card); color: var(--accent); font-weight: 600; }
  .sev-critical { color: #f85149; font-weight: 700; }
  .sev-high { color: #db6d28; font-weight: 700; }
  .sev-medium { color: #d29922; }
  .sev-low { color: #58a6ff; }
  .sev-info { color: #8b949e; }
  details { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 0.5rem 0; }
  summary { cursor: pointer; font-weight: 600; color: var(--accent); }
  pre { background: #0d1117; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; margin-top: 0.5rem; }
  footer { margin-top: 3rem; text-align: center; color: #484f58; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ ReconForge Report</h1>
  <div class="meta">
    <strong>Target:</strong> {{.Target}} &nbsp;|&nbsp;
    <strong>Mode:</strong> {{.ScanMode}} &nbsp;|&nbsp;
    <strong>Duration:</strong> {{.Duration}}
  </div>

  <div class="stats">
    <div class="stat-card"><div class="value">{{.Stats.SubdomainCount}}</div><div class="label">Subdomains</div></div>
    <div class="stat-card"><div class="value">{{.Stats.LiveHostCount}}</div><div class="label">Live Hosts</div></div>
    <div class="stat-card"><div class="value">{{.Stats.URLCount}}</div><div class="label">URLs</div></div>
    <div class="stat-card"><div class="value">{{.Stats.EmailCount}}</div><div class="label">Emails</div></div>
    <div class="stat-card"><div class="value">{{.Stats.FindingCount}}</div><div class="label">Findings</div></div>
  </div>

  {{if .Findings}}
  <h2>Findings</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Module</th><th>Target</th><th>Detail</th></tr></thead>
    <tbody>
    {{range $i, $f := .Findings}}
    <tr>
      <td>{{$i}}</td>
      <td class="sev-{{$f.Severity}}">{{$f.Severity}}</td>
      <td>{{$f.Module}}</td>
      <td>{{$f.Target}}</td>
      <td>{{$f.Detail}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .Subdomains}}
  <h2>Subdomains ({{.Stats.SubdomainCount}})</h2>
  <details><summary>Show all</summary><pre>{{range .Subdomains}}{{.}}
{{end}}</pre></details>
  {{end}}

  {{if .LiveHosts}}
  <h2>Live Hosts ({{.Stats.LiveHostCount}})</h2>
  <details><summary>Show all</summary><pre>{{range .LiveHosts}}{{.}}
{{end}}</pre></details>
  {{end}}

  <footer>Generated by ReconForge • {{.CompletedAt.Format "2006-01-02 15:04:05"}}</footer>
</div>
</body>
</html>`
