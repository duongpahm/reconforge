package findings

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/reconforge/reconforge/internal/models"
	"github.com/reconforge/reconforge/internal/project"
)

//go:embed templates/burp.xml.tmpl
var burpXMLTemplate string

type jsonFinding struct {
	FindingID   string `json:"finding_id"`
	ScanID      string `json:"scan_id"`
	Target      string `json:"target"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Module      string `json:"module"`
	Tool        string `json:"tool"`
	Host        string `json:"host"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Reference   string `json:"reference"`
	Tags        string `json:"tags"`
	RawOutput   string `json:"raw_output"`
	RequestRaw  string `json:"request_raw"`
	ResponseRaw string `json:"response_raw"`
	Notes       string `json:"notes"`
	Fingerprint string `json:"fingerprint"`
}

// Export writes filtered findings in the requested format.
func Export(target, format, outFile string, severities []string) error {
	pm, err := project.NewManager()
	if err != nil {
		return err
	}
	defer pm.Close()

	findings, err := pm.ListFindings(target, strings.Join(severities, ","), "", "", "")
	if err != nil {
		return err
	}

	data, err := renderExport(strings.ToLower(format), findings)
	if err != nil {
		return err
	}

	return writeOutput(outFile, data)
}

func renderExport(format string, findings []models.Finding) ([]byte, error) {
	switch format {
	case "burp-xml":
		return renderBurpXML(findings)
	case "markdown", "md":
		return renderMarkdown(findings), nil
	case "csv":
		return renderCSV(findings)
	case "ndjson":
		return renderNDJSON(findings)
	case "hackerone":
		return renderPlatformTemplate("HackerOne Submission Draft", findings), nil
	case "bugcrowd":
		return renderPlatformTemplate("Bugcrowd Submission Draft", findings), nil
	case "nuclei-targets":
		return renderNucleiTargets(findings), nil
	default:
		return nil, fmt.Errorf("unsupported findings export format %q", format)
	}
}

func writeOutput(outFile string, data []byte) error {
	if outFile == "" || outFile == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil && filepath.Dir(outFile) != "." {
		return err
	}
	return os.WriteFile(outFile, data, 0o644)
}

func renderNDJSON(findings []models.Finding) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, finding := range findings {
		if err := enc.Encode(toJSONFinding(finding)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func renderCSV(findings []models.Finding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"finding_id", "target", "severity", "type", "module", "host", "url", "title", "description", "tags"}); err != nil {
		return nil, err
	}
	for _, finding := range findings {
		if err := w.Write([]string{
			finding.FindingID,
			finding.Target,
			finding.Severity,
			finding.Type,
			finding.Module,
			finding.Host,
			finding.URL,
			finding.Title,
			finding.Description,
			finding.Tags,
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func renderMarkdown(findings []models.Finding) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Findings Export\n\n")
	buf.WriteString(fmt.Sprintf("Total findings: %d\n\n", len(findings)))

	if len(findings) == 0 {
		return buf.Bytes()
	}

	buf.WriteString("| Severity | Module | Type | Host | Title |\n")
	buf.WriteString("|----------|--------|------|------|-------|\n")
	for _, finding := range findings {
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			escapePipes(finding.Severity),
			escapePipes(finding.Module),
			escapePipes(finding.Type),
			escapePipes(bestHost(finding)),
			escapePipes(bestTitle(finding)),
		))
	}

	buf.WriteString("\n## Details\n\n")
	for i, finding := range findings {
		buf.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(defaultValue(finding.Severity, "info")), bestTitle(finding)))
		buf.WriteString(fmt.Sprintf("- Target: `%s`\n", defaultValue(finding.Target, "-")))
		buf.WriteString(fmt.Sprintf("- Module: `%s`\n", defaultValue(finding.Module, "-")))
		buf.WriteString(fmt.Sprintf("- Type: `%s`\n", defaultValue(finding.Type, "-")))
		buf.WriteString(fmt.Sprintf("- Host: `%s`\n", defaultValue(bestHost(finding), "-")))
		if finding.URL != "" {
			buf.WriteString(fmt.Sprintf("- URL: `%s`\n", finding.URL))
		}
		if finding.Description != "" {
			buf.WriteString(fmt.Sprintf("\n%s\n\n", finding.Description))
		} else {
			buf.WriteString("\nNo description.\n\n")
		}
	}

	return buf.Bytes()
}

func renderPlatformTemplate(title string, findings []models.Finding) []byte {
	var buf bytes.Buffer
	buf.WriteString("# " + title + "\n\n")
	for i, finding := range findings {
		buf.WriteString(fmt.Sprintf("## %d. %s\n\n", i+1, bestTitle(finding)))
		buf.WriteString(fmt.Sprintf("- Severity: %s\n", defaultValue(finding.Severity, "unknown")))
		buf.WriteString(fmt.Sprintf("- Target: %s\n", defaultValue(finding.Target, "-")))
		if finding.URL != "" {
			buf.WriteString(fmt.Sprintf("- URL: %s\n", finding.URL))
		}
		if finding.Description != "" {
			buf.WriteString("\n### Description\n")
			buf.WriteString(finding.Description + "\n")
		}
		if finding.RequestRaw != "" {
			buf.WriteString("\n### Reproduction\n```http\n")
			buf.WriteString(finding.RequestRaw)
			if !strings.HasSuffix(finding.RequestRaw, "\n") {
				buf.WriteString("\n")
			}
			buf.WriteString("```\n")
		}
		buf.WriteString("\n")
	}
	return buf.Bytes()
}

func renderNucleiTargets(findings []models.Finding) []byte {
	targets := make(map[string]struct{})
	for _, finding := range findings {
		if target := findingNucleiTarget(finding); target != "" {
			targets[target] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(targets))
	for target := range targets {
		ordered = append(ordered, target)
	}
	sort.Strings(ordered)

	var buf bytes.Buffer
	for _, target := range ordered {
		buf.WriteString(target + "\n")
	}
	return buf.Bytes()
}

func renderBurpXML(findings []models.Finding) ([]byte, error) {
	funcs := template.FuncMap{
		"xml": xmlEscape,
	}
	tpl, err := template.New("burp").Funcs(funcs).Parse(burpXMLTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	data := struct {
		Findings []models.Finding
	}{
		Findings: findings,
	}
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func bestTitle(finding models.Finding) string {
	return defaultValue(finding.Title, defaultValue(finding.Description, finding.FindingID))
}

func bestHost(finding models.Finding) string {
	if finding.Host != "" {
		return finding.Host
	}
	if finding.URL == "" {
		return ""
	}
	u, err := url.Parse(finding.URL)
	if err != nil {
		return ""
	}
	return u.Host
}

func findingNucleiTarget(finding models.Finding) string {
	if finding.URL != "" {
		u, err := url.Parse(finding.URL)
		if err == nil && u.Host != "" {
			return u.Host
		}
	}
	return finding.Host
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func escapePipes(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func xmlEscape(value string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(value)); err != nil {
		return value
	}
	return buf.String()
}

func WriteExport(w io.Writer, format string, findings []models.Finding) error {
	data, err := renderExport(format, findings)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func MarshalFindingJSON(finding models.Finding) ([]byte, error) {
	return json.Marshal(toJSONFinding(finding))
}

func toJSONFinding(finding models.Finding) jsonFinding {
	return jsonFinding{
		FindingID:   finding.FindingID,
		ScanID:      finding.ScanID,
		Target:      finding.Target,
		Type:        finding.Type,
		Severity:    finding.Severity,
		Module:      finding.Module,
		Tool:        finding.Tool,
		Host:        finding.Host,
		URL:         finding.URL,
		Title:       finding.Title,
		Description: finding.Description,
		Evidence:    finding.Evidence,
		Reference:   finding.Reference,
		Tags:        finding.Tags,
		RawOutput:   finding.RawOutput,
		RequestRaw:  finding.RequestRaw,
		ResponseRaw: finding.ResponseRaw,
		Notes:       finding.Notes,
		Fingerprint: finding.Fingerprint,
	}
}
