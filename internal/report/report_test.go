package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReportFromResults(t *testing.T) {
	sr := module.NewScanResults()
	sr.AddSubdomains([]string{"a.example.com", "b.example.com"})
	sr.AddLiveHosts([]string{"http://a.example.com"})
	sr.AddURLs([]string{"http://a.example.com/page1"})
	sr.AddEmails([]string{"admin@example.com"})
	sr.AddFindings([]module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "a.example.com", Detail: "CVE-2024-1234"},
		{Module: "xss", Type: "vuln", Severity: "high", Target: "a.example.com", Detail: "XSS found"},
		{Module: "spf", Type: "info", Severity: "info", Target: "example.com", Detail: "No SPF"},
	})

	report := NewReportFromResults("example.com", "recon", sr, time.Now().Add(-5*time.Minute))

	assert.Equal(t, "example.com", report.Target)
	assert.Equal(t, "recon", report.ScanMode)
	assert.Equal(t, 2, report.Stats.SubdomainCount)
	assert.Equal(t, 1, report.Stats.LiveHostCount)
	assert.Equal(t, 1, report.Stats.URLCount)
	assert.Equal(t, 1, report.Stats.EmailCount)
	assert.Equal(t, 3, report.Stats.FindingCount)
	assert.Equal(t, 1, report.Stats.BySeverity["critical"])
	assert.Equal(t, 1, report.Stats.BySeverity["high"])
	assert.Equal(t, 1, report.Stats.BySeverity["info"])
}

func TestExportJSON(t *testing.T) {
	sr := module.NewScanResults()
	sr.AddSubdomains([]string{"test.example.com"})
	report := NewReportFromResults("example.com", "recon", sr, time.Now())

	tmpDir := t.TempDir()
	path, err := report.ExportJSON(tmpDir)
	require.NoError(t, err)
	assert.FileExists(t, path)

	data, _ := os.ReadFile(path)
	assert.Contains(t, string(data), "example.com")
	assert.Contains(t, string(data), "test.example.com")
}

func TestExportMarkdown(t *testing.T) {
	sr := module.NewScanResults()
	sr.AddSubdomains([]string{"test.example.com"})
	sr.AddFindings([]module.Finding{
		{Module: "nuclei", Severity: "critical", Target: "test.example.com", Detail: "CVE found"},
	})
	report := NewReportFromResults("example.com", "recon", sr, time.Now())

	tmpDir := t.TempDir()
	path, err := report.ExportMarkdown(tmpDir)
	require.NoError(t, err)
	assert.FileExists(t, path)

	data, _ := os.ReadFile(path)
	content := string(data)
	assert.Contains(t, content, "# ReconForge Report")
	assert.Contains(t, content, "CRITICAL")
	assert.Contains(t, content, "CVE found")
}

func TestExportHTML(t *testing.T) {
	sr := module.NewScanResults()
	sr.AddSubdomains([]string{"test.example.com"})
	report := NewReportFromResults("example.com", "recon", sr, time.Now())

	tmpDir := t.TempDir()
	path, err := report.ExportHTML(tmpDir)
	require.NoError(t, err)
	assert.FileExists(t, path)

	data, _ := os.ReadFile(path)
	content := string(data)
	assert.Contains(t, content, "<!DOCTYPE html>")
	assert.Contains(t, content, "example.com")
	assert.Contains(t, content, "ReconForge Report")
}

func TestExportAll(t *testing.T) {
	sr := module.NewScanResults()
	report := NewReportFromResults("example.com", "recon", sr, time.Now())

	tmpDir := t.TempDir()
	files, err := report.ExportAll(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, 3, len(files))

	// Check all files exist
	assert.FileExists(t, filepath.Join(tmpDir, "report.json"))
	assert.FileExists(t, filepath.Join(tmpDir, "report.md"))
	assert.FileExists(t, filepath.Join(tmpDir, "report.html"))
}

func TestSeverityIcon(t *testing.T) {
	assert.Equal(t, "🔴", severityIcon("critical"))
	assert.Equal(t, "🟠", severityIcon("high"))
	assert.Equal(t, "🟡", severityIcon("medium"))
	assert.Equal(t, "🔵", severityIcon("low"))
	assert.Equal(t, "⚪", severityIcon("info"))
}
