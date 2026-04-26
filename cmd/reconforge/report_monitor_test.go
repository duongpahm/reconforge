package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportCommandExecutiveAndFileOutput(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.SaveFindings("scan-report", "acme.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "app.acme.test", Detail: "RCE", URL: "https://app.acme.test", Host: "app.acme.test"},
	}))

	oldTarget, oldTemplate, oldOut, oldSeverity, oldTag := reportTarget, reportTemplate, reportOut, reportSeverity, reportTag
	t.Cleanup(func() {
		reportTarget = oldTarget
		reportTemplate = oldTemplate
		reportOut = oldOut
		reportSeverity = oldSeverity
		reportTag = oldTag
	})

	reportTarget = "acme.test"
	reportTemplate = "executive"
	reportSeverity = ""
	reportTag = ""
	reportOut = ""

	out := captureStdout(t, func() {
		require.NoError(t, reportCmd.RunE(reportCmd, nil))
	})
	assert.Contains(t, out, "Executive Summary")
	assert.Contains(t, out, "app.acme.test")

	reportTemplate = "hackerone"
	reportOut = filepath.Join(t.TempDir(), "report.md")

	out = captureStdout(t, func() {
		require.NoError(t, reportCmd.RunE(reportCmd, nil))
	})
	assert.Contains(t, out, "Report generated")

	data, err := os.ReadFile(reportOut)
	require.NoError(t, err)
	assert.Contains(t, string(data), "Proof of Concept")
	assert.Contains(t, string(data), "RCE")
}

func TestMonitorStatusNoActiveMonitors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		require.NoError(t, monitorStatusCmd.RunE(monitorStatusCmd, nil))
	})
	assert.Contains(t, out, "No active monitors.")
}

func TestMonitorScanArgs(t *testing.T) {
	assert.Equal(t, []string{"scan", "--domain", "example.com"}, monitorScanArgs("example.com"))
}

func TestReportCommandNoFindings(t *testing.T) {
	_ = withCLIProjectManager(t)

	oldTarget, oldTemplate, oldOut, oldSeverity, oldTag := reportTarget, reportTemplate, reportOut, reportSeverity, reportTag
	t.Cleanup(func() {
		reportTarget = oldTarget
		reportTemplate = oldTemplate
		reportOut = oldOut
		reportSeverity = oldSeverity
		reportTag = oldTag
	})

	reportTarget = "empty.test"
	reportTemplate = "executive"
	reportOut = ""
	reportSeverity = ""
	reportTag = ""

	err := reportCmd.RunE(reportCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no findings found")
}

func TestMonitorDeltaUsesStoredScans(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.SaveFindings("scan-a", "delta.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "low", Target: "old.delta.test", Detail: "old", URL: "https://old.delta.test", Host: "old.delta.test"},
	}))
	require.NoError(t, pm.SaveFindings("scan-b", "delta.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "new.delta.test", Detail: "new", URL: "https://new.delta.test", Host: "new.delta.test"},
	}))

	scans, err := pm.GetLastNScans("delta.test", 2)
	require.NoError(t, err)
	require.Len(t, scans, 2)

	diff, err := pm.DiffScans(scans[1].RunID, scans[0].RunID)
	require.NoError(t, err)
	assert.Len(t, diff.Added, 1)
	assert.Equal(t, "new.delta.test", diff.Added[0].Title)
}
