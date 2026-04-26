package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/project"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withCLIProjectManager(t *testing.T) *project.Manager {
	t.Helper()

	t.Setenv("HOME", t.TempDir())

	pm, err := project.NewManager()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pm.Close())
	})

	return pm
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	require.NoError(t, w.Close())
	os.Stdout = old
	return <-done
}

func TestProjectCommandsLifecycle(t *testing.T) {
	_ = withCLIProjectManager(t)

	oldScope := projectScopePath
	t.Cleanup(func() {
		projectScopePath = oldScope
	})

	projectScopePath = "/tmp/acme.scope"
	out := captureStdout(t, func() {
		require.NoError(t, projectCreateCmd.RunE(projectCreateCmd, []string{"acme"}))
	})
	assert.Contains(t, out, "created successfully")

	out = captureStdout(t, func() {
		require.NoError(t, projectAddTargetCmd.RunE(projectAddTargetCmd, []string{"acme", "app.acme.test"}))
	})
	assert.Contains(t, out, "added to project")

	out = captureStdout(t, func() {
		require.NoError(t, projectListCmd.RunE(projectListCmd, nil))
	})
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "/tmp/acme.scope")

	out = captureStdout(t, func() {
		require.NoError(t, projectArchiveCmd.RunE(projectArchiveCmd, []string{"acme"}))
	})
	assert.Contains(t, out, "archived")
}

func TestFindingsCommands(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.SaveFindings("scan-1", "acme.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "app.acme.test", Detail: "CVE-123", URL: "https://app.acme.test", Host: "app.acme.test"},
	}))

	findings, err := pm.ListFindings("acme.test", "", "", "", "")
	require.NoError(t, err)
	require.Len(t, findings, 1)

	oldTarget, oldFormat, oldTag := findingsTarget, findingsFormat, findingsTag
	t.Cleanup(func() {
		findingsTarget = oldTarget
		findingsFormat = oldFormat
		findingsTag = oldTag
	})

	findingsTarget = "acme.test"
	findingsFormat = "plain"
	out := captureStdout(t, func() {
		require.NoError(t, findingsListCmd.RunE(findingsListCmd, nil))
	})
	assert.Contains(t, out, "app.acme.test")
	assert.Contains(t, out, "https://app.acme.test")

	findingsFormat = "json"
	out = captureStdout(t, func() {
		require.NoError(t, findingsShowCmd.RunE(findingsShowCmd, []string{findings[0].FindingID}))
	})
	assert.Contains(t, out, findings[0].FindingID)
	assert.Contains(t, out, `"Severity": "critical"`)

	out = captureStdout(t, func() {
		require.NoError(t, findingsTagCmd.RunE(findingsTagCmd, []string{findings[0].FindingID, "triaged"}))
	})
	assert.Contains(t, out, "Tagged")

	findingsTag = "triaged"
	findingsFormat = "plain"
	out = captureStdout(t, func() {
		require.NoError(t, findingsListCmd.RunE(findingsListCmd, nil))
	})
	assert.Contains(t, out, "app.acme.test")
}

func TestDiffCommandJSON(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.SaveFindings("scan-1", "acme.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "high", Target: "old.acme.test", Detail: "legacy", URL: "https://old.acme.test", Host: "old.acme.test"},
		{Module: "nuclei", Type: "vuln", Severity: "medium", Target: "same.acme.test", Detail: "stable", URL: "https://same.acme.test", Host: "same.acme.test"},
	}))
	require.NoError(t, pm.SaveFindings("scan-2", "acme.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "new.acme.test", Detail: "fresh", URL: "https://new.acme.test", Host: "new.acme.test"},
		{Module: "nuclei", Type: "vuln", Severity: "medium", Target: "same.acme.test", Detail: "stable", URL: "https://same.acme.test", Host: "same.acme.test"},
	}))

	oldTarget, oldFrom, oldTo, oldLast, oldFormat := diffTarget, diffFrom, diffTo, diffLast, diffFormat
	t.Cleanup(func() {
		diffTarget = oldTarget
		diffFrom = oldFrom
		diffTo = oldTo
		diffLast = oldLast
		diffFormat = oldFormat
	})

	diffTarget = "acme.test"
	diffLast = 2
	diffFrom = ""
	diffTo = ""
	diffFormat = "json"

	out := captureStdout(t, func() {
		require.NoError(t, diffCmd.RunE(diffCmd, nil))
	})
	assert.Contains(t, out, `"change":"added"`)
	assert.Contains(t, out, `"change":"removed"`)
	assert.Contains(t, out, `"change":"unchanged"`)
}
