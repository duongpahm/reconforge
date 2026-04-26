package project

import (
	"testing"

	"github.com/reconforge/reconforge/internal/module"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withTestManager(t *testing.T) *Manager {
	t.Helper()

	t.Setenv("HOME", t.TempDir())

	manager, err := NewManager()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close())
	})

	return manager
}

func TestManager_ProjectLifecycle(t *testing.T) {
	manager := withTestManager(t)

	require.NoError(t, manager.CreateProject("acme", "/tmp/acme.scope"))
	require.NoError(t, manager.AddTarget("acme", "app.acme.test"))
	require.NoError(t, manager.AddTarget("acme", "api.acme.test"))

	projects, err := manager.ListProjects()
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, "acme", projects[0].Name)
	assert.Equal(t, "/tmp/acme.scope", projects[0].ScopePath)

	project, err := manager.GetProject("acme")
	require.NoError(t, err)
	require.Len(t, project.Targets, 2)
	assert.Equal(t, "active", project.Status)

	targets, err := manager.ListTargetNames("app")
	require.NoError(t, err)
	assert.Equal(t, []string{"app.acme.test"}, targets)

	require.NoError(t, manager.ArchiveProject("acme"))
	project, err = manager.GetProject("acme")
	require.NoError(t, err)
	assert.Equal(t, "archived", project.Status)
}

func TestManager_FindingsWorkflow(t *testing.T) {
	manager := withTestManager(t)

	baseScanID := "scan-001"
	compareScanID := "scan-002"
	baseFindings := []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "high", Target: "app.acme.test", Detail: "CVE-1", URL: "https://app.acme.test/a", Host: "app.acme.test"},
		{Module: "httpx", Type: "info", Severity: "low", Target: "api.acme.test", Detail: "banner", URL: "https://api.acme.test/", Host: "api.acme.test"},
	}
	compareFindings := []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "high", Target: "app.acme.test", Detail: "CVE-1", URL: "https://app.acme.test/a", Host: "app.acme.test"},
		{Module: "nuclei", Type: "vuln", Severity: "critical", Target: "app.acme.test", Detail: "CVE-2", URL: "https://app.acme.test/b", Host: "app.acme.test"},
	}

	require.NoError(t, manager.SaveFindings(baseScanID, "acme.test", baseFindings))
	require.NoError(t, manager.SaveFindings(compareScanID, "acme.test", compareFindings))

	scans, err := manager.GetLastNScans("acme.test", 2)
	require.NoError(t, err)
	require.Len(t, scans, 2)
	assert.Equal(t, compareScanID, scans[0].RunID)
	assert.Equal(t, baseScanID, scans[1].RunID)

	listed, err := manager.ListFindings("acme.test", "critical", "", "", "")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "critical", listed[0].Severity)

	finding, err := manager.GetFinding(listed[0].FindingID)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2", finding.Description)

	require.NoError(t, manager.UpdateFindingTag(finding.FindingID, "triaged", false))
	require.NoError(t, manager.UpdateFindingNote(finding.FindingID, "needs ticket"))

	updated, err := manager.GetFinding(finding.FindingID)
	require.NoError(t, err)
	assert.Contains(t, updated.Tags, "triaged")
	assert.Equal(t, "needs ticket", updated.Notes)

	diff, err := manager.DiffScans(baseScanID, compareScanID)
	require.NoError(t, err)
	assert.Len(t, diff.Added, 1)
	assert.Len(t, diff.Removed, 1)
	assert.Len(t, diff.Unchanged, 1)
}

func TestManager_DedupFindings(t *testing.T) {
	manager := withTestManager(t)

	dupes := []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "high", Target: "dup.acme.test", Detail: "same", URL: "https://dup.acme.test", Host: "dup.acme.test"},
	}

	require.NoError(t, manager.SaveFindings("scan-dup-1", "acme.test", dupes))
	require.NoError(t, manager.SaveFindings("scan-dup-2", "acme.test", dupes))

	count, err := manager.DedupFindings("acme.test", true)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)

	findings, err := manager.ListFindings("acme.test", "", "duplicate", "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, findings)
}
