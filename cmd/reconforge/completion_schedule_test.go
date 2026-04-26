package main

import (
	"testing"

	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompleteTargetNames(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.CreateProject("acme", "/tmp/acme.scope"))
	require.NoError(t, pm.AddTarget("acme", "app.acme.test"))
	require.NoError(t, pm.AddTarget("acme", "api.acme.test"))

	targets, directive := completeTargetNames(completionCmd, nil, "ap")
	assert.Equal(t, []string{"api.acme.test", "app.acme.test"}, targets)
	assert.Equal(t, directive, directive&directive)
}

func TestCompletionCommandBashOutput(t *testing.T) {
	out := captureStdout(t, func() {
		require.NoError(t, completionCmd.RunE(completionCmd, []string{"bash"}))
	})
	assert.Contains(t, out, "complete")
	assert.Contains(t, out, "reconforge")
}

func TestScheduleListNoActiveSchedules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		require.NoError(t, scheduleListCmd.RunE(scheduleListCmd, nil))
	})
	assert.Contains(t, out, "No active schedules.")
}

func TestScheduleAddRejectsInvalidCron(t *testing.T) {
	oldTarget, oldCron, oldMode := scheduleTarget, scheduleCron, scheduleMode
	t.Cleanup(func() {
		scheduleTarget = oldTarget
		scheduleCron = oldCron
		scheduleMode = oldMode
	})

	scheduleTarget = "example.com"
	scheduleCron = "invalid cron"
	scheduleMode = "web"

	err := scheduleAddCmd.RunE(scheduleAddCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cron expression")
}

func TestScheduleScanArgs(t *testing.T) {
	assert.Equal(t, []string{"scan", "--domain", "example.com", "--mode", "web"}, scheduleScanArgs("example.com", "web"))
	assert.Equal(t, []string{"scan", "--domain", "example.com"}, scheduleScanArgs("example.com", ""))
}

func TestCompletionAndScheduleUseStoredTargets(t *testing.T) {
	pm := withCLIProjectManager(t)
	require.NoError(t, pm.SaveFindings("scan-comp", "acme.test", []module.Finding{
		{Module: "nuclei", Type: "vuln", Severity: "high", Target: "stored.acme.test", Detail: "issue", URL: "https://stored.acme.test", Host: "stored.acme.test"},
	}))
	require.NoError(t, pm.CreateProject("acme", "/tmp/acme.scope"))
	require.NoError(t, pm.AddTarget("acme", "stored.acme.test"))

	targets, _ := completeTargetNames(completionCmd, nil, "stored")
	assert.Equal(t, []string{"stored.acme.test"}, targets)
}
