package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/duongpahm/ReconForge/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotifyRuleLifecycleCommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	oldName, oldTarget, oldMinSeverity, oldKeywords, oldWebhook := ruleName, ruleTarget, ruleMinSeverity, ruleKeywords, ruleWebhook
	t.Cleanup(func() {
		ruleName = oldName
		ruleTarget = oldTarget
		ruleMinSeverity = oldMinSeverity
		ruleKeywords = oldKeywords
		ruleWebhook = oldWebhook
	})

	ruleName = "critical-web"
	ruleTarget = "acme\\.test"
	ruleMinSeverity = "high"
	ruleKeywords = "rce,ssrf"
	ruleWebhook = "https://example.test/hook"

	out := captureStdout(t, func() {
		require.NoError(t, notifyRuleAddCmd.RunE(notifyRuleAddCmd, []string{"rule-1"}))
	})
	assert.Contains(t, out, "added successfully")

	engine, err := notify.LoadRules(getRulesPath())
	require.NoError(t, err)
	require.Len(t, engine.Rules, 1)
	assert.Equal(t, "rule-1", engine.Rules[0].ID)
	assert.Equal(t, []string{"rce", "ssrf"}, engine.Rules[0].Keywords)

	out = captureStdout(t, func() {
		require.NoError(t, notifyRuleListCmd.RunE(notifyRuleListCmd, nil))
	})
	assert.Contains(t, out, "rule-1")
	assert.Contains(t, out, "critical-web")
	assert.Contains(t, out, "https://example.test/hook")

	out = captureStdout(t, func() {
		require.NoError(t, notifyRuleRemoveCmd.RunE(notifyRuleRemoveCmd, []string{"rule-1"}))
	})
	assert.Contains(t, out, "removed")

	engine, err = notify.LoadRules(getRulesPath())
	require.NoError(t, err)
	assert.Empty(t, engine.Rules)
}

func TestNotifyRuleListEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		require.NoError(t, notifyRuleListCmd.RunE(notifyRuleListCmd, nil))
	})
	assert.Contains(t, out, "No notification rules configured.")
}

func TestNotifyRuleAddDuplicate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	engine := &notify.RuleEngine{
		Rules: []notify.Rule{{ID: "rule-1", Name: "existing"}},
	}
	require.NoError(t, engine.SaveRules(getRulesPath()))

	err := notifyRuleAddCmd.RunE(notifyRuleAddCmd, []string{"rule-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestCacheClearCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cacheDir := filepath.Join(home, ".reconforge", "cache")
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "nested", "artifact.txt"), []byte("stale"), 0o644))

	out := captureStdout(t, func() {
		require.NoError(t, cacheClearCmd.RunE(cacheClearCmd, nil))
	})
	assert.Contains(t, out, "Cache cleared successfully.")

	info, err := os.Stat(cacheDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestGetRulesPathUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	assert.Equal(t, filepath.Join(home, ".reconforge", "notify_rules.json"), getRulesPath())
}
