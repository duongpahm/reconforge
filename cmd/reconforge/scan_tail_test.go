package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/reconforge/reconforge/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildScanCommandArgs(t *testing.T) {
	oldCfgFile, oldProxyURL, oldScanDomain := cfgFile, proxyURL, scanDomain
	oldScanList, oldScanCIDR, oldScanMode := scanList, scanCIDR, scanMode
	oldScanProfile, oldScanResume := scanProfile, scanResume
	oldScanPrefix, oldScanDryRun := scanPrefix, scanDryRun
	oldScanInScope, oldScanParallel := scanInScope, scanParallel
	oldVerbose := verbose
	t.Cleanup(func() {
		cfgFile, proxyURL, scanDomain = oldCfgFile, oldProxyURL, oldScanDomain
		scanList, scanCIDR, scanMode = oldScanList, oldScanCIDR, oldScanMode
		scanProfile, scanResume = oldScanProfile, oldScanResume
		scanPrefix, scanDryRun = oldScanPrefix, oldScanDryRun
		scanInScope, scanParallel = oldScanInScope, oldScanParallel
		verbose = oldVerbose
	})

	cfgFile = "/tmp/test-config.yaml"
	proxyURL = "http://127.0.0.1:8080"
	verbose = true
	scanDomain = "example.com"
	scanList = "targets.txt"
	scanCIDR = "10.0.0.0/24"
	scanMode = "osint"
	scanProfile = "quick"
	scanResume = true
	scanPrefix = "eng"
	scanDryRun = true
	scanInScope = "./scope.txt"
	scanParallel = 3

	args := buildScanCommandArgs()
	assert.Equal(t, []string{
		"scan",
		"--config", "/tmp/test-config.yaml",
		"--proxy", "http://127.0.0.1:8080",
		"--verbose",
		"--domain", "example.com",
		"--list", "targets.txt",
		"--cidr", "10.0.0.0/24",
		"--mode", "osint",
		"--profile", "quick",
		"--resume",
		"--prefix", "eng",
		"--dry-run",
		"--inscope", "./scope.txt",
		"--parallel", "3",
	}, args)
}

func TestFollowStateFileWaitsForNewScan(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	sm, err := engine.NewStateManager(dbPath)
	require.NoError(t, err)
	defer sm.Close()

	oldScanID, err := sm.StartScan("example.com", "recon")
	require.NoError(t, err)
	require.NoError(t, sm.UpdateModule(oldScanID, "old_mod", engine.StatusComplete, 1, 0.1, ""))
	require.NoError(t, sm.MarkComplete(oldScanID))

	startedAfter := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- followStateFile(context.Background(), "example.com", dbPath, startedAfter)
	}()

	// State timestamps are persisted with second precision, so ensure the
	// replacement scan starts in a later second than startedAfter.
	for time.Now().Unix() == startedAfter.Unix() {
		time.Sleep(50 * time.Millisecond)
	}

	newScanID, err := sm.StartScan("example.com", "recon")
	require.NoError(t, err)
	require.NoError(t, sm.UpdateModule(newScanID, "new_mod", engine.StatusComplete, 2, 0.1, ""))
	require.NoError(t, sm.MarkComplete(newScanID))

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("followStateFile did not return for new completed scan")
	}
}
