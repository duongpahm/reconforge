package daemon

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelperDaemonProcess(t *testing.T) {
	if os.Getenv("RECONFORGE_DAEMON_HELPER") != "1" {
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	<-sigCh
	os.Exit(0)
}

func TestStartBackgroundAndStopBackground(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "run", "worker.pid")
	logFile := filepath.Join(dir, "logs", "worker.log")

	exe, err := os.Executable()
	require.NoError(t, err)

	t.Setenv("RECONFORGE_DAEMON_HELPER", "1")

	require.NoError(t, StartBackground(exe, []string{"-test.run=TestHelperDaemonProcess"}, pidFile, logFile))

	var pid int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(string(data))
		if err != nil {
			return false
		}
		running, runningPID := IsRunning(pidFile)
		return running && runningPID == pid
	}, 3*time.Second, 50*time.Millisecond)

	require.NoError(t, StopBackground(pidFile))
	assert.Eventually(t, func() bool {
		running, _ := IsRunning(pidFile)
		return !running
	}, 3*time.Second, 50*time.Millisecond)
}

func TestIsRunningInvalidPIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "bad.pid")
	require.NoError(t, os.WriteFile(pidFile, []byte("not-a-pid"), 0o644))

	running, pid := IsRunning(pidFile)
	assert.False(t, running)
	assert.Zero(t, pid)
}

func TestStopBackgroundMissingPIDFile(t *testing.T) {
	err := StopBackground(filepath.Join(t.TempDir(), "missing.pid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not read pid file")
}
