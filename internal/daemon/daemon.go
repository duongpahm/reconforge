package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// StartBackground runs a command in the background, writing output to logFile and saving its PID to pidFile.
func StartBackground(name string, args []string, pidFile string, logFile string) error {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(pidFile), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return err
	}

	cmd := exec.Command(name, args...)

	// Open log file
	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	
	cmd.Stdout = lf
	cmd.Stderr = lf

	// Run in background and detach
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // detaches from the current terminal
	}

	if err := cmd.Start(); err != nil {
		lf.Close()
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// We can safely close the log file descriptor in the parent process
	lf.Close()

	// Write PID to file
	pidStr := strconv.Itoa(cmd.Process.Pid)
	if err := os.WriteFile(pidFile, []byte(pidStr), 0o644); err != nil {
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	return nil
}

// StopBackground reads the PID from pidFile and sends a SIGTERM.
func StopBackground(pidFile string) error {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("could not read pid file (is it running?): %w", err)
	}

	pid, err := strconv.Atoi(string(b))
	if err != nil {
		return fmt.Errorf("invalid pid in file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// If error is "os: process already finished", just clean up the file
		if err.Error() == "os: process already finished" {
			os.Remove(pidFile)
			return nil
		}
		return fmt.Errorf("failed to send SIGTERM: %w", err)
	}

	// Clean up PID file
	os.Remove(pidFile)
	return nil
}

// IsRunning checks if the process specified in pidFile is currently running.
func IsRunning(pidFile string) (bool, int) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return false, 0
	}

	pid, err := strconv.Atoi(string(b))
	if err != nil {
		return false, 0
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}

	// Sending signal 0 checks if the process exists without actually sending a signal
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}

	return true, pid
}
