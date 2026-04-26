package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/daemon"
	"github.com/duongpahm/ReconForge/internal/notify"
	"github.com/duongpahm/ReconForge/internal/project"
	"github.com/duongpahm/ReconForge/internal/ui"
	"github.com/spf13/cobra"
)

var (
	monitorTarget      string
	monitorInterval    time.Duration
	monitorMinSeverity string
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Continuous scan monitoring",
}

var monitorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a background monitor",
	RunE: func(cmd *cobra.Command, args []string) error {
		if monitorTarget == "" {
			return fmt.Errorf("--target is required")
		}

		home, _ := os.UserHomeDir()
		pidFile := filepath.Join(home, ".reconforge", "run", fmt.Sprintf("monitor_%s.pid", monitorTarget))
		logFile := filepath.Join(home, ".reconforge", "logs", fmt.Sprintf("monitor_%s.log", monitorTarget))

		if running, pid := daemon.IsRunning(pidFile); running {
			return fmt.Errorf("monitor for %s is already running with PID %d", monitorTarget, pid)
		}

		// Reconstruct the command to run the foreground daemon
		exe, err := os.Executable()
		if err != nil {
			return err
		}

		daemonArgs := []string{
			"monitor", "run",
			"-t", monitorTarget,
			"--interval", monitorInterval.String(),
			"--min-severity", monitorMinSeverity,
		}

		if err := daemon.StartBackground(exe, daemonArgs, pidFile, logFile); err != nil {
			return fmt.Errorf("failed to start monitor: %w", err)
		}

		fmt.Printf("[+] Monitor started for %s\n", monitorTarget)
		fmt.Printf("[-] Log file: %s\n", logFile)
		return nil
	},
}

var monitorRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Internal: Run the monitoring loop",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if monitorTarget == "" {
			return fmt.Errorf("--target is required")
		}

		fmt.Printf("Starting monitoring loop for %s every %s...\n", monitorTarget, monitorInterval)
		ticker := time.NewTicker(monitorInterval)
		defer ticker.Stop()

		// Run once immediately
		runMonitorCycle()

		for range ticker.C {
			runMonitorCycle()
		}
		return nil
	},
}

var monitorStopCmd = &cobra.Command{
	Use:   "stop <target>",
	Short: "Stop a background monitor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		home, _ := os.UserHomeDir()
		pidFile := filepath.Join(home, ".reconforge", "run", fmt.Sprintf("monitor_%s.pid", target))

		if err := daemon.StopBackground(pidFile); err != nil {
			return err
		}

		fmt.Printf("[-] Monitor for %s stopped.\n", target)
		return nil
	},
}

var monitorStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "List active monitors",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		runDir := filepath.Join(home, ".reconforge", "run")

		files, err := os.ReadDir(runDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No active monitors.")
				return nil
			}
			return err
		}

		t := ui.NewTable([]string{"Target", "PID", "Status"})
		active := 0

		for _, f := range files {
			if strings.HasPrefix(f.Name(), "monitor_") && strings.HasSuffix(f.Name(), ".pid") {
				target := strings.TrimSuffix(strings.TrimPrefix(f.Name(), "monitor_"), ".pid")
				pidFile := filepath.Join(runDir, f.Name())
				if running, pid := daemon.IsRunning(pidFile); running {
					t.AddRow([]string{target, fmt.Sprintf("%d", pid), "Running"})
					active++
				} else {
					// Clean up dead pid file
					os.Remove(pidFile)
				}
			}
		}

		if active == 0 {
			fmt.Println("No active monitors.")
			return nil
		}

		t.Render()
		return nil
	},
}

func runMonitorCycle() {
	fmt.Printf("[%s] Running scan cycle for %s...\n", time.Now().Format(time.RFC3339), monitorTarget)

	// Execute the scan programmatically. We can reuse the scan logic by setting up arguments
	// and calling the scanCmd, or directly invoking the orchestrator.
	// For simplicity in CLI mapping, we will invoke the scan process by executing ourselves.
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error resolving executable: %v\n", err)
		return
	}

	cmd := exec.Command(exe, monitorScanArgs(monitorTarget)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[%s] Scan cycle failed: %v\n", time.Now().Format(time.RFC3339), err)
	} else {
		fmt.Printf("[%s] Scan cycle completed successfully.\n", time.Now().Format(time.RFC3339))
	}

	// Trigger diff and notify
	pm, err := project.NewManager()
	if err == nil {
		defer pm.Close()
		scans, err := pm.GetLastNScans(monitorTarget, 2)
		if err == nil && len(scans) == 2 {
			baseScanID := scans[1].RunID
			compareScanID := scans[0].RunID
			scanDiff, err := pm.DiffScans(baseScanID, compareScanID)
			if err == nil && len(scanDiff.Added) > 0 {
				fmt.Printf("[%s] Found %d new findings. Processing rules...\n", time.Now().Format(time.RFC3339), len(scanDiff.Added))

				home, _ := os.UserHomeDir()
				rulesPath := filepath.Join(home, ".reconforge", "notify_rules.json")
				if engine, err := notify.LoadRules(rulesPath); err == nil {
					engine.ProcessDelta(monitorTarget, scanDiff.Added)
				}
			}
		}
	}
}

func monitorScanArgs(target string) []string {
	return []string{"scan", "--domain", target}
}

func init() {
	monitorStartCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target to monitor")
	monitorStartCmd.Flags().DurationVar(&monitorInterval, "interval", 60*time.Minute, "Monitoring interval (e.g. 60m, 12h)")
	monitorStartCmd.Flags().StringVar(&monitorMinSeverity, "min-severity", "low", "Minimum severity to trigger alert")

	monitorRunCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target to monitor")
	monitorRunCmd.Flags().DurationVar(&monitorInterval, "interval", 60*time.Minute, "Monitoring interval")
	monitorRunCmd.Flags().StringVar(&monitorMinSeverity, "min-severity", "low", "Minimum severity")

	monitorCmd.AddCommand(monitorStartCmd, monitorRunCmd, monitorStopCmd, monitorStatusCmd)
	rootCmd.AddCommand(monitorCmd)
}
