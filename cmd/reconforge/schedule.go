package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/reconforge/reconforge/internal/daemon"
	"github.com/reconforge/reconforge/internal/notify"
	"github.com/reconforge/reconforge/internal/project"
	"github.com/reconforge/reconforge/internal/ui"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
)

var (
	scheduleTarget string
	scheduleCron   string
	scheduleMode   string
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Cron-based scan scheduling",
}

var scheduleAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new scan schedule",
	RunE: func(cmd *cobra.Command, args []string) error {
		if scheduleTarget == "" || scheduleCron == "" {
			return fmt.Errorf("--target and --cron are required")
		}

		// Validate cron expression
		if _, err := cron.ParseStandard(scheduleCron); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}

		home, _ := os.UserHomeDir()
		pidFile := filepath.Join(home, ".reconforge", "run", fmt.Sprintf("cron_%s.pid", scheduleTarget))
		logFile := filepath.Join(home, ".reconforge", "logs", fmt.Sprintf("cron_%s.log", scheduleTarget))

		if running, pid := daemon.IsRunning(pidFile); running {
			return fmt.Errorf("schedule for %s is already running with PID %d", scheduleTarget, pid)
		}

		exe, err := os.Executable()
		if err != nil {
			return err
		}

		daemonArgs := []string{
			"schedule", "run",
			"-t", scheduleTarget,
			"--cron", scheduleCron,
			"--mode", scheduleMode,
		}

		if err := daemon.StartBackground(exe, daemonArgs, pidFile, logFile); err != nil {
			return fmt.Errorf("failed to start schedule: %w", err)
		}

		fmt.Printf("[+] Schedule added for %s (Cron: %s)\n", scheduleTarget, scheduleCron)
		return nil
	},
}

var scheduleRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Internal: Run the cron loop",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		c := cron.New()

		_, err := c.AddFunc(scheduleCron, func() {
			runCronCycle()
		})
		if err != nil {
			return err
		}

		fmt.Printf("Starting cron scheduler for %s with expression: %s\n", scheduleTarget, scheduleCron)
		c.Start()

		// Block forever
		select {}
	},
}

var scheduleRemoveCmd = &cobra.Command{
	Use:   "remove <target>",
	Short: "Remove a schedule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		home, _ := os.UserHomeDir()
		pidFile := filepath.Join(home, ".reconforge", "run", fmt.Sprintf("cron_%s.pid", target))

		if err := daemon.StopBackground(pidFile); err != nil {
			return err
		}

		fmt.Printf("[-] Schedule for %s removed.\n", target)
		return nil
	},
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active schedules",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		runDir := filepath.Join(home, ".reconforge", "run")

		files, err := os.ReadDir(runDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No active schedules.")
				return nil
			}
			return err
		}

		t := ui.NewTable([]string{"Target", "PID", "Status"})
		active := 0

		for _, f := range files {
			if strings.HasPrefix(f.Name(), "cron_") && strings.HasSuffix(f.Name(), ".pid") {
				target := strings.TrimSuffix(strings.TrimPrefix(f.Name(), "cron_"), ".pid")
				pidFile := filepath.Join(runDir, f.Name())
				if running, pid := daemon.IsRunning(pidFile); running {
					t.AddRow([]string{target, fmt.Sprintf("%d", pid), "Scheduled"})
					active++
				} else {
					os.Remove(pidFile)
				}
			}
		}

		if active == 0 {
			fmt.Println("No active schedules.")
			return nil
		}

		t.Render()
		return nil
	},
}

func runCronCycle() {
	fmt.Printf("[CRON] Running scheduled scan for %s...\n", scheduleTarget)

	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error resolving executable: %v\n", err)
		return
	}

	cmd := exec.Command(exe, scheduleScanArgs(scheduleTarget, scheduleMode)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[CRON] Scan cycle failed: %v\n", err)
	} else {
		fmt.Printf("[CRON] Scan cycle completed successfully.\n")
	}

	// Trigger diff and notify
	pm, err := project.NewManager()
	if err == nil {
		defer pm.Close()
		scans, err := pm.GetLastNScans(scheduleTarget, 2)
		if err == nil && len(scans) == 2 {
			baseScanID := scans[1].RunID
			compareScanID := scans[0].RunID
			scanDiff, err := pm.DiffScans(baseScanID, compareScanID)
			if err == nil && len(scanDiff.Added) > 0 {
				fmt.Printf("[CRON] Found %d new findings. Processing rules...\n", len(scanDiff.Added))

				home, _ := os.UserHomeDir()
				rulesPath := filepath.Join(home, ".reconforge", "notify_rules.json")
				if engine, err := notify.LoadRules(rulesPath); err == nil {
					engine.ProcessDelta(scheduleTarget, scanDiff.Added)
				}
			}
		}
	}
}

func scheduleScanArgs(target, mode string) []string {
	args := []string{"scan", "--domain", target}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	return args
}

func init() {
	scheduleAddCmd.Flags().StringVarP(&scheduleTarget, "target", "t", "", "Target to schedule")
	scheduleAddCmd.Flags().StringVar(&scheduleCron, "cron", "", "Cron expression (e.g., '0 2 * * *')")
	scheduleAddCmd.Flags().StringVarP(&scheduleMode, "mode", "m", "web", "Scan mode (web, full, etc.)")

	scheduleRunCmd.Flags().StringVarP(&scheduleTarget, "target", "t", "", "Target")
	scheduleRunCmd.Flags().StringVar(&scheduleCron, "cron", "", "Cron expression")
	scheduleRunCmd.Flags().StringVarP(&scheduleMode, "mode", "m", "web", "Scan mode")

	scheduleCmd.AddCommand(scheduleAddCmd, scheduleRunCmd, scheduleRemoveCmd, scheduleListCmd)
	rootCmd.AddCommand(scheduleCmd)
}
