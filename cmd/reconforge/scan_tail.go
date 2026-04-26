package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/exitcode"
	"github.com/spf13/cobra"
)

var scanTail bool

func runScanWithTail(cmd *cobra.Command, cfg *config.Config, targets []string) error {
	if len(targets) != 1 {
		return exitcode.Usage(fmt.Errorf("--tail currently supports exactly one target"))
	}

	target := targets[0]
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	dirName := target
	if scanPrefix != "" {
		dirName = scanPrefix + "_" + target
	}
	outputDir := filepath.Join(cfg.General.OutputDir, dirName)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	logFile := filepath.Join(outputDir, "scan.tail.log")
	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer lf.Close()

	child := exec.Command(exe, buildScanCommandArgs()...)
	child.Stdout = lf
	child.Stderr = lf
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		return fmt.Errorf("start background scan: %w", err)
	}

	fmt.Printf("Following scan for %s (pid=%d). Press Ctrl+C to stop following; scan keeps running.\n", target, child.Process.Pid)

	sigCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	statePath := filepath.Join(outputDir, "state.db")
	if err := followStateFile(sigCtx, target, statePath, time.Now().Add(-2*time.Second)); err != nil {
		if sigCtx.Err() != nil {
			fmt.Printf("\nStopped following. Scan is still running in background (pid=%d).\n", child.Process.Pid)
			return nil
		}
		return err
	}

	return nil
}

func buildScanCommandArgs() []string {
	args := []string{"scan"}
	if cfgFile != "" {
		args = append(args, "--config", cfgFile)
	}
	if proxyURL != "" {
		args = append(args, "--proxy", proxyURL)
	}
	if verbose {
		args = append(args, "--verbose")
	}
	if scanDomain != "" {
		args = append(args, "--domain", scanDomain)
	}
	if scanList != "" {
		args = append(args, "--list", scanList)
	}
	if scanCIDR != "" {
		args = append(args, "--cidr", scanCIDR)
	}
	if scanMode != "" {
		args = append(args, "--mode", scanMode)
	}
	if scanProfile != "" {
		args = append(args, "--profile", scanProfile)
	}
	if scanResume {
		args = append(args, "--resume")
	}
	if scanPrefix != "" {
		args = append(args, "--prefix", scanPrefix)
	}
	if scanDryRun {
		args = append(args, "--dry-run")
	}
	if scanInScope != "" {
		args = append(args, "--inscope", scanInScope)
	}
	if scanParallel > 0 {
		args = append(args, "--parallel", strconv.Itoa(scanParallel))
	}
	return args
}

func followStateFile(ctx context.Context, target, dbPath string, startedAfter time.Time) error {
	var lastRendered string

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sm, err := engine.NewStateManager(dbPath)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		state, err := sm.GetLastScan(target)
		_ = sm.Close()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if state == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if state.StartedAt.Before(startedAfter) {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		rendered, err := renderTailState(state, "auto")
		if err != nil {
			return err
		}
		if rendered != lastRendered {
			fmt.Print(rendered)
			lastRendered = rendered
		}

		switch state.Status {
		case engine.StatusComplete:
			return nil
		case engine.StatusFailed:
			return exitcode.Scan(fmt.Errorf("scan failed for %s", target))
		}

		time.Sleep(1 * time.Second)
	}
}
