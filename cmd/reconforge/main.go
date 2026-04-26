// Package main provides the CLI entry point for ReconForge.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/exitcode"
	"github.com/reconforge/reconforge/internal/ui"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/notify"
	"github.com/reconforge/reconforge/internal/orchestrator"
	"github.com/reconforge/reconforge/internal/report"
	"github.com/reconforge/reconforge/internal/runner"
)

var (
	cfgFile  string
	verbose  bool
	proxyURL string
	logger   zerolog.Logger
)

func main() {
	var output io.Writer = os.Stderr
	if ui.IsStderrTTY() {
		output = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		}
	}
	logger = zerolog.New(output).With().Timestamp().Logger()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(exitcode.Code(err))
	}
}

var rootCmd = &cobra.Command{
	Use:   "reconforge",
	Short: "ReconForge — All-in-One Offensive Reconnaissance Platform",
	Long: `ReconForge is a powerful reconnaissance framework that orchestrates 80+ security tools
for automated bug bounty hunting and penetration testing.

Built as a modern Go replacement for reconFTW, with DAG-based pipeline execution
and plugin-based extensibility for terminal-first workflows.`,
	Example: strings.TrimSpace(`
  reconforge init --yes
  reconforge scan -d example.com --profile quick
  reconforge findings list --target example.com --format ndjson
`),
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		runner.SetProxyEnv(proxyURL)
	},
}

// === SCAN COMMAND ===

var (
	scanDomain           string
	scanList             string
	scanCIDR             string
	scanMode             string
	scanProfile          string
	scanResume           bool
	scanPrefix           string
	scanDryRun           bool
	scanSkipMissingTools bool
	scanInScope          string
	scanParallel         int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run reconnaissance scan on a target",
	Long:  `Execute a full or partial reconnaissance scan on the specified target domain, list, or CIDR range.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return exitcode.Config(fmt.Errorf("load config: %w", err))
		}

		if scanDomain == "" && scanList == "" && scanCIDR == "" {
			return exitcode.Usage(fmt.Errorf("specify a target with -d (domain), -l (list), or --cidr"))
		}

		var targets []string
		if scanDomain != "" {
			for _, t := range strings.Split(scanDomain, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					targets = append(targets, t)
				}
			}
		}
		if scanList != "" {
			content, err := os.ReadFile(scanList)
			if err != nil {
				return exitcode.Usage(fmt.Errorf("read target list: %w", err))
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					targets = append(targets, line)
				}
			}
		}
		if scanCIDR != "" {
			targets = append(targets, scanCIDR)
		}

		if len(targets) == 0 {
			return exitcode.Usage(fmt.Errorf("no targets found"))
		}

		if scanTail {
			return runScanWithTail(cmd, cfg, targets)
		}

		// Map new flags to config
		cfg.General.DryRun = scanDryRun
		cfg.General.SkipMissingTools = scanSkipMissingTools
		if scanPrefix != "" {
			cfg.General.Prefix = scanPrefix
		}
		if scanInScope != "" {
			cfg.Target.ScopeFile = scanInScope
		}

		startedAt := time.Now()

		logger.Info().
			Str("version", config.Version).
			Int("targets", len(targets)).
			Str("mode", scanMode).
			Str("profile", scanProfile).
			Int("parallel", scanParallel).
			Int("workers", cfg.General.MaxWorkers).
			Msg("Starting ReconForge scan")

		ctx := cmd.Context()

		// Worker pool for multi-target scanning
		sem := make(chan struct{}, scanParallel)
		errCh := make(chan error, len(targets))

		for _, target := range targets {
			sem <- struct{}{}
			go func(t string) {
				defer func() { <-sem }()

				// Initialize orchestrator with all modules
				orch := orchestrator.New(cfg, logger.With().Str("target", t).Logger())

				// Execute scan
				if err := orch.Scan(ctx, t, scanMode, scanResume); err != nil {
					// Send failure notification
					notifier := notify.New(cfg.Export.Notify, logger)
					alert := notify.NewAlertFromResults(t, "failed", time.Since(startedAt), orch.Results())
					notifier.Send(ctx, alert)
					errCh <- fmt.Errorf("scan failed for %s: %w", t, err)
					return
				}

				// Generate reports
				results := orch.Results()
				scanReport := report.NewReportFromResults(t, scanMode, results, startedAt)

				dirName := t
				if cfg.General.Prefix != "" {
					dirName = cfg.General.Prefix + "_" + t
				}
				outputDir := filepath.Join(cfg.General.OutputDir, dirName)

				files, err := scanReport.ExportAll(outputDir)
				if err != nil {
					logger.Warn().Err(err).Str("target", t).Msg("Report generation failed")
				} else {
					for _, f := range files {
						logger.Info().Str("file", f).Str("target", t).Msg("Report generated")
					}
				}

				// Send success notification
				notifier := notify.New(cfg.Export.Notify, logger)
				alert := notify.NewAlertFromResults(t, "completed", time.Since(startedAt), results)
				notifier.Send(ctx, alert)

				errCh <- nil
			}(target)
		}

		// Wait for all to finish
		var scanErrs []error
		for i := 0; i < len(targets); i++ {
			if err := <-errCh; err != nil {
				scanErrs = append(scanErrs, err)
				logger.Error().Err(err).Msg("Target scan error")
			}
		}
		if len(scanErrs) > 0 {
			joined := errors.Join(scanErrs...)
			return exitcode.Scan(joined)
		}

		return nil
	},
}

// === CONFIG COMMAND ===

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return exitcode.Config(err)
		}
		fmt.Printf("Config loaded successfully\n")
		fmt.Printf("  Version:    %s\n", config.Version)
		fmt.Printf("  Build:      %s\n", config.BuildTime)
		fmt.Printf("  Tools Dir:  %s\n", cfg.General.ToolsDir)
		fmt.Printf("  Output Dir: %s\n", cfg.General.OutputDir)
		fmt.Printf("  Workers:    %d\n", cfg.General.MaxWorkers)
		fmt.Printf("  Modules:    OSINT=%v Sub=%v Web=%v Vuln=%v\n",
			cfg.OSINT.Enabled, cfg.Subdomain.Enabled, cfg.Web.Enabled, cfg.Vuln.Enabled)
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := config.Load(cfgFile, logger)
		if err != nil {
			return exitcode.Config(fmt.Errorf("[-] validation failed: %w", err))
		}
		fmt.Println("[+] Configuration is valid")
		return nil
	},
}

var configProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List available scan profiles",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Available scan profiles:")
		for _, p := range config.ListProfiles() {
			fmt.Printf("  • %s\n", p)
		}
	},
}

// === VERSION COMMAND ===

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print version information",
	Example: "  reconforge version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ReconForge %s\n", config.Version)
		fmt.Printf("Build time: %s\n", config.BuildTime)
	},
}

func init() {
	// Persistent flags (all commands)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./configs/default.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy", "", "HTTP(S) proxy for all tool subprocesses (e.g. http://127.0.0.1:8080)")

	// Scan flags
	scanCmd.Flags().StringVarP(&scanDomain, "domain", "d", "", "target domain (e.g., example.com)")
	scanCmd.Flags().StringVarP(&scanList, "list", "l", "", "file with list of targets")
	scanCmd.Flags().StringVar(&scanCIDR, "cidr", "", "target CIDR range")
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "recon", "scan mode: recon|passive|all|web|osint|zen|custom")
	scanCmd.Flags().StringVarP(&scanProfile, "profile", "p", "", "scan profile: quick|stealth|full|deep")
	scanCmd.Flags().BoolVar(&scanResume, "resume", false, "resume last scan on target")
	scanCmd.Flags().StringVar(&scanPrefix, "prefix", "", "prefix for output files/directories")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "simulate execution without running tools")
	scanCmd.Flags().BoolVar(&scanSkipMissingTools, "skip-missing-tools", false, "Skip modules whose required tools are missing instead of failing the scan")
	scanCmd.Flags().StringVar(&scanInScope, "inscope", "", "path to .scope file")
	scanCmd.Flags().IntVar(&scanParallel, "parallel", 1, "number of targets to scan concurrently")
	scanCmd.Flags().BoolVar(&scanTail, "tail", false, "Follow scan progress in a detached tail session")
	scanCmd.Example = strings.TrimSpace(`
  reconforge scan -d example.com
  reconforge scan -d example.com --tail
  reconforge scan -d example.com --skip-missing-tools
  reconforge scan -d example.com --profile full --dry-run
  reconforge scan -l targets.txt --parallel 3
`)
	_ = findingsListCmd.RegisterFlagCompletionFunc("target", completeTargetNames)

	// Config subcommands
	configCmd.AddCommand(configShowCmd, configValidateCmd, configProfilesCmd)
	configCmd.Example = strings.TrimSpace(`
  reconforge config show
  reconforge config validate --config ~/.reconforge/config.yaml
`)

	// Register all top-level commands
	rootCmd.AddCommand(scanCmd, configCmd, versionCmd)
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
