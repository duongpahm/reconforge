// Package main provides the CLI entry point for ReconForge.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/reconforge/reconforge/internal/api"
	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/models"
	"github.com/reconforge/reconforge/internal/notify"
	"github.com/reconforge/reconforge/internal/orchestrator"
	"github.com/reconforge/reconforge/internal/report"
	"github.com/reconforge/reconforge/internal/temporal"
	"github.com/reconforge/reconforge/internal/vm"
	"github.com/reconforge/reconforge/pkg/tool"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

var (
	cfgFile string
	verbose bool
	logger  zerolog.Logger
)

func main() {
	// Setup logger
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}
	logger = zerolog.New(output).With().Timestamp().Logger()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "reconforge",
	Short: "ReconForge — All-in-One Offensive Reconnaissance Platform",
	Long: `ReconForge is a powerful reconnaissance framework that orchestrates 80+ security tools
for automated bug bounty hunting and penetration testing.

Built as a modern Go replacement for reconFTW, with native Kali VM integration,
DAG-based pipeline execution, and plugin-based extensibility.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
	},
}

// === SCAN COMMAND ===

var (
	scanDomain  string
	scanList    string
	scanCIDR    string
	scanMode    string
	scanProfile string
	scanResume  string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run reconnaissance scan on a target",
	Long:  `Execute a full or partial reconnaissance scan on the specified target domain, list, or CIDR range.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if scanDomain == "" && scanList == "" && scanCIDR == "" {
			return fmt.Errorf("specify a target with -d (domain), -l (list), or --cidr")
		}

		target := coalesce(scanDomain, scanList, scanCIDR)
		startedAt := time.Now()

		logger.Info().
			Str("version", config.Version).
			Str("target", target).
			Str("mode", scanMode).
			Str("profile", scanProfile).
			Bool("parallel", cfg.General.Parallel).
			Int("workers", cfg.General.MaxWorkers).
			Msg("Starting ReconForge scan")

		// Initialize orchestrator with all modules
		orch := orchestrator.New(cfg, logger)

		// Execute scan
		ctx := cmd.Context()
		if err := orch.Scan(ctx, target, scanMode); err != nil {
			// Send failure notification
			notifier := notify.New(cfg.Export.Notify, logger)
			alert := notify.NewAlertFromResults(target, "failed", time.Since(startedAt), orch.Results())
			notifier.Send(ctx, alert)
			return fmt.Errorf("scan failed: %w", err)
		}

		// Generate reports
		results := orch.Results()
		scanReport := report.NewReportFromResults(target, scanMode, results, startedAt)
		outputDir := filepath.Join(cfg.General.OutputDir, target)

		files, err := scanReport.ExportAll(outputDir)
		if err != nil {
			logger.Warn().Err(err).Msg("Report generation failed")
		} else {
			for _, f := range files {
				logger.Info().Str("file", f).Msg("Report generated")
			}
		}

		// Send success notification
		notifier := notify.New(cfg.Export.Notify, logger)
		alert := notify.NewAlertFromResults(target, "completed", time.Since(startedAt), results)
		notifier.Send(ctx, alert)

		return nil
	},
}

// === VM COMMAND ===

var (
	vmImage string
)

var vmCmd = &cobra.Command{
	Use:   "vm",
	Short: "Manage Kali Linux VM",
	Long:  `Create, start, stop, and manage the Kali Linux VM used for running security tools.`,
}

var vmSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup a new Kali Linux VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		mgr, err := vm.NewManager(cfg.VM.Provider, cfg.VM.Name, logger)
		if err != nil {
			return err
		}

		image := cfg.VM.Image
		if vmImage != "" {
			image = vmImage
		}

		opts := vm.VMOpts{
			Provider:  cfg.VM.Provider,
			Name:      cfg.VM.Name,
			Memory:    cfg.VM.Memory,
			CPUs:      cfg.VM.CPUs,
			DiskGB:    cfg.VM.DiskGB,
			Image:     image,
			SSHPort:   cfg.VM.SSHPort,
			SharedDir: cfg.VM.SharedDir,
		}

		fmt.Println("🖥️  Setting up Kali Linux VM...")
		if err := mgr.Setup(cmd.Context(), opts); err != nil {
			fmt.Printf("❌ VM setup failed: %v\n", err)
			return nil
		}
		fmt.Println("✅ VM setup complete")
		return nil
	},
}

var vmStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show VM status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		mgr, err := vm.NewManager(cfg.VM.Provider, cfg.VM.Name, logger)
		if err != nil {
			return err
		}

		status, err := mgr.Status(cmd.Context())
		if err != nil {
			return err
		}

		stateIcon := "⏹️"
		if status.State == "running" {
			stateIcon = "🟢"
		}

		fmt.Printf("📊 VM Status\n")
		fmt.Printf("  Name:     %s\n", status.Name)
		fmt.Printf("  State:    %s %s\n", stateIcon, status.State)
		fmt.Printf("  Provider: %s\n", status.Provider)
		fmt.Printf("  Memory:   %d MB\n", status.Memory)
		fmt.Printf("  CPUs:     %d\n", status.CPUs)
		fmt.Printf("  SSH Port: %d (ready: %v)\n", status.SSHPort, status.SSHReady)
		if status.SharedDir != "" {
			fmt.Printf("  Shared:   %s\n", status.SharedDir)
		}
		return nil
	},
}

var vmStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		mgr, err := vm.NewManager(cfg.VM.Provider, cfg.VM.Name, logger)
		if err != nil {
			return err
		}

		fmt.Println("▶️  Starting VM...")
		if err := mgr.Start(cmd.Context()); err != nil {
			return err
		}
		fmt.Println("✅ VM started")
		return nil
	},
}

var vmStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		mgr, err := vm.NewManager(cfg.VM.Provider, cfg.VM.Name, logger)
		if err != nil {
			return err
		}

		fmt.Println("⏹️  Stopping VM...")
		if err := mgr.Stop(cmd.Context()); err != nil {
			return err
		}
		fmt.Println("✅ VM stopped")
		return nil
	},
}

var vmSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH into the VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		port := cfg.VM.SSHPort
		if port == 0 {
			port = 2222
		}

		fmt.Printf("🔑 Connecting to VM via SSH on port %d...\n", port)
		sshCmd := exec.Command("ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-p", fmt.Sprint(port),
			"kali@localhost",
		)
		sshCmd.Stdin = os.Stdin
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
		return sshCmd.Run()
	},
}

var vmDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy the VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		mgr, err := vm.NewManager(cfg.VM.Provider, cfg.VM.Name, logger)
		if err != nil {
			return err
		}

		fmt.Printf("💥 Destroying VM %q...\n", cfg.VM.Name)
		if err := mgr.Destroy(cmd.Context()); err != nil {
			return err
		}
		fmt.Println("✅ VM destroyed")
		return nil
	},
}

// === TOOLS COMMAND ===

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Manage security tools",
	Long:  `Install, update, and check the status of 80+ security tools.`,
}

var toolsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Health check all required tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := tool.DefaultRegistry()
		statusMap := reg.CheckAll(cmd.Context())

		fmt.Printf("🔍 Checking %d required tools...\n\n", len(statusMap))

		missing := 0
		for _, name := range getSortedToolNames(statusMap) {
			s := statusMap[name]
			if !s.Installed {
				fmt.Printf("  ❌ %-15s — not found\n", name)
				if s.Required {
					missing++
				}
			} else if !s.Healthy {
				fmt.Printf("  ⚠️  %-15s — health check failed: %s\n", name, s.Error)
			} else {
				fmt.Printf("  ✅ %-15s — %s\n", name, s.Version)
			}
		}

		fmt.Println()
		if missing > 0 {
			fmt.Printf("⚠️  %d tools missing. Run 'reconforge tools install' to install.\n", missing)
		} else {
			fmt.Printf("✅ All required tools available\n")
		}
		return nil
	},
}

func getSortedToolNames(m map[string]tool.ToolStatus) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	// just a simple sort not required since we just print
	return names
}

var toolsInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install missing tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := tool.DefaultRegistry()
		installer := tool.NewInstaller(logger)

		fmt.Printf("📦 Checking and installing missing tools...\n\n")

		if err := installer.InstallMissing(cmd.Context(), reg); err != nil {
			fmt.Printf("\n❌ Installation failed: %v\n", err)
			return err
		}

		fmt.Println("\n✅ All tools installed successfully")
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
			return err
		}
		fmt.Printf("Config loaded successfully\n")
		fmt.Printf("  Version:    %s\n", config.Version)
		fmt.Printf("  Build:      %s\n", config.BuildTime)
		fmt.Printf("  Tools Dir:  %s\n", cfg.General.ToolsDir)
		fmt.Printf("  Output Dir: %s\n", cfg.General.OutputDir)
		fmt.Printf("  Workers:    %d\n", cfg.General.MaxWorkers)
		fmt.Printf("  VM:         %v (%s)\n", cfg.VM.Enabled, cfg.VM.Provider)
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
			return fmt.Errorf("❌ validation failed: %w", err)
		}
		fmt.Println("✅ Configuration is valid")
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

// === REPORT COMMAND ===

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📄 Report generation — coming in Phase 6")
		return nil
	},
}

// === VERSION COMMAND ===

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ReconForge %s\n", config.Version)
		fmt.Printf("Build time: %s\n", config.BuildTime)
	},
}

func init() {
	// Persistent flags (all commands)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./configs/default.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")

	// Scan flags
	scanCmd.Flags().StringVarP(&scanDomain, "domain", "d", "", "target domain (e.g., example.com)")
	scanCmd.Flags().StringVarP(&scanList, "list", "l", "", "file with list of targets")
	scanCmd.Flags().StringVar(&scanCIDR, "cidr", "", "target CIDR range")
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "recon", "scan mode: recon|passive|all|web|osint|zen|custom")
	scanCmd.Flags().StringVarP(&scanProfile, "profile", "p", "", "scan profile: quick|stealth|full|deep")
	scanCmd.Flags().StringVar(&scanResume, "resume", "", "resume scan by ID")

	// VM subcommands
	vmSetupCmd.Flags().StringVar(&vmImage, "image", "", "path to Kali Linux OVA image")
	vmCmd.AddCommand(vmSetupCmd, vmStatusCmd, vmStartCmd, vmStopCmd, vmSSHCmd, vmDestroyCmd)

	// Tools subcommands
	toolsCmd.AddCommand(toolsCheckCmd, toolsInstallCmd)

	// Config subcommands
	configCmd.AddCommand(configShowCmd, configValidateCmd, configProfilesCmd)

	// Register all top-level commands
	rootCmd.AddCommand(scanCmd, vmCmd, toolsCmd, configCmd, reportCmd, versionCmd, serverCmd, workerCmd)
}

// serverCmd starts the ReconForge REST API server.
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the ReconForge REST API and Web Dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")

		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// Initialize Database
		dbPath := filepath.Join(cfg.General.OutputDir, "reconforge.db")
		db, err := models.SetupDatabase(dbPath)
		if err != nil {
			return fmt.Errorf("failed to setup database: %w", err)
		}

		// Initialize Temporal Client
		tempClient, err := client.Dial(client.Options{
			HostPort: client.DefaultHostPort,
		})
		if err != nil {
			return fmt.Errorf("failed to create temporal client: %w", err)
		}
		defer tempClient.Close()

		srv := api.NewServer(cfg, logger, db, tempClient)
		return srv.Start(addr)
	},
}

// workerCmd starts the Temporal worker for distributed scanning.
var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Start a Temporal worker for ReconForge scans",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		c, err := client.Dial(client.Options{
			HostPort: client.DefaultHostPort,
		})
		if err != nil {
			return fmt.Errorf("failed to create temporal client: %w", err)
		}
		defer c.Close()

		w := worker.New(c, "reconforge-task-queue", worker.Options{})

		a := temporal.NewActivities(cfg, logger)
		
		w.RegisterWorkflow(temporal.ScanWorkflow)
		w.RegisterActivity(a.RunModule)

		logger.Info().Msg("Starting Temporal worker on reconforge-task-queue")
		return w.Run(worker.InterruptCh())
	},
}

func initServerFlags() {
	serverCmd.Flags().String("addr", ":8080", "Bind address for API server")
}

func init() {
	initServerFlags()
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
