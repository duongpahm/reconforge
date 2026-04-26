package main

import (
	"fmt"
	"os"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/tools"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system environment and required tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		manager := tools.NewManager()

		fmt.Println("Running environment checks...")
		issues := manager.CheckEnvironment()

		if len(issues) == 0 {
			fmt.Println("Environment: OK")
		} else {
			fmt.Println("Environment Issues Found:")
			for _, issue := range issues {
				fmt.Printf("  - %s\n", issue)
			}
		}

		fmt.Println("\nChecking required tools...")
		var requiredTools []string
		for name := range tools.Registry {
			requiredTools = append(requiredTools, name)
		}

		missing := 0
		for _, tool := range requiredTools {
			installed, _ := manager.IsInstalled(tool)
			if !installed {
				fmt.Printf("  - Missing: %s\n", tool)
				missing++
			}
		}

		if missing == 0 {
			fmt.Println("All required tools are installed.")
		} else {
			fmt.Printf("\nFound %d missing tools. Run 'reconforge tools install all' to install them.\n", missing)
		}

		cfg, err := config.Load(cfgFile, logger)
		if err == nil {
			if path, ok := activeConfigPath(cfgFile); ok {
				if info, statErr := os.Stat(path); statErr == nil && config.HasNotifySecrets(cfg) && info.Mode().Perm()&0o077 != 0 {
					fmt.Printf("\nWARNING: config file contains secrets and is too permissive. Run: chmod 600 %s\n", path)
				}
			}
		}

		return nil
	},
}

func activeConfigPath(explicit string) (string, bool) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, true
		}
		return "", false
	}
	for _, path := range config.DefaultConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
