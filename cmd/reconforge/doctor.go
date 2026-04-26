package main

import (
	"fmt"

	"github.com/reconforge/reconforge/internal/tools"
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

		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
