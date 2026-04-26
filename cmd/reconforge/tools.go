package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/reconforge/reconforge/internal/tools"
	"github.com/reconforge/reconforge/internal/ui"
	"github.com/spf13/cobra"
)

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Manage external security tools",
}

var toolsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tools and their installation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		manager := tools.NewManager()

		// Get required tools from registry
		requiredMap := make(map[string]bool)
		for name := range tools.Registry {
			requiredMap[name] = true
		}

		statuses := manager.List()
		sort.Slice(statuses, func(i, j int) bool {
			return statuses[i].Name < statuses[j].Name
		})

		t := ui.NewTable([]string{"Tool", "Required", "Status", "Path"})

		for _, s := range statuses {
			reqStr := "No"
			if requiredMap[s.Name] {
				reqStr = "Yes"
			}

			statusStr := "Missing"
			if s.Installed {
				statusStr = "Installed"
			}

			pathStr := s.Path
			if pathStr == "" {
				pathStr = "-"
			}

			t.AddRow([]string{s.Name, reqStr, statusStr, pathStr})
		}

		fmt.Println("Tool Installation Status:")
		t.Render()
		return nil
	},
}

var toolsInstallCmd = &cobra.Command{
	Use:   "install <name|all>",
	Short: "Install a specific tool or all missing tools",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		manager := tools.NewManager()
		target := strings.ToLower(args[0])

		if target == "all" {
			fmt.Println("Installing all registered tools...")
			for name := range tools.Registry {
				installed, _ := manager.IsInstalled(name)
				if !installed {
					fmt.Printf("Installing %s...\n", name)
					if err := manager.Install(name); err != nil {
						fmt.Printf("Failed to install %s: %v\n", name, err)
					} else {
						fmt.Printf("Successfully installed %s.\n", name)
					}
				} else {
					fmt.Printf("Tool %s is already installed.\n", name)
				}
			}
			return nil
		}

		fmt.Printf("Installing %s...\n", target)
		if err := manager.Install(target); err != nil {
			return err
		}
		fmt.Printf("Successfully installed %s.\n", target)
		return nil
	},
}

var toolsUpdateCmd = &cobra.Command{
	Use:   "update <name|all>",
	Short: "Update a specific tool or all tools",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		manager := tools.NewManager()
		target := strings.ToLower(args[0])

		// Update logic is often the same as install for Go tools (@latest)
		if target == "all" {
			fmt.Println("Updating all registered tools...")
			for name := range tools.Registry {
				fmt.Printf("Updating %s...\n", name)
				if err := manager.Install(name); err != nil {
					fmt.Printf("Failed to update %s: %v\n", name, err)
				} else {
					fmt.Printf("Successfully updated %s.\n", name)
				}
			}
			return nil
		}

		fmt.Printf("Updating %s...\n", target)
		if err := manager.Install(target); err != nil {
			return err
		}
		fmt.Printf("Successfully updated %s.\n", target)
		return nil
	},
}

var toolsPathCmd = &cobra.Command{
	Use:   "path <name>",
	Short: "Print the absolute path to a tool binary",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		manager := tools.NewManager()
		target := strings.ToLower(args[0])

		installed, path := manager.IsInstalled(target)
		if !installed {
			return fmt.Errorf("tool %s is not installed", target)
		}
		fmt.Println(path)
		return nil
	},
}

func init() {
	toolsCmd.AddCommand(toolsListCmd, toolsInstallCmd, toolsUpdateCmd, toolsPathCmd)
	rootCmd.AddCommand(toolsCmd)
}
