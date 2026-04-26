package main

import (
	"fmt"
	"strings"

	"github.com/duongpahm/ReconForge/internal/project"
	"github.com/spf13/cobra"
)

var (
	projectScopePath string
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage recon engagements and projects",
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		mgr, err := project.NewManager()
		if err != nil {
			return err
		}
		defer mgr.Close()

		if err := mgr.CreateProject(name, projectScopePath); err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
		fmt.Printf("[+] Project '%s' created successfully.\n", name)
		return nil
	},
}

var projectAddTargetCmd = &cobra.Command{
	Use:   "add-target [project] [target]",
	Short: "Add a target to a project",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		projName := args[0]
		target := args[1]

		mgr, err := project.NewManager()
		if err != nil {
			return err
		}
		defer mgr.Close()

		if err := mgr.AddTarget(projName, target); err != nil {
			return fmt.Errorf("failed to add target: %w", err)
		}
		fmt.Printf("[+] Target '%s' added to project '%s'.\n", target, projName)
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := project.NewManager()
		if err != nil {
			return err
		}
		defer mgr.Close()

		projects, err := mgr.ListProjects()
		if err != nil {
			return err
		}

		fmt.Println("📁 Projects")
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("%-20s | %-10s | %-20s\n", "NAME", "STATUS", "SCOPE")
		fmt.Println(strings.Repeat("-", 60))
		for _, p := range projects {
			scope := p.ScopePath
			if scope == "" {
				scope = "none"
			}
			fmt.Printf("%-20s | %-10s | %-20s\n", p.Name, p.Status, scope)
		}
		fmt.Println(strings.Repeat("-", 60))
		return nil
	},
}

var projectArchiveCmd = &cobra.Command{
	Use:   "archive [project]",
	Short: "Archive a project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projName := args[0]
		mgr, err := project.NewManager()
		if err != nil {
			return err
		}
		defer mgr.Close()

		if err := mgr.ArchiveProject(projName); err != nil {
			return err
		}
		fmt.Printf("[+] Project '%s' archived.\n", projName)
		return nil
	},
}

var projectScanCmd = &cobra.Command{
	Use:   "scan [project]",
	Short: "Scan all targets in a project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projName := args[0]
		mgr, err := project.NewManager()
		if err != nil {
			return err
		}

		proj, err := mgr.GetProject(projName)
		if err != nil {
			mgr.Close()
			return err
		}
		mgr.Close()

		if len(proj.Targets) == 0 {
			fmt.Printf("[!] Project '%s' has no targets.\n", projName)
			return nil
		}

		var targets []string
		for _, t := range proj.Targets {
			targets = append(targets, t.Target)
		}

		// We override scanDomain to effectively bypass the CLI target flag
		scanDomain = strings.Join(targets, ",")
		if proj.ScopePath != "" && scanInScope == "" {
			scanInScope = proj.ScopePath
		}

		// Setup parallel scanning behavior via main's scanCmd
		// We can directly call the scanCmd logic by modifying args and calling its RunE
		fmt.Printf("[*] Starting scan for project '%s' (%d targets)...\n", proj.Name, len(targets))

		return scanCmd.RunE(cmd, []string{})
	},
}

func init() {
	projectCreateCmd.Flags().StringVar(&projectScopePath, "scope", "", "Path to scope file")
	projectCmd.AddCommand(projectCreateCmd, projectAddTargetCmd, projectListCmd, projectArchiveCmd, projectScanCmd)
	rootCmd.AddCommand(projectCmd)
}
