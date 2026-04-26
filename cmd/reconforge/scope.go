package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/duongpahm/ReconForge/internal/exitcode"
	"github.com/duongpahm/ReconForge/pkg/platform"
	"github.com/duongpahm/ReconForge/pkg/scope"
	"github.com/spf13/cobra"
)

var (
	syncFrom    string
	syncProgram string
	syncOut     string
)

var scopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage and test scope rules",
}

var scopeValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a .scope file syntax",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		file := args[0]
		s, err := scope.ParseScopeFile(file)
		if err != nil {
			return exitcode.Scope(fmt.Errorf("failed to validate scope file: %w", err))
		}

		fmt.Printf("[+] Scope file '%s' is valid.\n", file)
		fmt.Printf("   In-Scope Items:     %d\n", len(s.InScope))
		fmt.Printf("   Out-of-Scope Items: %d\n", len(s.OutOfScope))
		return nil
	},
}

var scopeTestCmd = &cobra.Command{
	Use:   "test [file] [url_or_domain]",
	Short: "Test if a URL or domain is within scope",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		file := args[0]
		target := args[1]

		s, err := scope.ParseScopeFile(file)
		if err != nil {
			return exitcode.Scope(fmt.Errorf("failed to parse scope file: %w", err))
		}

		if s.IsInScope(target) {
			fmt.Printf("[+] %s is IN SCOPE\n", target)
		} else {
			fmt.Printf("[-] %s is OUT OF SCOPE\n", target)
			return exitcode.Scope(fmt.Errorf("%s is out of scope", target))
		}
		return nil
	},
}

var scopeSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync scope from a bug bounty platform",
	RunE: func(cmd *cobra.Command, args []string) error {
		if syncFrom == "" || syncProgram == "" || syncOut == "" {
			return fmt.Errorf("--from, --program, and -o are required")
		}

		token := ""
		switch strings.ToLower(syncFrom) {
		case "hackerone", "h1":
			token = os.Getenv("H1_TOKEN")
		case "bugcrowd", "bc":
			token = os.Getenv("BUGCROWD_TOKEN")
		}

		client, err := platform.GetClient(strings.ToLower(syncFrom), token)
		if err != nil {
			return err
		}

		s, err := client.GetScope(syncProgram)
		if err != nil {
			return fmt.Errorf("sync failed: %w", err)
		}

		// Write to output file
		var lines []string
		for _, in := range s.InScope {
			lines = append(lines, in)
		}
		for _, out := range s.OutOfScope {
			lines = append(lines, "!"+out)
		}

		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(syncOut, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}

		fmt.Printf("[+] Scope synced successfully to %s\n", syncOut)
		return nil
	},
}

func init() {
	scopeSyncCmd.Flags().StringVar(&syncFrom, "from", "", "Platform to sync from (hackerone, bugcrowd)")
	scopeSyncCmd.Flags().StringVar(&syncProgram, "program", "", "Program name or handle")
	scopeSyncCmd.Flags().StringVarP(&syncOut, "out", "o", "", "Output scope file path")

	scopeCmd.AddCommand(scopeValidateCmd, scopeTestCmd, scopeSyncCmd)
	rootCmd.AddCommand(scopeCmd)
}
