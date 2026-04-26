package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage reconforge cache",
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the reconforge cache directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not get home directory: %w", err)
		}

		cacheDir := filepath.Join(home, ".reconforge", "cache")

		fmt.Printf("Clearing cache directory: %s...\n", cacheDir)

		if err := os.RemoveAll(cacheDir); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}

		// Recreate empty directory structure
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return fmt.Errorf("failed to recreate cache directory: %w", err)
		}

		fmt.Println("Cache cleared successfully.")
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
	rootCmd.AddCommand(cacheCmd)
}
