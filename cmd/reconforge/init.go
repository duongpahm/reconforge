package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/project"
	"github.com/reconforge/reconforge/internal/ui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	initYes     bool
	initNoTools bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap ReconForge config and local project database",
	Long:  "Create ~/.reconforge/config.yaml and ~/.reconforge/projects.db with sensible defaults.",
	Example: strings.TrimSpace(`
  reconforge init
  reconforge init --yes
  reconforge init --yes --no-tools
`),
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		configDir := filepath.Join(home, ".reconforge")
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			return err
		}

		outputDir := "./Recon"
		profile := config.ProfileQuick
		notifyChannel := "none"

		if !initYes && ui.IsTTY() {
			reader := bufio.NewReader(os.Stdin)
			outputDir = prompt(reader, "Output directory", outputDir)
			profile = prompt(reader, "Default profile", profile)
			notifyChannel = prompt(reader, "Notify channel (none/slack/discord/telegram)", notifyChannel)
		}

		if err := writeInitConfig(filepath.Join(configDir, "config.yaml"), outputDir, profile, notifyChannel); err != nil {
			return err
		}

		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		fmt.Printf("[+] Created %s\n", filepath.Join(configDir, "config.yaml"))
		fmt.Printf("[+] Created %s\n", filepath.Join(configDir, "projects.db"))
		if initNoTools {
			fmt.Println("[*] Tool installation skipped.")
		} else {
			fmt.Println("[*] Tool installation is optional. Use `reconforge tools install all` when ready.")
		}

		return nil
	},
}

func prompt(reader *bufio.Reader, label, defaultValue string) string {
	fmt.Printf("%s [%s]: ", label, defaultValue)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defaultValue
	}

	value := strings.TrimSpace(line)
	if value == "" {
		return defaultValue
	}

	return value
}

func writeInitConfig(path, outputDir, profile, notifyChannel string) error {
	cfg := struct {
		General struct {
			OutputDir string `yaml:"output_dir"`
		} `yaml:"general"`
		DefaultProfile string `yaml:"default_profile"`
		Export         struct {
			Notify struct {
				Channel string `yaml:"channel"`
				Enabled bool   `yaml:"enabled"`
			} `yaml:"notify"`
		} `yaml:"export"`
	}{}

	cfg.General.OutputDir = outputDir
	cfg.DefaultProfile = profile
	cfg.Export.Notify.Channel = notifyChannel
	cfg.Export.Notify.Enabled = notifyChannel != "" && notifyChannel != "none"

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

func init() {
	initCmd.Flags().BoolVar(&initYes, "yes", false, "Skip prompts and use default values")
	initCmd.Flags().BoolVar(&initNoTools, "no-tools", false, "Do not install tools during setup")
	rootCmd.AddCommand(initCmd)
}
