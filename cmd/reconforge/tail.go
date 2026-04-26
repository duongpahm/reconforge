package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/ui"
	"github.com/spf13/cobra"
)

var (
	tailFollow   bool
	tailInterval time.Duration
	tailFormat   string
)

var tailCmd = &cobra.Command{
	Use:   "tail <target>",
	Short: "Show the latest scan state for a target",
	Args:  cobra.ExactArgs(1),
	Example: strings.TrimSpace(`
  reconforge tail example.com
  reconforge tail example.com --follow
  reconforge tail example.com --format json
`),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile, logger)
		if err != nil {
			return err
		}

		target := args[0]
		dbPath := filepath.Join(cfg.General.OutputDir, target, "state.db")
		sm, err := engine.NewStateManager(dbPath)
		if err != nil {
			return fmt.Errorf("open state for %s: %w", target, err)
		}
		defer sm.Close()

		var lastRendered string
		for {
			state, err := sm.GetLastScan(target)
			if err != nil {
				return err
			}
			if state == nil {
				return fmt.Errorf("no scan state found for %s", target)
			}

			rendered, err := renderTailState(state, tailFormat)
			if err != nil {
				return err
			}
			if rendered != lastRendered {
				if lastRendered != "" && ui.IsTTY() && tailFormat != "json" {
					fmt.Println()
				}
				fmt.Print(rendered)
				lastRendered = rendered
			}

			if !tailFollow || state.Status == engine.StatusComplete || state.Status == engine.StatusFailed {
				return nil
			}

			time.Sleep(tailInterval)
		}
	},
}

func renderTailState(state *engine.ScanState, format string) (string, error) {
	if format == "auto" {
		if ui.IsTTY() {
			format = "pretty"
		} else {
			format = "json"
		}
	}

	switch format {
	case "json":
		payload, err := json.Marshal(state)
		if err != nil {
			return "", err
		}
		return string(payload) + "\n", nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "Scan %s  target=%s  mode=%s  status=%s  findings=%d\n", state.ID, state.Target, state.Mode, state.Status, state.Findings)
		for _, mod := range state.Modules {
			fmt.Fprintf(&b, "  %-22s %-10s findings=%-4d duration=%0.1fs\n", mod.Name, mod.Status, mod.Findings, mod.Duration)
			if mod.Error != "" {
				fmt.Fprintf(&b, "    error: %s\n", mod.Error)
			}
		}
		return b.String(), nil
	}
}

func init() {
	tailCmd.Flags().BoolVarP(&tailFollow, "follow", "f", false, "Keep polling until the latest scan completes")
	tailCmd.Flags().DurationVar(&tailInterval, "interval", 2*time.Second, "Polling interval when following")
	tailCmd.Flags().StringVar(&tailFormat, "format", "auto", "Output format (auto, pretty, json)")
	rootCmd.AddCommand(tailCmd)
}
