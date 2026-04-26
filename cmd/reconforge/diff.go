package main

import (
	"encoding/json"
	"fmt"

	"github.com/reconforge/reconforge/internal/project"
	"github.com/reconforge/reconforge/internal/ui"
	"github.com/spf13/cobra"
)

var (
	diffTarget string
	diffFrom   string
	diffTo     string
	diffLast   int
	diffFormat string
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare findings between two scans",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		if diffTarget == "" {
			return fmt.Errorf("--target is required")
		}

		var baseScanID, compareScanID string

		if diffLast == 2 {
			scans, err := pm.GetLastNScans(diffTarget, 2)
			if err != nil {
				return err
			}
			if len(scans) < 2 {
				return fmt.Errorf("need at least 2 scans to diff, found %d", len(scans))
			}
			// scans[0] is the newest, scans[1] is the older one
			baseScanID = scans[1].RunID
			compareScanID = scans[0].RunID
		} else if diffFrom != "" && diffTo != "" {
			baseScanID = diffFrom
			compareScanID = diffTo
		} else {
			return fmt.Errorf("must specify either --last 2 or both --from and --to")
		}

		scanDiff, err := pm.DiffScans(baseScanID, compareScanID)
		if err != nil {
			return fmt.Errorf("failed to compute diff: %w", err)
		}

		if diffFormat == "json" || diffFormat == "ndjson" {
			outputJSONDiff(scanDiff)
			return nil
		}

		// Print human readable diff
		fmt.Printf("\n[*] Scan Delta for Target: %s\n", diffTarget)
		fmt.Printf("Base:    %s (%s)\n", baseScanID, scanDiff.BaseScan.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Compare: %s (%s)\n\n", compareScanID, scanDiff.CompareScan.CreatedAt.Format("2006-01-02 15:04:05"))

		fmt.Printf("[*] Summary:\n")
		fmt.Printf("  • Added:     %d\n", len(scanDiff.Added))
		fmt.Printf("  • Removed:   %d\n", len(scanDiff.Removed))
		fmt.Printf("  • Unchanged: %d\n\n", len(scanDiff.Unchanged))

		if len(scanDiff.Added) > 0 {
			fmt.Println("🟢 Added Findings:")
			t := ui.NewTable([]string{"Severity", "Module", "Finding", "URL"})
			for _, f := range scanDiff.Added {
				t.AddRow([]string{
					f.Severity,
					f.Module,
					f.Title,
					f.URL,
				})
			}
			t.Render()
			fmt.Println()
		}

		if len(scanDiff.Removed) > 0 {
			fmt.Println("🔴 Removed Findings:")
			t := ui.NewTable([]string{"Severity", "Module", "Finding", "URL"})
			for _, f := range scanDiff.Removed {
				t.AddRow([]string{
					f.Severity,
					f.Module,
					f.Title,
					f.URL,
				})
			}
			t.Render()
			fmt.Println()
		}

		return nil
	},
}

func outputJSONDiff(d *project.ScanDiff) {
	for _, f := range d.Added {
		m := map[string]interface{}{"change": "added", "finding": f}
		b, _ := json.Marshal(m)
		fmt.Println(string(b))
	}
	for _, f := range d.Removed {
		m := map[string]interface{}{"change": "removed", "finding": f}
		b, _ := json.Marshal(m)
		fmt.Println(string(b))
	}
	for _, f := range d.Unchanged {
		m := map[string]interface{}{"change": "unchanged", "finding": f}
		b, _ := json.Marshal(m)
		fmt.Println(string(b))
	}
}

func init() {
	diffCmd.Flags().StringVarP(&diffTarget, "target", "t", "", "Target to diff")
	diffCmd.Flags().StringVar(&diffFrom, "from", "", "Base scan ID")
	diffCmd.Flags().StringVar(&diffTo, "to", "", "Compare scan ID")
	diffCmd.Flags().IntVar(&diffLast, "last", 0, "Compare last N scans (e.g. 2)")
	diffCmd.Flags().StringVar(&diffFormat, "format", "table", "Output format (table, json, ndjson)")

	rootCmd.AddCommand(diffCmd)
}
