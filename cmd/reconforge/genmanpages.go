package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var manpagesOut string

var genManpagesCmd = &cobra.Command{
	Use:    "gen-manpages",
	Short:  "Generate man pages",
	Hidden: true,
	Example: strings.TrimSpace(`
  reconforge gen-manpages --out ./man
`),
	RunE: func(cmd *cobra.Command, args []string) error {
		header := &doc.GenManHeader{
			Title:   "RECONFORGE",
			Section: "1",
		}
		return doc.GenManTree(rootCmd, header, manpagesOut)
	},
}

func init() {
	genManpagesCmd.Flags().StringVar(&manpagesOut, "out", ".", "Output directory for generated man pages")
	rootCmd.AddCommand(genManpagesCmd)
}
