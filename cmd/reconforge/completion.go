package main

import (
	"os"
	"strings"

	"github.com/reconforge/reconforge/internal/project"
	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:                   "completion [bash|zsh|fish|powershell]",
	Short:                 "Generate shell completion scripts",
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Example: strings.TrimSpace(`
  reconforge completion bash
  reconforge completion zsh > "$(brew --prefix)/share/zsh/site-functions/_reconforge"
  reconforge completion fish > ~/.config/fish/completions/reconforge.fish
`),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return nil
		}
	},
}

func completeTargetNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	pm, err := project.NewManager()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	defer pm.Close()

	targets, err := pm.ListTargetNames(toComplete)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return targets, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	completionCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(completionCmd)
}
