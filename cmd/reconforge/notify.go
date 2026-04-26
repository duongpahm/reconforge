package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/duongpahm/ReconForge/internal/notify"
	"github.com/duongpahm/ReconForge/internal/ui"
	"github.com/spf13/cobra"
)

var (
	ruleName        string
	ruleTarget      string
	ruleMinSeverity string
	ruleKeywords    string
	ruleWebhook     string
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Manage notification rules",
}

var notifyRuleAddCmd = &cobra.Command{
	Use:   "add <id>",
	Short: "Add a notification rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		rulesPath := getRulesPath()

		engine, err := notify.LoadRules(rulesPath)
		if err != nil {
			return err
		}

		// Check if exists
		for _, r := range engine.Rules {
			if r.ID == id {
				return fmt.Errorf("rule with ID %s already exists", id)
			}
		}

		var keywords []string
		if ruleKeywords != "" {
			keywords = strings.Split(ruleKeywords, ",")
			for i := range keywords {
				keywords[i] = strings.TrimSpace(keywords[i])
			}
		}

		newRule := notify.Rule{
			ID:          id,
			Name:        ruleName,
			Target:      ruleTarget,
			MinSeverity: ruleMinSeverity,
			Keywords:    keywords,
			WebhookURL:  ruleWebhook,
		}

		engine.Rules = append(engine.Rules, newRule)

		if err := engine.SaveRules(rulesPath); err != nil {
			return err
		}

		fmt.Printf("[+] Rule '%s' added successfully.\n", id)
		return nil
	},
}

var notifyRuleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List notification rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		rulesPath := getRulesPath()
		engine, err := notify.LoadRules(rulesPath)
		if err != nil {
			return err
		}

		if len(engine.Rules) == 0 {
			fmt.Println("No notification rules configured.")
			return nil
		}

		t := ui.NewTable([]string{"ID", "Name", "Target", "MinSev", "Keywords", "Webhook"})
		for _, r := range engine.Rules {
			kw := strings.Join(r.Keywords, ", ")
			if kw == "" {
				kw = "*"
			}
			target := r.Target
			if target == "" {
				target = "*"
			}
			minSev := r.MinSeverity
			if minSev == "" {
				minSev = "*"
			}
			t.AddRow([]string{r.ID, r.Name, target, minSev, kw, r.WebhookURL})
		}
		t.Render()
		return nil
	},
}

var notifyRuleRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "Remove a notification rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		rulesPath := getRulesPath()

		engine, err := notify.LoadRules(rulesPath)
		if err != nil {
			return err
		}

		found := false
		var newRules []notify.Rule
		for _, r := range engine.Rules {
			if r.ID == id {
				found = true
				continue
			}
			newRules = append(newRules, r)
		}

		if !found {
			return fmt.Errorf("rule %s not found", id)
		}

		engine.Rules = newRules
		if err := engine.SaveRules(rulesPath); err != nil {
			return err
		}

		fmt.Printf("🗑️ Rule '%s' removed.\n", id)
		return nil
	},
}

func getRulesPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reconforge", "notify_rules.json")
}

func init() {
	notifyRuleAddCmd.Flags().StringVarP(&ruleName, "name", "n", "", "Rule name")
	notifyRuleAddCmd.Flags().StringVarP(&ruleTarget, "target", "t", "", "Target regex")
	notifyRuleAddCmd.Flags().StringVarP(&ruleMinSeverity, "min-severity", "s", "", "Minimum severity (low, medium, high, critical)")
	notifyRuleAddCmd.Flags().StringVarP(&ruleKeywords, "keywords", "k", "", "Comma-separated keywords")
	notifyRuleAddCmd.Flags().StringVarP(&ruleWebhook, "webhook", "w", "", "Specific webhook URL")

	notifyCmd.AddCommand(notifyRuleAddCmd, notifyRuleListCmd, notifyRuleRemoveCmd)
	rootCmd.AddCommand(notifyCmd)
}
