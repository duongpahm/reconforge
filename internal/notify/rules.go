package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/reconforge/reconforge/internal/models"
)

// Rule defines a criteria for triggering a notification.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Target      string   `json:"target,omitempty"`       // Regex pattern for target matching
	MinSeverity string   `json:"min_severity,omitempty"` // low, medium, high, critical
	Keywords    []string `json:"keywords,omitempty"`     // Match finding title or module
	WebhookURL  string   `json:"webhook_url,omitempty"`  // Specific webhook to trigger
}

// RuleEngine evaluates findings against a set of rules.
type RuleEngine struct {
	Rules []Rule
}

// LoadRules loads rules from a JSON file.
func LoadRules(path string) (*RuleEngine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RuleEngine{Rules: []Rule{}}, nil
		}
		return nil, fmt.Errorf("read rules: %w", err)
	}

	var rules []Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	return &RuleEngine{Rules: rules}, nil
}

// SaveRules saves the current rules to a JSON file.
func (re *RuleEngine) SaveRules(path string) error {
	os.MkdirAll(filepath.Dir(path), 0o755)
	b, err := json.MarshalIndent(re.Rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// severityWeight maps severities to an integer weight for comparison.
var severityWeight = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Matches checks if a finding triggers a specific rule.
func (r *Rule) Matches(target string, f models.Finding) bool {
	// 1. Check Target
	if r.Target != "" {
		matched, err := regexp.MatchString(r.Target, target)
		if err != nil || !matched {
			return false
		}
	}

	// 2. Check Severity
	if r.MinSeverity != "" {
		ruleWeight := severityWeight[strings.ToLower(r.MinSeverity)]
		findingWeight := severityWeight[strings.ToLower(f.Severity)]
		if findingWeight < ruleWeight {
			return false
		}
	}

	// 3. Check Keywords
	if len(r.Keywords) > 0 {
		keywordMatched := false
		lowerTitle := strings.ToLower(f.Title)
		lowerModule := strings.ToLower(f.Module)
		for _, kw := range r.Keywords {
			lkw := strings.ToLower(kw)
			if strings.Contains(lowerTitle, lkw) || strings.Contains(lowerModule, lkw) {
				keywordMatched = true
				break
			}
		}
		if !keywordMatched {
			return false
		}
	}

	return true
}

// GetTriggeredRules returns a list of rules that match a given finding.
func (re *RuleEngine) GetTriggeredRules(target string, f models.Finding) []Rule {
	var triggered []Rule
	for _, r := range re.Rules {
		if r.Matches(target, f) {
			triggered = append(triggered, r)
		}
	}
	return triggered
}

// ProcessDelta evaluates added findings against rules and triggers webhooks.
func (re *RuleEngine) ProcessDelta(target string, added []models.Finding) {
	// Simple map to dedup webhook calls per webhook URL if we want to batch them,
	// but for simplicity, we trigger one message per matched rule/finding.

	// A real implementation would batch findings per webhook URL to avoid spam.
	for _, f := range added {
		rules := re.GetTriggeredRules(target, f)
		for _, r := range rules {
			if r.WebhookURL != "" {
				sendRuleWebhook(r, target, f)
			}
		}
	}
}

func sendRuleWebhook(r Rule, target string, f models.Finding) {
	msg := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *ReconForge Alert [%s]*\n*Target*: %s\n*Finding*: %s (%s)\n*Severity*: %s\n*Module*: %s\n*URL*: %s",
			r.Name, target, f.Title, f.Fingerprint[:8], f.Severity, f.Module, f.URL),
	}

	b, _ := json.Marshal(msg)
	http.Post(r.WebhookURL, "application/json", bytes.NewBuffer(b))
}
