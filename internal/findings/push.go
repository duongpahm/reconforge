package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/reconforge/reconforge/internal/models"
	"github.com/reconforge/reconforge/internal/project"
)

type TicketBackend interface {
	Name() string
	Push(ctx context.Context, finding models.Finding) (string, error)
}

type PushOptions struct {
	Repo       string
	Project    string
	Team       string
	Host       string
	Severity   []string
	DryRun     bool
	HTTPClient *http.Client
}

type JiraBackend struct {
	host    string
	token   string
	project string
	client  *http.Client
}

type GitHubBackend struct {
	token  string
	repo   string
	client *http.Client
}

type LinearBackend struct {
	token  string
	team   string
	client *http.Client
}

func Push(target, backendName string, opts PushOptions) error {
	pm, err := project.NewManager()
	if err != nil {
		return err
	}
	defer pm.Close()

	findings, err := pm.ListFindings(target, strings.Join(opts.Severity, ","), "", "", "")
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return fmt.Errorf("no findings found matching criteria")
	}

	backend, err := newBackend(backendName, opts)
	if err != nil {
		return err
	}

	for _, finding := range findings {
		if opts.DryRun {
			fmt.Printf("[dry-run] would push %s finding %s to %s\n", defaultValue(finding.Severity, "unknown"), finding.FindingID, backend.Name())
			continue
		}

		ticketURL, err := backend.Push(context.Background(), finding)
		if err != nil {
			return fmt.Errorf("push finding %s: %w", finding.FindingID, err)
		}
		fmt.Printf("[+] %s -> %s\n", finding.FindingID, ticketURL)
	}

	return nil
}

func newBackend(name string, opts PushOptions) (TicketBackend, error) {
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	switch strings.ToLower(name) {
	case "github":
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("GITHUB_TOKEN is required")
		}
		if opts.Repo == "" {
			return nil, fmt.Errorf("--repo is required for github backend")
		}
		return &GitHubBackend{token: token, repo: opts.Repo, client: client}, nil
	case "jira":
		token := os.Getenv("JIRA_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("JIRA_TOKEN is required")
		}
		if opts.Host == "" || opts.Project == "" {
			return nil, fmt.Errorf("--host and --project are required for jira backend")
		}
		return &JiraBackend{host: strings.TrimRight(opts.Host, "/"), token: token, project: opts.Project, client: client}, nil
	case "linear":
		token := os.Getenv("LINEAR_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("LINEAR_TOKEN is required")
		}
		if opts.Team == "" {
			return nil, fmt.Errorf("--team is required for linear backend")
		}
		return &LinearBackend{token: token, team: opts.Team, client: client}, nil
	default:
		return nil, fmt.Errorf("unsupported ticket backend %q", name)
	}
}

func (b *GitHubBackend) Name() string { return "github" }

func (b *GitHubBackend) Push(ctx context.Context, finding models.Finding) (string, error) {
	payload := map[string]any{
		"title": labelsTitle(finding),
		"body":  issueBody(finding),
		"labels": []string{
			"reconforge",
			defaultValue(finding.Severity, "unknown"),
			defaultValue(finding.Module, "module:unknown"),
		},
	}
	var resp struct {
		HTMLURL string `json:"html_url"`
	}
	err := doJSON(ctx, b.client, http.MethodPost, "https://api.github.com/repos/"+b.repo+"/issues", b.token, payload, &resp)
	if err != nil {
		return "", err
	}
	return resp.HTMLURL, nil
}

func (b *JiraBackend) Name() string { return "jira" }

func (b *JiraBackend) Push(ctx context.Context, finding models.Finding) (string, error) {
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": b.project},
			"summary":     labelsTitle(finding),
			"description": issueBody(finding),
			"issuetype":   map[string]string{"name": "Task"},
		},
	}
	var resp struct {
		Key string `json:"key"`
	}
	err := doJSON(ctx, b.client, http.MethodPost, b.host+"/rest/api/3/issue", b.token, payload, &resp)
	if err != nil {
		return "", err
	}
	return b.host + "/browse/" + resp.Key, nil
}

func (b *LinearBackend) Name() string { return "linear" }

func (b *LinearBackend) Push(ctx context.Context, finding models.Finding) (string, error) {
	payload := map[string]any{
		"query": `
mutation IssueCreate($teamId: String!, $title: String!, $description: String!) {
  issueCreate(input: {teamId: $teamId, title: $title, description: $description}) {
    success
    issue {
      identifier
      url
    }
  }
}`,
		"variables": map[string]any{
			"teamId":      b.team,
			"title":       labelsTitle(finding),
			"description": issueBody(finding),
		},
	}
	var resp struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
				Issue   struct {
					URL string `json:"url"`
				} `json:"issue"`
			} `json:"issueCreate"`
		} `json:"data"`
	}
	err := doJSON(ctx, b.client, http.MethodPost, "https://api.linear.app/graphql", b.token, payload, &resp)
	if err != nil {
		return "", err
	}
	if !resp.Data.IssueCreate.Success {
		return "", fmt.Errorf("linear issueCreate returned success=false")
	}
	return resp.Data.IssueCreate.Issue.URL, nil
}

func doJSON(ctx context.Context, client *http.Client, method, endpoint, token string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	if strings.Contains(endpoint, "api.github.com") {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func labelsTitle(finding models.Finding) string {
	return fmt.Sprintf("[%s] %s", strings.ToUpper(defaultValue(finding.Severity, "unknown")), bestTitle(finding))
}

func issueBody(finding models.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", defaultValue(finding.Target, "-"))
	fmt.Fprintf(&b, "Module: %s\n", defaultValue(finding.Module, "-"))
	fmt.Fprintf(&b, "Type: %s\n", defaultValue(finding.Type, "-"))
	if finding.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", finding.URL)
	}
	if finding.Host != "" {
		fmt.Fprintf(&b, "Host: %s\n", finding.Host)
	}
	if finding.Description != "" {
		b.WriteString("\nDescription:\n")
		b.WriteString(finding.Description + "\n")
	}
	if finding.RequestRaw != "" {
		b.WriteString("\nRequest:\n```http\n")
		b.WriteString(finding.RequestRaw)
		if !strings.HasSuffix(finding.RequestRaw, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	}
	return b.String()
}
