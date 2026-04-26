package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	findingsexport "github.com/reconforge/reconforge/internal/findings"
	"github.com/reconforge/reconforge/internal/models"
	"github.com/reconforge/reconforge/internal/project"
	"github.com/spf13/cobra"
)

var (
	findingsTarget   string
	findingsSeverity string
	findingsTag      string
	findingsModule   string
	findingsType     string
	findingsFormat   string
	findingsWrite    bool
	replayEdit       bool
	replayProxy      string
	findingsOutput   string
	findingsBackend  string
	findingsRepo     string
	findingsProject  string
	findingsTeam     string
	findingsHost     string
	findingsDryRun   bool
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Query, triage, and replay scan findings",
}

var findingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		findings, err := pm.ListFindings(findingsTarget, findingsSeverity, findingsTag, findingsModule, findingsType)
		if err != nil {
			return err
		}

		switch findingsFormat {
		case "ndjson":
			for _, f := range findings {
				b, _ := findingsexport.MarshalFindingJSON(f)
				fmt.Println(string(b))
			}
			return nil
		case "plain":
			for _, f := range findings {
				fmt.Println(plainFindingValue(f))
			}
			return nil
		}

		// Default table output
		fmt.Printf("%-36s | %-10s | %-15s | %-30s | %s\n", "ID", "SEVERITY", "MODULE", "HOST", "TITLE")
		fmt.Println(strings.Repeat("-", 120))
		for _, f := range findings {
			fmt.Printf("%-36s | %-10s | %-15s | %-30s | %s\n", f.FindingID, f.Severity, f.Module, f.Host, f.Title)
		}
		return nil
	},
}

var findingsShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show details of a specific finding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		f, err := pm.GetFinding(args[0])
		if err != nil {
			return err
		}

		if findingsFormat == "json" {
			b, _ := json.MarshalIndent(f, "", "  ")
			fmt.Println(string(b))
			return nil
		}

		fmt.Printf("Finding ID: %s\n", f.FindingID)
		fmt.Printf("Target:     %s\n", f.Target)
		fmt.Printf("Severity:   %s\n", f.Severity)
		fmt.Printf("Module:     %s\n", f.Module)
		fmt.Printf("URL:        %s\n", f.URL)
		fmt.Printf("Tags:       %s\n", f.Tags)
		fmt.Printf("\nTitle: %s\n", f.Title)
		fmt.Printf("Description: %s\n", f.Description)
		if f.Notes != "" {
			fmt.Printf("\nNotes: %s\n", f.Notes)
		}
		if f.RequestRaw != "" {
			fmt.Println("\n--- HTTP Request ---")
			fmt.Println(f.RequestRaw)
		}
		return nil
	},
}

var findingsTagCmd = &cobra.Command{
	Use:   "tag <id> <tag>",
	Short: "Add a tag to a finding",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		if err := pm.UpdateFindingTag(args[0], args[1], false); err != nil {
			return err
		}
		fmt.Printf("[+] Tagged %s with '%s'\n", args[0], args[1])
		return nil
	},
}

var findingsUntagCmd = &cobra.Command{
	Use:   "untag <id> <tag>",
	Short: "Remove a tag from a finding",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		if err := pm.UpdateFindingTag(args[0], args[1], true); err != nil {
			return err
		}
		fmt.Printf("[+] Untagged '%s' from %s\n", args[1], args[0])
		return nil
	},
}

var findingsNoteCmd = &cobra.Command{
	Use:   "note <id>",
	Short: "Edit notes for a finding using $EDITOR",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		f, err := pm.GetFinding(args[0])
		if err != nil {
			return err
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "nano" // fallback
		}

		tmpFile, err := os.CreateTemp("", "reconforge-note-*.txt")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())

		tmpFile.WriteString(f.Notes)
		tmpFile.Close()

		c := exec.Command(editor, tmpFile.Name())
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("editor failed: %w", err)
		}

		newNote, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			return err
		}

		if string(newNote) != f.Notes {
			if err := pm.UpdateFindingNote(args[0], string(newNote)); err != nil {
				return err
			}
			fmt.Println("[+] Notes updated.")
		} else {
			fmt.Println("No changes made to notes.")
		}
		return nil
	},
}

var findingsReplayCmd = &cobra.Command{
	Use:   "replay <id>",
	Short: "Replay the raw HTTP request of a finding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		f, err := pm.GetFinding(args[0])
		if err != nil {
			return err
		}

		if f.RequestRaw == "" {
			return fmt.Errorf("finding %s has no raw HTTP request", args[0])
		}

		reqRaw := f.RequestRaw

		if replayEdit {
			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "nano"
			}
			tmpFile, err := os.CreateTemp("", "reconforge-replay-*.http")
			if err != nil {
				return err
			}
			defer os.Remove(tmpFile.Name())

			tmpFile.WriteString(reqRaw)
			tmpFile.Close()

			c := exec.Command(editor, tmpFile.Name())
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("editor failed: %w", err)
			}

			b, err := os.ReadFile(tmpFile.Name())
			if err != nil {
				return err
			}
			reqRaw = string(b)
		}

		// Simple raw HTTP parsing
		lines := strings.SplitN(reqRaw, "\r\n\r\n", 2)
		if len(lines) == 1 {
			lines = strings.SplitN(reqRaw, "\n\n", 2)
		}

		headersPart := lines[0]
		bodyPart := ""
		if len(lines) > 1 {
			bodyPart = lines[1]
		}

		headerLines := strings.Split(headersPart, "\n")
		if len(headerLines) == 0 {
			return fmt.Errorf("invalid request")
		}

		reqLine := strings.Split(strings.TrimSpace(headerLines[0]), " ")
		if len(reqLine) < 2 {
			return fmt.Errorf("invalid request line")
		}

		method := reqLine[0]
		path := reqLine[1]
		targetURL := f.URL
		if targetURL == "" {
			targetURL = "http://" + f.Host
		}

		// Ensure base url doesn't have path to avoid duplicate paths
		u, _ := url.Parse(targetURL)
		if u != nil {
			targetURL = u.Scheme + "://" + u.Host
		}

		fullURL := targetURL + path

		req, err := http.NewRequest(method, fullURL, strings.NewReader(bodyPart))
		if err != nil {
			return err
		}

		for i := 1; i < len(headerLines); i++ {
			hLine := strings.TrimSpace(headerLines[i])
			if hLine == "" {
				continue
			}
			parts := strings.SplitN(hLine, ":", 2)
			if len(parts) == 2 {
				req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		client := &http.Client{}
		if replayProxy != "" {
			proxyUrl, err := url.Parse(replayProxy)
			if err != nil {
				return err
			}
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
		}

		fmt.Printf("[*] Replaying %s to %s...\n\n", method, fullURL)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		fmt.Printf("--- HTTP %s ---\n", resp.Status)
		for k, v := range resp.Header {
			for _, val := range v {
				fmt.Printf("%s: %s\n", k, val)
			}
		}
		fmt.Println()
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Println(string(respBody))

		return nil
	},
}

var findingsDedupCmd = &cobra.Command{
	Use:   "dedup",
	Short: "Find and optionally tag duplicate findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		count, err := pm.DedupFindings(findingsTarget, findingsWrite)
		if err != nil {
			return err
		}

		if findingsWrite {
			fmt.Printf("[+] Marked %d duplicate findings with 'duplicate' tag.\n", count)
		} else {
			fmt.Printf("[*] Found %d duplicate findings (dry-run). Use --write to tag them.\n", count)
		}
		return nil
	},
}

var findingsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings to various formats (burp-xml, markdown, csv, ndjson, hackerone, bugcrowd, nuclei-targets)",
	RunE: func(cmd *cobra.Command, args []string) error {
		severity, _ := cmd.Flags().GetStringSlice("severity")
		return findingsexport.Export(findingsTarget, findingsFormat, findingsOutput, severity)
	},
}

var findingsPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push findings to ticket system (jira/github/linear)",
	RunE: func(cmd *cobra.Command, args []string) error {
		severity, _ := cmd.Flags().GetStringSlice("severity")
		return findingsexport.Push(findingsTarget, findingsBackend, findingsexport.PushOptions{
			Repo:     findingsRepo,
			Project:  findingsProject,
			Team:     findingsTeam,
			Host:     findingsHost,
			Severity: severity,
			DryRun:   findingsDryRun,
		})
	},
}

func plainFindingValue(f models.Finding) string {
	if f.URL != "" {
		return f.URL
	}
	if f.Host != "" {
		return f.Host
	}
	if f.Target != "" {
		return f.Target
	}
	return f.FindingID
}

func init() {
	findingsListCmd.Flags().StringVarP(&findingsTarget, "target", "t", "", "Target filter")
	findingsListCmd.Flags().StringVar(&findingsSeverity, "severity", "", "Severity filter (comma separated)")
	findingsListCmd.Flags().StringVar(&findingsTag, "tag", "", "Tag filter")
	findingsListCmd.Flags().StringVar(&findingsModule, "module", "", "Module filter")
	findingsListCmd.Flags().StringVar(&findingsType, "type", "", "Finding type filter")
	findingsListCmd.Flags().StringVar(&findingsFormat, "format", "table", "Output format (table, ndjson, plain)")

	findingsShowCmd.Flags().StringVar(&findingsFormat, "format", "text", "Output format (text, json)")

	findingsReplayCmd.Flags().BoolVar(&replayEdit, "edit", false, "Edit request before replaying")
	findingsReplayCmd.Flags().StringVar(&replayProxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")

	findingsDedupCmd.Flags().StringVarP(&findingsTarget, "target", "t", "", "Target filter (required)")
	findingsDedupCmd.MarkFlagRequired("target")
	findingsDedupCmd.Flags().BoolVar(&findingsWrite, "write", false, "Actually apply tags (default is dry-run)")

	findingsExportCmd.Flags().StringVarP(&findingsTarget, "target", "t", "", "Target to export from")
	findingsExportCmd.Flags().StringVarP(&findingsFormat, "format", "f", "markdown", "Format: burp-xml, markdown, csv, ndjson, hackerone, bugcrowd, nuclei-targets")
	findingsExportCmd.Flags().StringVarP(&findingsOutput, "output", "o", "-", "Output file (- for stdout)")
	findingsExportCmd.Flags().StringSlice("severity", nil, "Filter by severity")
	_ = findingsExportCmd.MarkFlagRequired("target")

	findingsPushCmd.Flags().StringVarP(&findingsTarget, "target", "t", "", "Target to push from")
	findingsPushCmd.Flags().StringVar(&findingsBackend, "to", "", "Backend to push to (jira, github, linear)")
	findingsPushCmd.Flags().StringVar(&findingsRepo, "repo", "", "GitHub repository in owner/name form")
	findingsPushCmd.Flags().StringVar(&findingsProject, "project", "", "Jira project key")
	findingsPushCmd.Flags().StringVar(&findingsTeam, "team", "", "Linear team ID")
	findingsPushCmd.Flags().StringVar(&findingsHost, "host", "", "Jira host URL")
	findingsPushCmd.Flags().StringSlice("severity", nil, "Filter by severity")
	findingsPushCmd.Flags().BoolVar(&findingsDryRun, "dry-run", false, "Preview tickets without sending them")
	_ = findingsPushCmd.MarkFlagRequired("target")
	_ = findingsPushCmd.MarkFlagRequired("to")

	findingsCmd.AddCommand(findingsListCmd, findingsShowCmd, findingsTagCmd, findingsUntagCmd, findingsNoteCmd, findingsReplayCmd, findingsDedupCmd, findingsExportCmd, findingsPushCmd)
	rootCmd.AddCommand(findingsCmd)
}
