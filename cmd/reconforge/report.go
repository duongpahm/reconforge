package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/reconforge/reconforge/internal/project"
	"github.com/spf13/cobra"
)

var (
	reportTarget   string
	reportTemplate string
	reportOut      string
	reportSeverity string
	reportTag      string
)

var (
	hackeroneTemplate = `
# {{ .Title }}

**Target:** {{ .Target }}
**Severity:** {{ .Severity }}
**URL:** {{ .URL }}

## Description
{{ .Description }}

## Proof of Concept
` + "```http" + `
{{ .RequestRaw }}
` + "```" + `

## Impact
Please refer to the CVSS vector associated with this vulnerability type.
`

	bugcrowdTemplate = `
# Vulnerability Report: {{ .Title }}

**VRT Category:** Server-Side Injection (Example)
**Target:** {{ .URL }}

## Bug Description
{{ .Description }}

## Proof of Concept (PoC)
` + "```" + `
{{ .RequestRaw }}
` + "```" + `

## Remediation
Apply appropriate security patches and input validation.
`

	executiveTemplate = `
# Executive Summary

**Engagement Target:** {{ .Target }}
**Total Findings:** {{ len .Findings }}

## Key Findings
{{ range .Findings }}
### [{{ .Severity }}] {{ .Title }}
- **Location:** {{ .URL }}
- **Module:** {{ .Module }}
{{ end }}

Please review the detailed technical attachments for remediation steps.
`
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		if reportTarget == "" {
			return fmt.Errorf("--target is required")
		}

		pm, err := project.NewManager()
		if err != nil {
			return err
		}
		defer pm.Close()

		findings, err := pm.ListFindings(reportTarget, reportSeverity, reportTag, "", "")
		if err != nil {
			return err
		}

		if len(findings) == 0 {
			return fmt.Errorf("no findings found matching criteria")
		}

		var tplString string
		switch strings.ToLower(reportTemplate) {
		case "hackerone", "h1":
			tplString = hackeroneTemplate
		case "bugcrowd", "bc":
			tplString = bugcrowdTemplate
		case "executive", "exec":
			tplString = executiveTemplate
		default:
			return fmt.Errorf("unknown template: %s (use hackerone, bugcrowd, or executive)", reportTemplate)
		}

		t, err := template.New("report").Parse(tplString)
		if err != nil {
			return err
		}

		var buf bytes.Buffer

		if strings.ToLower(reportTemplate) == "executive" || strings.ToLower(reportTemplate) == "exec" {
			// Executive report takes all findings
			data := struct {
				Target   string
				Findings interface{}
			}{
				Target:   reportTarget,
				Findings: findings,
			}
			if err := t.Execute(&buf, data); err != nil {
				return err
			}
		} else {
			// Platform reports are usually per-finding. We will just render the highest severity one for now,
			// or the user can filter by --tag hot to get a specific one.
			f := findings[0] // take first finding
			if err := t.Execute(&buf, f); err != nil {
				return err
			}
		}

		if reportOut != "" {
			if err := os.WriteFile(reportOut, buf.Bytes(), 0o644); err != nil {
				return err
			}
			fmt.Printf("[+] Report generated: %s\n", reportOut)
		} else {
			fmt.Println(buf.String())
		}
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVarP(&reportTarget, "target", "t", "", "Target filter")
	reportCmd.Flags().StringVar(&reportTemplate, "template", "executive", "Template to use (hackerone, bugcrowd, executive)")
	reportCmd.Flags().StringVarP(&reportOut, "out", "o", "", "Output file")
	reportCmd.Flags().StringVar(&reportSeverity, "severity", "", "Severity filter (comma separated)")
	reportCmd.Flags().StringVar(&reportTag, "tag", "", "Tag filter")

	rootCmd.AddCommand(reportCmd)
}
