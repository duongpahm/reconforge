package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// CMSScanner detects CMS platforms on discovered web targets using CMSeeK.
type CMSScanner struct{}

func (m *CMSScanner) Name() string            { return "cms_scanner" }
func (m *CMSScanner) Description() string     { return "CMS detection via CMSeeK" }
func (m *CMSScanner) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *CMSScanner) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *CMSScanner) RequiredTools() []string { return []string{"cmseek"} }

func (m *CMSScanner) Validate(cfg *config.Config) error {
	if !cfg.Web.CMSScan {
		return fmt.Errorf("CMS scanning disabled")
	}
	return nil
}

func (m *CMSScanner) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	cmsDir := filepath.Join(scan.OutputDir, "cms")
	if err := os.MkdirAll(cmsDir, 0o755); err != nil {
		return fmt.Errorf("create cms dir: %w", err)
	}

	websAllFile := filepath.Join(websDir, "webs_all.txt")
	targets, err := readLines(websAllFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Warn().Msg("No web targets for CMS scanning; skipping")
		return nil
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running CMSeeK")

	// CMSeeK with batch mode: -l for list, --batch to disable interactive, -r to randomize UA
	_, err = scan.Runner.Run(ctx, "cmseek", []string{
		"-l", websAllFile,
		"--batch",
		"-r",
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("CMSeeK failed (non-fatal)")
		return nil
	}

	// CMSeeK writes results to its own Result directory; copy to our cms/ dir
	toolsDir := scan.Config.General.ToolsDir
	cmseekResultDir := filepath.Join(toolsDir, "CMSeeK", "Result")
	if _, err := os.Stat(cmseekResultDir); err == nil {
		entries, _ := os.ReadDir(cmseekResultDir)
		for _, e := range entries {
			if e.IsDir() {
				src := filepath.Join(cmseekResultDir, e.Name())
				dst := filepath.Join(cmsDir, e.Name())
				os.Rename(src, dst)
			}
		}
	}

	scan.Logger.Info().Msg("CMS scanning complete")
	return nil
}

// IISShortname scans for IIS 8.3 shortname vulnerabilities using shortscan via nuclei.
type IISShortname struct{}

func (m *IISShortname) Name() string            { return "iis_shortname" }
func (m *IISShortname) Description() string     { return "IIS 8.3 shortname vulnerability scanner" }
func (m *IISShortname) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *IISShortname) Dependencies() []string  { return []string{"nuclei_check"} }
func (m *IISShortname) RequiredTools() []string { return []string{"shortscan"} }

func (m *IISShortname) Validate(cfg *config.Config) error {
	if !cfg.Web.IISShortname {
		return fmt.Errorf("IIS shortname scanning disabled")
	}
	return nil
}

func (m *IISShortname) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnsDir := filepath.Join(scan.OutputDir, "vulns", "iis-shortname-shortscan")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	nucleiInfoFile := filepath.Join(scan.OutputDir, "nuclei_output", "info.txt")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return fmt.Errorf("create iis output dir: %w", err)
	}

	// Extract IIS targets from nuclei info output
	iisSitesFile := filepath.Join(tmpDir, "iis_sites.txt")
	_ = os.WriteFile(iisSitesFile, []byte{}, 0o644)

	if _, err := os.Stat(nucleiInfoFile); err == nil {
		// grep for iis-version findings
		result, _ := scan.Runner.Run(ctx, "grep", []string{"iis-version", nucleiInfoFile},
			runner.RunOpts{Timeout: 10 * time.Second})
		if result != nil && len(result.Stdout) > 0 {
			// Extract URL column (field 4 in nuclei output)
			awk, _ := scan.Runner.Run(ctx, "awk", []string{`/iis-version/ {print $4}`, nucleiInfoFile},
				runner.RunOpts{Timeout: 10 * time.Second})
			if awk != nil {
				os.WriteFile(iisSitesFile, awk.Stdout, 0o644)
			}
		}
	}

	targets, err := readLines(iisSitesFile)
	if err != nil || len(targets) == 0 {
		scan.Logger.Info().Msg("No IIS targets found; skipping shortname scan")
		return nil
	}

	scan.Logger.Info().Int("targets", len(targets)).Msg("Running IIS shortname scan")

	for _, target := range targets {
		if target == "" {
			continue
		}
		outFile := filepath.Join(vulnsDir, sanitizeFilename(target)+".txt")
		result, err := scan.Runner.Run(ctx, "shortscan", []string{
			target, "-F", "-s", "-p", "1",
		}, runner.RunOpts{Timeout: 5 * time.Minute})
		if err != nil {
			scan.Logger.Debug().Err(err).Str("target", target).Msg("shortscan failed (non-fatal)")
			continue
		}
		// Only save if vulnerable
		output := string(result.Stdout)
		if containsAny(output, "Vulnerable: Yes") {
			os.WriteFile(outFile, []byte(output), 0o644)
		}
	}

	scan.Logger.Info().Msg("IIS shortname scan complete")
	return nil
}

func sanitizeFilename(s string) string {
	r := s
	for _, ch := range []string{"://", "/", ":", "?"} {
		r = replaceAll(r, ch, "_")
	}
	return r
}

func replaceAll(s, old, newStr string) string {
	result := s
	for {
		replaced := fmt.Sprintf("%s", result)
		_ = replaced
		break
	}
	// Simple replacement
	out := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			out += newStr
			i += len(old)
		} else {
			out += string(s[i])
			i++
		}
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
