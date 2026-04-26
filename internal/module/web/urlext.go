package web

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
)

// URLExt groups extracted URLs by extension and flags suspicious file types.
type URLExt struct{}

func (m *URLExt) Name() string { return "urlext" }
func (m *URLExt) Description() string {
	return "URL extension grouping and sensitive extension detection"
}
func (m *URLExt) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *URLExt) Dependencies() []string  { return []string{"url_checks"} }
func (m *URLExt) RequiredTools() []string { return nil }

func (m *URLExt) Validate(cfg *config.Config) error {
	if !cfg.Web.URLExt {
		return fmt.Errorf("urlext disabled")
	}
	return nil
}

func (m *URLExt) Run(_ context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	if err := ensureDir(websDir); err != nil {
		return err
	}

	urlFile := filepath.Join(websDir, "url_extract.txt")
	urls, err := readLines(urlFile)
	if err != nil || len(urls) == 0 {
		scan.Logger.Info().Msg("No URL input for urlext; skipping")
		return nil
	}

	extToURLs := make(map[string][]string)
	suspiciousExts := map[string]bool{
		"bak":    true,
		"backup": true,
		"config": true,
		"db":     true,
		"env":    true,
		"ini":    true,
		"json":   true,
		"key":    true,
		"log":    true,
		"old":    true,
		"pem":    true,
		"p12":    true,
		"rar":    true,
		"sql":    true,
		"sqlite": true,
		"tar":    true,
		"txt":    true,
		"xml":    true,
		"yaml":   true,
		"yml":    true,
		"zip":    true,
	}

	var findings []module.Finding
	for _, rawURL := range urls {
		ext := normalizeURLExtension(rawURL)
		if ext == "" {
			continue
		}
		extToURLs[ext] = append(extToURLs[ext], rawURL)
		if suspiciousExts[ext] {
			findings = append(findings, module.Finding{
				Module:   "urlext",
				Type:     "url",
				Severity: "medium",
				Target:   rawURL,
				Detail:   fmt.Sprintf("Suspicious file extension detected: .%s", ext),
			})
		}
	}

	written := 0
	for ext, lines := range extToURLs {
		if len(lines) == 0 {
			continue
		}
		outFile := filepath.Join(websDir, fmt.Sprintf("url_ext_%s.txt", ext))
		if err := writeLines(outFile, dedupLines(lines)); err == nil {
			written++
		}
	}

	if len(findings) > 0 {
		if !scan.Config.General.Deep && len(findings) > 500 {
			findings = findings[:500]
		}
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Int("extensions", written).Int("suspicious", len(findings)).Msg("urlext complete")
	return nil
}

func normalizeURLExtension(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), "."))
	if ext == "" {
		return ""
	}
	if len(ext) > 12 {
		return ""
	}
	for _, c := range ext {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return ""
		}
	}
	return ext
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", path, err)
	}
	return nil
}

var _ module.Module = (*URLExt)(nil)
