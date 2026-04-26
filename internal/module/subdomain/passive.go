// Package subdomain implements passive subdomain enumeration modules.
package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// --- Subfinder ---

// Subfinder performs passive subdomain enumeration using subfinder.
type Subfinder struct{}

func (m *Subfinder) Name() string            { return "subfinder" }
func (m *Subfinder) Description() string     { return "Fast passive subdomain enumeration via subfinder" }
func (m *Subfinder) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *Subfinder) Dependencies() []string  { return nil }
func (m *Subfinder) RequiredTools() []string { return []string{"subfinder"} }

func (m *Subfinder) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Passive {
		return fmt.Errorf("passive subdomain scanning disabled")
	}
	return nil
}

func (m *Subfinder) Run(ctx context.Context, scan *module.ScanContext) error {
	outFile := filepath.Join(scan.OutputDir, "subdomains", "subfinder.txt")
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	args := []string{
		"-d", scan.Target,
		"-all",
		"-o", outFile,
		"-silent",
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running subfinder")

	result, err := scan.Runner.Run(ctx, "subfinder", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("subfinder failed (non-fatal)")
		return nil
	}

	subs, _ := readLines(outFile)
	added := scan.Results.AddSubdomains(subs)

	scan.Logger.Info().
		Int("found", len(subs)).
		Int("new", added).
		Dur("duration", result.Duration).
		Msg("Subfinder completed")

	return nil
}

// --- CrtSh ---

// CrtSh enumerates subdomains via Certificate Transparency logs (crt.sh).
type CrtSh struct{}

func (m *CrtSh) Name() string { return "crt_sh" }
func (m *CrtSh) Description() string {
	return "Certificate Transparency subdomain discovery via crt.sh"
}
func (m *CrtSh) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *CrtSh) Dependencies() []string  { return nil }
func (m *CrtSh) RequiredTools() []string { return nil }

func (m *CrtSh) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.CRT {
		return fmt.Errorf("crt.sh scanning disabled")
	}
	return nil
}

func (m *CrtSh) Run(ctx context.Context, scan *module.ScanContext) error {
	outFile := filepath.Join(scan.OutputDir, "subdomains", "crt_sh.txt")
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Querying crt.sh")

	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", scan.Target)

	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiURL, nil)
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("crt.sh request build failed (non-fatal)")
		return nil
	}
	req.Header.Set("User-Agent", "reconforge/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("crt.sh query failed (non-fatal)")
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("crt.sh read failed (non-fatal)")
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		scan.Logger.Warn().Err(err).Msg("crt.sh parse failed (non-fatal)")
		return nil
	}

	seen := make(map[string]bool)
	var filtered []string
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			s := strings.TrimSpace(strings.TrimPrefix(raw, "*."))
			if s == "" || strings.HasPrefix(s, "*") || seen[s] {
				continue
			}
			seen[s] = true
			filtered = append(filtered, s)
		}
	}

	writeLines(outFile, filtered)
	added := scan.Results.AddSubdomains(filtered)

	scan.Logger.Info().
		Int("found", len(filtered)).
		Int("new", added).
		Msg("crt.sh completed")

	return nil
}

// --- GithubSubdomains ---

// GithubSubdomains discovers subdomains from GitHub code search.
type GithubSubdomains struct{}

func (m *GithubSubdomains) Name() string            { return "github_subs" }
func (m *GithubSubdomains) Description() string     { return "Subdomain discovery via GitHub code search" }
func (m *GithubSubdomains) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *GithubSubdomains) Dependencies() []string  { return nil }
func (m *GithubSubdomains) RequiredTools() []string { return []string{"github-subdomains"} }

func (m *GithubSubdomains) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.Passive {
		return fmt.Errorf("passive subdomain scanning disabled")
	}
	return nil
}

func (m *GithubSubdomains) Run(ctx context.Context, scan *module.ScanContext) error {
	outFile := filepath.Join(scan.OutputDir, "subdomains", "github_subs.txt")
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	args := []string{
		"-d", scan.Target,
		"-o", outFile,
	}

	scan.Logger.Info().Str("target", scan.Target).Msg("Running github-subdomains")

	_, err := scan.Runner.Run(ctx, "github-subdomains", args, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("github-subdomains failed (non-fatal)")
		return nil
	}

	subs, _ := readLines(outFile)
	added := scan.Results.AddSubdomains(subs)

	scan.Logger.Info().
		Int("found", len(subs)).
		Int("new", added).
		Msg("github-subdomains completed")

	return nil
}

// --- Helpers ---

// readLines reads non-empty lines from a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// parseLines splits bytes into non-empty trimmed lines.
func parseLines(data []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// writeLines writes lines to a file.
func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

// Compile-time interface checks.
var (
	_ module.Module = (*Subfinder)(nil)
	_ module.Module = (*CrtSh)(nil)
	_ module.Module = (*GithubSubdomains)(nil)
)
