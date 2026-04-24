package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// VirtualHosts discovers virtual hosts by fuzzing known IPs with subdomain wordlists.
type VirtualHosts struct{}

func (m *VirtualHosts) Name() string            { return "virtual_hosts" }
func (m *VirtualHosts) Description() string     { return "Virtual host discovery via VhostFinder" }
func (m *VirtualHosts) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *VirtualHosts) Dependencies() []string  { return []string{"httpx_probe", "port_scan"} }
func (m *VirtualHosts) RequiredTools() []string { return []string{"VhostFinder"} }

func (m *VirtualHosts) Validate(cfg *config.Config) error {
	if !cfg.Web.VirtualHosts {
		return fmt.Errorf("virtual host scanning disabled")
	}
	return nil
}

func (m *VirtualHosts) Run(ctx context.Context, scan *module.ScanContext) error {
	websDir := filepath.Join(scan.OutputDir, "webs")
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}

	ipsFile := filepath.Join(hostsDir, "ips.txt")
	subsFile := filepath.Join(subsDir, "subdomains.txt")

	ips, err := readLines(ipsFile)
	if err != nil || len(ips) == 0 {
		scan.Logger.Warn().Msg("No IPs for virtual host discovery; skipping")
		return nil
	}
	subs, err := readLines(subsFile)
	if err != nil || len(subs) == 0 {
		scan.Logger.Warn().Msg("No subdomains for virtual host wordlist; skipping")
		return nil
	}

	scan.Logger.Info().Int("ips", len(ips)).Int("words", len(subs)).Msg("Running VhostFinder")

	outFile := filepath.Join(websDir, "virtualhosts.txt")
	result, err := scan.Runner.Run(ctx, "VhostFinder", []string{
		"-ips", ipsFile,
		"-wordlist", subsFile,
		"-verify",
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("VhostFinder failed (non-fatal)")
		return nil
	}

	// Filter lines containing "+" (VhostFinder positive indicator)
	var found []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.Contains(line, "+") {
			found = append(found, strings.TrimSpace(line))
		}
	}

	if len(found) > 0 {
		if err := writeLines(outFile, found); err != nil {
			return fmt.Errorf("write vhosts results: %w", err)
		}
	}

	scan.Logger.Info().Int("found", len(found)).Msg("Virtual host discovery complete")
	return nil
}
