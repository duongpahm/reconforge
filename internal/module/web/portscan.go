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

// PortScan runs naabu for fast port discovery then nmap for service detection,
// matching the reconFTW portscan() naabu_nmap strategy.
type PortScan struct{}

func (m *PortScan) Name() string            { return "port_scan" }
func (m *PortScan) Description() string     { return "Port scanning via naabu + nmap" }
func (m *PortScan) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *PortScan) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *PortScan) RequiredTools() []string { return []string{"naabu"} }

func (m *PortScan) Validate(cfg *config.Config) error {
	if !cfg.Web.PortScan {
		return fmt.Errorf("port scanning disabled")
	}
	return nil
}

func (m *PortScan) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	websDir := filepath.Join(scan.OutputDir, "webs")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("create hosts dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return fmt.Errorf("create webs dir: %w", err)
	}

	// Build IP list from resolved subdomains
	ipsFile := filepath.Join(hostsDir, "ips.txt")
	ipsNoCDNFile := filepath.Join(tmpDir, "ips_nocdn.txt")

	// Use ips.txt if it exists, otherwise fall back to resolved subdomains
	if _, err := os.Stat(ipsFile); os.IsNotExist(err) {
		scan.Logger.Warn().Msg("No hosts/ips.txt found; port scan skipped")
		return nil
	}

	ips, err := readLines(ipsNoCDNFile)
	if err != nil || len(ips) == 0 {
		// Fallback to all IPs
		ips, err = readLines(ipsFile)
		if err != nil || len(ips) == 0 {
			scan.Logger.Warn().Msg("No IPs to scan")
			return nil
		}
		_ = writeLines(ipsNoCDNFile, ips)
	}

	scan.Logger.Info().Int("ips", len(ips)).Msg("Running naabu port discovery")

	// Phase 1: naabu fast port discovery
	naabuOut := filepath.Join(hostsDir, "naabu_open.txt")
	_, err = scan.Runner.Run(ctx, "naabu", []string{
		"-list", ipsNoCDNFile,
		"-silent",
		"-rate", "1000",
		"-top-ports", "1000",
		"-o", naabuOut,
	}, runner.RunOpts{Timeout: 30 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("naabu failed (non-fatal)")
		return nil
	}

	// Extract open ports from naabu output (format: ip:port)
	naabuLines, err := readLines(naabuOut)
	if err != nil || len(naabuLines) == 0 {
		scan.Logger.Info().Msg("No open ports found by naabu")
		return nil
	}

	// Build comma-separated port list for nmap
	portSet := make(map[string]bool)
	for _, line := range naabuLines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 {
			portSet[parts[1]] = true
		}
	}
	var ports []string
	for p := range portSet {
		ports = append(ports, p)
	}
	portList := strings.Join(ports, ",")

	// Phase 2: nmap service fingerprinting on discovered ports
	scan.Logger.Info().Str("ports", portList).Msg("Running nmap service fingerprinting")
	nmapBase := filepath.Join(hostsDir, "portscan_active")
	_, err = scan.Runner.Run(ctx, "nmap", []string{
		"-sV",
		"--open",
		"-n",
		"-Pn",
		"-p", portList,
		"-iL", ipsNoCDNFile,
		"-oA", nmapBase,
	}, runner.RunOpts{Timeout: 60 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("nmap failed (non-fatal)")
	}

	// Extract web URLs from nmap output using nmapurls if available
	nmapXML := nmapBase + ".xml"
	if _, err := os.Stat(nmapXML); err == nil {
		nmapWebsOut, err := scan.Runner.Run(ctx, "nmapurls", []string{}, runner.RunOpts{
			Timeout: 1 * time.Minute,
			Stdin:   mustOpen(nmapXML),
		})
		if err == nil && nmapWebsOut != nil {
			var webURLs []string
			for _, u := range strings.Split(string(nmapWebsOut.Stdout), "\n") {
				u = strings.TrimSpace(u)
				if u != "" {
					webURLs = append(webURLs, u)
				}
			}
			if len(webURLs) > 0 {
				websFile := filepath.Join(websDir, "webs.txt")
				existing, _ := readLines(websFile)
				merged := dedupLines(append(existing, webURLs...))
				writeLines(websFile, merged)
				scan.Logger.Info().Int("web_urls", len(webURLs)).Msg("Extracted web URLs from nmap")
			}
		}
	}

	scan.Logger.Info().
		Int("open_ports", len(naabuLines)).
		Msg("Port scan complete")
	return nil
}

func mustOpen(path string) *os.File {
	f, _ := os.Open(path)
	return f
}

func dedupLines(lines []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lines {
		if l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
