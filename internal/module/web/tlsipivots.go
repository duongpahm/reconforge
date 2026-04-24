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

// TLSIPPivots extracts hostnames from TLS certificates on discovered IPs to find additional subdomains.
type TLSIPPivots struct{}

func (m *TLSIPPivots) Name() string            { return "tls_ip_pivots" }
func (m *TLSIPPivots) Description() string     { return "TLS certificate pivoting on IPs via tlsx" }
func (m *TLSIPPivots) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *TLSIPPivots) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *TLSIPPivots) RequiredTools() []string { return []string{"tlsx"} }

func (m *TLSIPPivots) Validate(cfg *config.Config) error {
	if !cfg.Web.TLSIPPivots {
		return fmt.Errorf("tls_ip_pivots disabled")
	}
	return nil
}

func (m *TLSIPPivots) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// Merge IP sources
	tmpTargets := filepath.Join(tmpDir, "tls_ip_targets.txt")
	var ips []string
	for _, src := range []string{
		filepath.Join(hostsDir, "ips.txt"),
		filepath.Join(hostsDir, "origin_ips.txt"),
	} {
		if lines, err := readLines(src); err == nil {
			ips = append(ips, lines...)
		}
	}
	if len(ips) == 0 {
		scan.Logger.Info().Msg("No IPs for TLS IP pivoting; skipping")
		return nil
	}
	if err := writeLines(tmpTargets, ips); err != nil {
		return fmt.Errorf("write tls ip targets: %w", err)
	}

	scan.Logger.Info().Int("ips", len(ips)).Msg("Running tlsx TLS IP pivoting")

	certsOut := filepath.Join(hostsDir, "tls_ip_certs.jsonl")
	ipsIn, err := os.Open(tmpTargets)
	if err != nil {
		return fmt.Errorf("open ip targets: %w", err)
	}
	defer ipsIn.Close()

	_, err = scan.Runner.Run(ctx, "tlsx", []string{
		"-san", "-cn", "-silent", "-ro", "-resp-only",
		"-p", "443",
		"-json",
		"-o", certsOut,
	}, runner.RunOpts{
		Timeout: 30 * time.Minute,
		Stdin:   ipsIn,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("tlsx failed (non-fatal)")
		return nil
	}

	// Extract hostnames from cert JSONL using jq-style parsing
	var pivotHosts []string
	if data, err := os.ReadFile(certsOut); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Simple field extraction — look for subject_cn and subject_an values
			for _, field := range []string{"subject_cn", "subject_an"} {
				idx := strings.Index(line, `"`+field+`"`)
				if idx < 0 {
					continue
				}
				rest := line[idx+len(field)+3:]
				if strings.HasPrefix(rest, `"`) {
					end := strings.Index(rest[1:], `"`)
					if end >= 0 {
						host := rest[1 : end+1]
						host = strings.TrimPrefix(host, "*.")
						if strings.Contains(host, ".") {
							pivotHosts = append(pivotHosts, host)
						}
					}
				}
			}
		}
	}

	if len(pivotHosts) == 0 {
		scan.Logger.Info().Msg("No hostnames found in TLS certs")
		return nil
	}

	pivotsFile := filepath.Join(subsDir, "tls_ip_pivots.txt")
	// Filter to in-scope (containing target domain)
	var inScope []string
	for _, h := range pivotHosts {
		if strings.Contains(h, scan.Target) {
			inScope = append(inScope, h)
		}
	}
	if len(inScope) == 0 {
		inScope = pivotHosts
	}

	writeLines(pivotsFile, inScope)
	scan.Results.AddSubdomains(inScope)
	scan.Logger.Info().Int("new_subs", len(inScope)).Msg("tls_ip_pivots complete")
	return nil
}
