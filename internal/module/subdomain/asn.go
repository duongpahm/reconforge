package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// ASNEnum discovers ASN/CIDR metadata for the target using asnmap.
type ASNEnum struct{}

func (m *ASNEnum) Name() string            { return "asn_enum" }
func (m *ASNEnum) Description() string     { return "ASN and CIDR enumeration via asnmap" }
func (m *ASNEnum) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *ASNEnum) Dependencies() []string  { return nil }
func (m *ASNEnum) RequiredTools() []string { return []string{"asnmap"} }

func (m *ASNEnum) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.ASNEnum {
		return fmt.Errorf("ASN enumeration disabled")
	}
	return nil
}

func (m *ASNEnum) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("create hosts dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	jsonOut := filepath.Join(tmpDir, "asnmap.json")

	scan.Logger.Info().Str("target", scan.Target).Msg("Running asnmap ASN enumeration")

	result, err := scan.Runner.Run(ctx, "asnmap", []string{
		"-d", scan.Target,
		"-silent",
		"-j",
	}, runner.RunOpts{Timeout: 2 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("asnmap failed (non-fatal)")
		return nil
	}

	if err := os.WriteFile(jsonOut, result.Stdout, 0o644); err != nil {
		return fmt.Errorf("write asnmap output: %w", err)
	}

	// Parse JSON output: extract CIDRs, ASN numbers, and domains
	var cidrs, asns, domains []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if cidr, ok := obj["cidr"].(string); ok && cidr != "" {
			cidrs = append(cidrs, cidr)
		}
		if asn, ok := obj["as_number"].(string); ok && asn != "" {
			asns = append(asns, asn)
		}
		if domList, ok := obj["domains"].([]interface{}); ok {
			for _, d := range domList {
				if ds, ok := d.(string); ok && ds != "" {
					domains = append(domains, ds)
				}
			}
		}
	}

	if len(cidrs) > 0 {
		cidrFile := filepath.Join(hostsDir, "asn_cidrs.txt")
		if err := writeLines(cidrFile, cidrs); err != nil {
			scan.Logger.Warn().Err(err).Msg("failed to write ASN CIDRs")
		}
	}
	if len(asns) > 0 {
		asnFile := filepath.Join(hostsDir, "asn_numbers.txt")
		if err := writeLines(asnFile, asns); err != nil {
			scan.Logger.Warn().Err(err).Msg("failed to write ASN numbers")
		}
	}

	// Feed discovered domains into subdomain pipeline
	if len(domains) > 0 {
		subsFile := filepath.Join(scan.OutputDir, "subdomains", "subdomains.txt")
		os.MkdirAll(filepath.Dir(subsFile), 0o755)
		scan.Results.AddSubdomains(domains)
	}

	scan.Logger.Info().
		Int("cidrs", len(cidrs)).
		Int("asns", len(asns)).
		Int("domains", len(domains)).
		Msg("asnmap complete")
	return nil
}
