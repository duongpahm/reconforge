package subdomain

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

// NSDelegation discovers subdomains via NS delegation zone transfer checks using dnsx.
type NSDelegation struct{}

func (m *NSDelegation) Name() string { return "sub_ns_delegation" }
func (m *NSDelegation) Description() string {
	return "NS delegation zone transfer subdomain discovery via dnsx"
}
func (m *NSDelegation) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *NSDelegation) Dependencies() []string  { return []string{"subdomain_passive"} }
func (m *NSDelegation) RequiredTools() []string { return []string{"dnsx"} }

func (m *NSDelegation) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.NSDelegation {
		return fmt.Errorf("sub_ns_delegation disabled")
	}
	return nil
}

func (m *NSDelegation) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	subsFile := filepath.Join(subsDir, "subdomains.txt")
	if _, err := os.Stat(subsFile); os.IsNotExist(err) {
		scan.Logger.Info().Msg("No subdomains.txt; sub_ns_delegation skipped")
		return nil
	}

	subsIn, err := os.Open(subsFile)
	if err != nil {
		return fmt.Errorf("open subdomains: %w", err)
	}
	defer subsIn.Close()

	scan.Logger.Info().Msg("Running dnsx NS delegation check")

	rawOut := filepath.Join(tmpDir, "ns_delegation_raw.txt")
	result, err := scan.Runner.Run(ctx, "dnsx", []string{
		"-ns", "-resp", "-silent", "-retry", "2",
		"-t", "100",
		"-o", rawOut,
	}, runner.RunOpts{
		Timeout: 15 * time.Minute,
		Stdin:   subsIn,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("dnsx ns delegation failed (non-fatal)")
		return nil
	}

	rawLines := strings.Split(string(result.Stdout), "\n")
	if content, err := os.ReadFile(rawOut); err == nil {
		rawLines = strings.Split(string(content), "\n")
	}

	var delegatedZones []string
	var newSubs []string

	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sub := fields[0]
		if sub == scan.Target {
			continue
		}
		delegatedZones = append(delegatedZones, sub)

		// Extract NS hostnames from the response and attempt AXFR
		for _, f := range fields[1:] {
			f = strings.Trim(f, "[]")
			if !strings.Contains(f, ".") {
				continue
			}
			// Attempt zone transfer via dig (run as shell command via runner)
			axfrResult, axfrErr := scan.Runner.Run(ctx, "dig", []string{
				"axfr", sub, "@" + f, "+short",
			}, runner.RunOpts{Timeout: 30 * time.Second})
			if axfrErr != nil {
				continue
			}
			for _, axfrLine := range strings.Split(string(axfrResult.Stdout), "\n") {
				axfrLine = strings.TrimSpace(strings.TrimSuffix(axfrLine, "."))
				if axfrLine == "" || !strings.Contains(axfrLine, ".") {
					continue
				}
				if strings.Contains(axfrLine, scan.Target) {
					newSubs = append(newSubs, axfrLine)
				}
			}
		}
	}

	if len(delegatedZones) > 0 {
		outZones := filepath.Join(subsDir, "ns_delegated_zones.txt")
		writeLines(outZones, delegatedZones)
	}

	if len(newSubs) > 0 {
		added := scan.Results.AddSubdomains(newSubs)
		scan.Logger.Info().Int("delegated_zones", len(delegatedZones)).Int("new_subs", added).Msg("sub_ns_delegation complete")
	} else {
		scan.Logger.Info().Int("delegated_zones", len(delegatedZones)).Msg("sub_ns_delegation complete (no new subs from AXFR)")
	}
	return nil
}
