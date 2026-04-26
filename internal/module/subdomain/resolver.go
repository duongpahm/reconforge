package subdomain

import (
	"context"
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

// Resolver performs DNS resolution on discovered subdomains using dnsx.
type Resolver struct{}

func (m *Resolver) Name() string            { return "dns_resolve" }
func (m *Resolver) Description() string     { return "DNS resolution and verification via dnsx" }
func (m *Resolver) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *Resolver) Dependencies() []string  { return []string{"subfinder", "crt_sh", "dns_brute"} }
func (m *Resolver) RequiredTools() []string { return []string{"dnsx"} }

func (m *Resolver) Validate(cfg *config.Config) error {
	return nil // always valid if tools available
}

func (m *Resolver) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		scan.Logger.Info().Msg("No subdomains to resolve, skipping")
		return nil
	}

	// Write input
	inputFile := filepath.Join(subsDir, "resolve_input.txt")
	writeLines(inputFile, currentSubs)

	outFile := filepath.Join(subsDir, "resolved.txt")

	args := []string{
		"-l", inputFile,
		"-o", outFile,
		"-a",     // A records
		"-aaaa",  // AAAA records
		"-cname", // CNAME records
		"-resp",  // response data
		"-retry", "3",
		"-silent",
	}

	// Add resolver if configured
	if scan.Config.DNS.Resolver == "dnsx" || scan.Config.DNS.Resolver == "auto" {
		resolversFile := filepath.Join(scan.Config.General.ToolsDir, "resolvers.txt")
		if _, err := os.Stat(resolversFile); err == nil {
			args = append(args, "-r", resolversFile)
		}
	}

	scan.Logger.Info().
		Int("subdomains", len(currentSubs)).
		Msg("Resolving subdomains with dnsx")

	result, err := scan.Runner.Run(ctx, "dnsx", args, runner.RunOpts{
		Timeout: 30 * time.Minute,
		Retry:   1,
	})
	if err != nil {
		return fmt.Errorf("dnsx: %w", err)
	}

	resolved, _ := readLines(outFile)
	// dnsx format: "hostname [A] [ip]"
	var hostnames []string
	for _, line := range resolved {
		host, _, _ := strings.Cut(line, " ")
		if host != "" {
			hostnames = append(hostnames, host)
		}
	}

	scan.Results.AddSubdomains(hostnames)

	scan.Logger.Info().
		Int("input", len(currentSubs)).
		Int("resolved", len(hostnames)).
		Dur("duration", result.Duration).
		Msg("DNS resolution completed")

	return nil
}

var _ module.Module = (*Resolver)(nil)
