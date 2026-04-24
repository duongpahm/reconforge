package subdomain

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

// --- ZoneTransfer ---

// ZoneTransfer attempts DNS zone transfer (AXFR) against nameservers.
type ZoneTransfer struct{}

func (m *ZoneTransfer) Name() string            { return "zone_transfer" }
func (m *ZoneTransfer) Description() string     { return "DNS zone transfer (AXFR) detection" }
func (m *ZoneTransfer) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *ZoneTransfer) Dependencies() []string  { return nil }
func (m *ZoneTransfer) RequiredTools() []string { return []string{"dig"} }

func (m *ZoneTransfer) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.ZoneTransfer {
		return fmt.Errorf("zone transfer scanning disabled")
	}
	return nil
}

func (m *ZoneTransfer) Run(ctx context.Context, scan *module.ScanContext) error {
	scan.Logger.Info().Str("target", scan.Target).Msg("Attempting zone transfer")

	// Get nameservers
	nss, err := net.DefaultResolver.LookupNS(ctx, scan.Target)
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("NS lookup failed")
		return nil
	}

	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	os.MkdirAll(subsDir, 0o755)
	outFile := filepath.Join(subsDir, "zone_transfer.txt")

	var allSubs []string

	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")

		result, err := scan.Runner.Run(ctx, "dig", []string{
			"AXFR",
			scan.Target,
			fmt.Sprintf("@%s", nsHost),
			"+noall", "+answer", "+short",
		}, runner.RunOpts{
			Timeout: 30 * time.Second,
		})
		if err != nil {
			continue
		}

		subs := parseLines(result.Stdout)
		if len(subs) > 0 {
			scan.Logger.Warn().
				Str("ns", nsHost).
				Int("records", len(subs)).
				Msg("Zone transfer SUCCESSFUL — security finding!")

			allSubs = append(allSubs, subs...)

			scan.Results.AddFindings([]module.Finding{{
				Module:   "zone_transfer",
				Type:     "vuln",
				Severity: "high",
				Target:   nsHost,
				Detail:   fmt.Sprintf("DNS zone transfer allowed on %s — %d records leaked", nsHost, len(subs)),
			}})
		}
	}

	if len(allSubs) > 0 {
		writeLines(outFile, allSubs)
		scan.Results.AddSubdomains(allSubs)
	}

	scan.Logger.Info().
		Int("ns_checked", len(nss)).
		Int("records", len(allSubs)).
		Msg("Zone transfer check completed")

	return nil
}

// --- S3Buckets ---

// S3Buckets detects misconfigured S3 buckets associated with the target.
type S3Buckets struct{}

func (m *S3Buckets) Name() string            { return "s3_buckets" }
func (m *S3Buckets) Description() string     { return "S3 bucket misconfiguration detection" }
func (m *S3Buckets) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *S3Buckets) Dependencies() []string  { return []string{"subfinder"} }
func (m *S3Buckets) RequiredTools() []string { return []string{"s3scanner"} }

func (m *S3Buckets) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.S3Buckets {
		return fmt.Errorf("S3 bucket scanning disabled")
	}
	return nil
}

func (m *S3Buckets) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	os.MkdirAll(subsDir, 0o755)

	// Generate potential bucket names from target
	bucketNames := generateBucketNames(scan.Target)
	inputFile := filepath.Join(subsDir, "s3_input.txt")
	writeLines(inputFile, bucketNames)

	outFile := filepath.Join(subsDir, "s3_results.txt")

	scan.Logger.Info().
		Int("candidates", len(bucketNames)).
		Msg("Scanning for S3 bucket misconfigurations")

	result, err := scan.Runner.Run(ctx, "s3scanner", []string{
		"-bucket-file", inputFile,
		"-o", outFile,
	}, runner.RunOpts{
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("s3scanner failed (non-fatal)")
		return nil
	}

	findings, _ := readLines(outFile)
	for _, f := range findings {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "s3_buckets",
			Type:     "vuln",
			Severity: "medium",
			Target:   scan.Target,
			Detail:   fmt.Sprintf("S3 bucket misconfiguration: %s", f),
		}})
	}

	scan.Logger.Info().
		Int("checked", len(bucketNames)).
		Int("findings", len(findings)).
		Dur("duration", result.Duration).
		Msg("S3 bucket scan completed")

	return nil
}

// generateBucketNames creates potential S3 bucket names from a domain.
func generateBucketNames(domain string) []string {
	base := strings.Split(domain, ".")[0]
	suffixes := []string{
		"", "-backup", "-bak", "-dev", "-staging", "-prod", "-data",
		"-assets", "-media", "-uploads", "-static", "-logs",
		"-db", "-internal", "-private", "-public", "-test",
	}

	var names []string
	for _, sfx := range suffixes {
		names = append(names, base+sfx)
		names = append(names, domain+sfx)
	}
	return names
}

// --- TLSGrab ---

// TLSGrab extracts subdomains from TLS certificates using tlsx.
type TLSGrab struct{}

func (m *TLSGrab) Name() string            { return "tls_grab" }
func (m *TLSGrab) Description() string     { return "TLS certificate subdomain extraction via tlsx" }
func (m *TLSGrab) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *TLSGrab) Dependencies() []string  { return []string{"subfinder"} }
func (m *TLSGrab) RequiredTools() []string { return []string{"tlsx"} }

func (m *TLSGrab) Validate(cfg *config.Config) error {
	return nil
}

func (m *TLSGrab) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	os.MkdirAll(subsDir, 0o755)

	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		return nil
	}

	inputFile := filepath.Join(subsDir, "tlsx_input.txt")
	writeLines(inputFile, currentSubs)

	outFile := filepath.Join(subsDir, "tls_sans.txt")

	args := []string{
		"-l", inputFile,
		"-san", // extract Subject Alternative Names
		"-cn",  // extract Common Name
		"-silent",
		"-o", outFile,
		"-p", "443,8443",
		"-c", "50",
	}

	scan.Logger.Info().
		Int("hosts", len(currentSubs)).
		Msg("Extracting subdomains from TLS certificates")

	result, err := scan.Runner.Run(ctx, "tlsx", args, runner.RunOpts{
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("tlsx failed (non-fatal)")
		return nil
	}

	subs, _ := readLines(outFile)
	// Filter to only include subdomains of the target
	var relevant []string
	for _, s := range subs {
		if strings.HasSuffix(s, "."+scan.Target) || s == scan.Target {
			relevant = append(relevant, s)
		}
	}

	added := scan.Results.AddSubdomains(relevant)

	scan.Logger.Info().
		Int("tls_hosts", len(currentSubs)).
		Int("sans_found", len(subs)).
		Int("relevant", len(relevant)).
		Int("new", added).
		Dur("duration", result.Duration).
		Msg("TLS certificate extraction completed")

	return nil
}

// Compile-time interface checks.
var (
	_ module.Module = (*ZoneTransfer)(nil)
	_ module.Module = (*S3Buckets)(nil)
	_ module.Module = (*TLSGrab)(nil)
)
