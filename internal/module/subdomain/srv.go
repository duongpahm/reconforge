package subdomain

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
)

var domainRe = regexp.MustCompile(`(?i)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)`)

// SRVEnum discovers subdomains by querying SRV DNS records using dnsx.
type SRVEnum struct{}

func (m *SRVEnum) Name() string            { return "srv_enum" }
func (m *SRVEnum) Description() string     { return "Subdomain discovery via SRV DNS record enumeration" }
func (m *SRVEnum) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *SRVEnum) Dependencies() []string  { return nil }
func (m *SRVEnum) RequiredTools() []string { return []string{"dnsx"} }

func (m *SRVEnum) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.SRVEnum {
		return fmt.Errorf("SRV enumeration disabled")
	}
	return nil
}

func (m *SRVEnum) Run(ctx context.Context, scan *module.ScanContext) error {
	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("create subdomains dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// Build SRV query list from common SRV prefixes
	srvPrefixes := []string{
		"_ftp._tcp", "_ssh._tcp", "_telnet._tcp", "_smtp._tcp", "_pop3._tcp",
		"_imap._tcp", "_http._tcp", "_https._tcp", "_ldap._tcp", "_kerberos._tcp",
		"_xmpp-client._tcp", "_xmpp-server._tcp", "_sip._tcp", "_sip._udp",
		"_sipfederationtls._tcp", "_autodiscover._tcp", "_imaps._tcp",
		"_pop3s._tcp", "_smtps._tcp", "_submissions._tcp", "_caldav._tcp",
		"_carddav._tcp", "_webdav._tcp", "_rdp._tcp", "_vnc._tcp",
	}

	queriesFile := filepath.Join(tmpDir, "srv_queries.txt")
	var queries []string
	for _, prefix := range srvPrefixes {
		queries = append(queries, fmt.Sprintf("%s.%s", prefix, scan.Target))
	}
	if err := writeLines(queriesFile, queries); err != nil {
		return fmt.Errorf("write SRV queries: %w", err)
	}

	rawFile := filepath.Join(tmpDir, "srv_results_raw.txt")
	scan.Logger.Info().Str("target", scan.Target).Int("queries", len(queries)).Msg("Running SRV record enumeration")

	qf, err := os.Open(queriesFile)
	if err != nil {
		return fmt.Errorf("open queries file: %w", err)
	}
	defer qf.Close()

	result, err := scan.Runner.Run(ctx, "dnsx", []string{
		"-srv",
		"-resp",
		"-silent",
		"-retry", "2",
		"-t", "100",
	}, runner.RunOpts{
		Timeout: 5 * time.Minute,
		Stdin:   qf,
	})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("dnsx SRV enum failed (non-fatal)")
		return nil
	}

	if err := os.WriteFile(rawFile, result.Stdout, 0o644); err != nil {
		scan.Logger.Warn().Err(err).Msg("failed to write SRV raw results")
	}

	// Save raw SRV data
	srvRecordsFile := filepath.Join(subsDir, "srv_records.txt")
	os.WriteFile(srvRecordsFile, result.Stdout, 0o644)

	// Extract hostnames from SRV output
	var hosts []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(result.Stdout)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := domainRe.FindAllString(line, -1)
		for _, m := range matches {
			m = strings.TrimSuffix(m, ".")
			if !seen[m] && strings.HasSuffix(m, scan.Target) {
				seen[m] = true
				hosts = append(hosts, m)
			}
		}
	}

	if len(hosts) > 0 {
		scan.Results.AddSubdomains(hosts)
		scan.Logger.Info().Int("found", len(hosts)).Msg("SRV enum complete")
	}
	return nil
}
