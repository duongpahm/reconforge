package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// GeoInfo enriches discovered public IPs with geolocation and ASN metadata.
type GeoInfo struct{}

func (m *GeoInfo) Name() string            { return "geo_info" }
func (m *GeoInfo) Description() string     { return "Enrich public IPs with geolocation and ASN metadata" }
func (m *GeoInfo) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *GeoInfo) Dependencies() []string  { return []string{} }
func (m *GeoInfo) RequiredTools() []string { return []string{"curl"} }

func (m *GeoInfo) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.GeoInfo {
		return fmt.Errorf("geo_info disabled")
	}
	return nil
}

func (m *GeoInfo) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("create hosts dir: %w", err)
	}

	inputFile := filepath.Join(hostsDir, "ips.txt")
	ips, err := readPublicIPs(inputFile)
	if err != nil {
		return fmt.Errorf("read ips: %w", err)
	}
	if len(ips) == 0 {
		if ip := sanitizePublicIP(scan.Target); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		scan.Logger.Info().Msg("No public IPs available for geo_info; skipping")
		return nil
	}

	if !scan.Config.General.Deep && len(ips) > 500 {
		scan.Logger.Warn().Int("ips", len(ips)).Msg("Too many IPs for geo_info; truncating to first 500 (use deep mode)")
		ips = ips[:500]
	}

	rawFile := filepath.Join(hostsDir, "ipinfo.txt")
	summaryFile := filepath.Join(hostsDir, "geo_info.txt")
	rawHandle, err := os.Create(rawFile)
	if err != nil {
		return fmt.Errorf("create raw geo file: %w", err)
	}
	defer rawHandle.Close()

	records := make([]string, 0, len(ips))
	findings := make([]module.Finding, 0, len(ips))

	for _, ip := range ips {
		record, err := lookupGeoRecord(ctx, scan, ip)
		if err != nil {
			scan.Logger.Warn().Err(err).Str("ip", ip).Msg("geo_info lookup failed")
			continue
		}

		if len(record.Raw) > 0 {
			if _, err := rawHandle.Write(append(record.Raw, '\n')); err != nil {
				scan.Logger.Warn().Err(err).Str("ip", ip).Msg("failed to append ipinfo raw record")
			}
		}

		line := strings.Join([]string{
			record.IP,
			emptyFallback(record.Country, "-"),
			emptyFallback(record.City, "-"),
			emptyFallback(record.ASN, "-"),
			emptyFallback(record.Org, "-"),
		}, "\t")
		records = append(records, line)

		findings = append(findings, module.Finding{
			Module:   m.Name(),
			Type:     "info",
			Severity: "info",
			Target:   record.IP,
			Detail:   fmt.Sprintf("GeoIP %s %s %s", emptyFallback(record.Country, "-"), emptyFallback(record.ASN, "-"), emptyFallback(record.Org, "-")),
		})
	}

	if len(records) == 0 {
		scan.Logger.Info().Msg("geo_info completed with no successful lookups")
		return nil
	}

	if err := writeLines(summaryFile, records); err != nil {
		return fmt.Errorf("write geo summary: %w", err)
	}
	scan.Results.AddFindings(findings)

	scan.Logger.Info().Int("ips", len(records)).Msg("geo_info complete")
	return nil
}

type geoRecord struct {
	IP      string
	Country string
	City    string
	ASN     string
	Org     string
	Raw     []byte
}

func lookupGeoRecord(ctx context.Context, scan *module.ScanContext, ip string) (geoRecord, error) {
	record := geoRecord{IP: ip}

	result, err := scan.Runner.Run(ctx, "curl", []string{
		"-sS",
		fmt.Sprintf("https://ipinfo.io/widget/demo/%s", ip),
	}, runner.RunOpts{Timeout: 30 * time.Second})
	if err != nil {
		return record, err
	}
	record.Raw = append([]byte(nil), result.Stdout...)

	var geo ipinfoResponse
	if err := json.Unmarshal(result.Stdout, &geo); err == nil {
		record.Country = strings.TrimSpace(geo.Country)
		record.City = strings.TrimSpace(geo.City)
		record.Org = strings.TrimSpace(geo.Org)
		if geo.ASN.ASN != "" {
			record.ASN = strings.TrimSpace(geo.ASN.ASN)
		}
		if record.Org == "" && geo.ASN.Name != "" {
			record.Org = strings.TrimSpace(geo.ASN.Name)
		}
	}

	if record.ASN == "" && scan.Runner.IsInstalled("asnmap") {
		asnResult, err := scan.Runner.Run(ctx, "asnmap", []string{
			"-ip", ip,
			"-silent",
			"-json",
		}, runner.RunOpts{Timeout: 30 * time.Second})
		if err == nil {
			var asn asnmapIPResponse
			if json.Unmarshal(asnResult.Stdout, &asn) == nil {
				if asn.ASN != "" {
					record.ASN = strings.TrimSpace(asn.ASN)
				}
				if record.Org == "" && asn.Org != "" {
					record.Org = strings.TrimSpace(asn.Org)
				}
			}
		}
	}

	return record, nil
}

type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	Org     string `json:"org"`
	ASN     struct {
		ASN  string `json:"asn"`
		Name string `json:"name"`
	} `json:"asn"`
}

type asnmapIPResponse struct {
	ASN string `json:"asn"`
	Org string `json:"org"`
}

func readPublicIPs(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer fh.Close()

	seen := make(map[string]bool)
	ips := make([]string, 0)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		ip := sanitizePublicIP(scanner.Text())
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

func sanitizePublicIP(raw string) string {
	for _, field := range strings.Fields(strings.TrimSpace(raw)) {
		parsed := net.ParseIP(strings.Trim(field, "[](),"))
		if parsed == nil || isPrivateOrLocalIP(parsed) {
			continue
		}
		return parsed.String()
	}
	return ""
}

func isPrivateOrLocalIP(ip net.IP) bool {
	privateCIDRs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func emptyFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

var _ module.Module = (*GeoInfo)(nil)
