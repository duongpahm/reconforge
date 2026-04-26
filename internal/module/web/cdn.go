package web

import (
	"bufio"
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

// CDNProvider detects CDN/WAF providers and isolates origin IPs.
type CDNProvider struct{}

func (m *CDNProvider) Name() string            { return "cdnprovider" }
func (m *CDNProvider) Description() string     { return "CDN/WAF provider detection via cdncheck" }
func (m *CDNProvider) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *CDNProvider) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *CDNProvider) RequiredTools() []string { return []string{"cdncheck"} }

func (m *CDNProvider) Validate(cfg *config.Config) error {
	if !cfg.Web.CDNProvider {
		return fmt.Errorf("cdnprovider disabled")
	}
	return nil
}

func (m *CDNProvider) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	for _, d := range []string{hostsDir, tmpDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	ipsFile := filepath.Join(hostsDir, "ips.txt")
	if _, err := os.Stat(ipsFile); os.IsNotExist(err) {
		scan.Logger.Warn().Msg("No hosts/ips.txt for cdnprovider; skipping")
		return nil
	}

	result, err := scan.Runner.Run(ctx, "cdncheck", []string{"-i", ipsFile, "-silent", "-json"}, runner.RunOpts{Timeout: 20 * time.Minute})
	if err != nil {
		scan.Logger.Warn().Err(err).Msg("cdncheck failed (non-fatal)")
		return nil
	}

	var (
		providerLines []string
		originIPs     []string
		findings      []module.Finding
	)

	seenProviders := make(map[string]bool)
	seenOrigins := make(map[string]bool)
	seenFindings := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(string(result.Stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		ip, provider, isCDN := parseCDNCheckLine(line)
		if ip == "" {
			continue
		}

		if isCDN {
			entry := ip + " " + provider
			if !seenProviders[entry] {
				seenProviders[entry] = true
				providerLines = append(providerLines, entry)
			}
			fkey := ip + "|" + provider
			if !seenFindings[fkey] {
				seenFindings[fkey] = true
				findings = append(findings, module.Finding{
					Module:   "cdnprovider",
					Type:     "info",
					Severity: "info",
					Target:   ip,
					Detail:   fmt.Sprintf("CDN/WAF provider detected: %s", provider),
				})
			}
			continue
		}

		if !seenOrigins[ip] {
			seenOrigins[ip] = true
			originIPs = append(originIPs, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		scan.Logger.Warn().Err(err).Msg("Failed parsing cdncheck output")
	}

	if len(providerLines) > 0 {
		_ = writeLines(filepath.Join(hostsDir, "cdn_providers.txt"), providerLines)
	}

	if len(originIPs) == 0 {
		// Keep compatibility with port_scan fallback behavior.
		originIPs, _ = readLines(ipsFile)
	}
	if len(originIPs) > 0 {
		_ = writeLines(filepath.Join(hostsDir, "origin_ips.txt"), originIPs)
		_ = writeLines(filepath.Join(tmpDir, "ips_nocdn.txt"), originIPs)
	}

	if len(findings) > 0 {
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Int("cdn_ips", len(providerLines)).Int("origin_ips", len(originIPs)).Msg("cdnprovider complete")
	return nil
}

func parseCDNCheckLine(line string) (ip string, provider string, isCDN bool) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(line), &obj); err == nil {
		ip = extractString(obj, "ip", "input", "host", "target")
		provider = extractString(obj, "cdn", "provider", "cdn_name", "waf", "waf_name")
		provider = strings.TrimSpace(provider)
		if provider == "" {
			if cdnVal, ok := obj["cdn"]; ok {
				switch v := cdnVal.(type) {
				case bool:
					if v {
						provider = "cdn"
					}
				case string:
					provider = strings.TrimSpace(v)
				}
			}
		}
		isCDN = providerLooksValid(provider)
		if !isCDN {
			if val, ok := obj["is_cdn"].(bool); ok {
				isCDN = val
				if isCDN && provider == "" {
					provider = "cdn"
				}
			}
		}
		if provider == "" {
			provider = "unknown"
		}
		return ip, provider, isCDN
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}
	ip = fields[0]
	provider = "unknown"
	if len(fields) > 1 {
		provider = strings.Join(fields[1:], " ")
	}
	isCDN = providerLooksValid(provider)
	return ip, provider, isCDN
}

func extractString(obj map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if ok {
			if out := strings.TrimSpace(s); out != "" {
				return out
			}
		}
	}
	return ""
}

func providerLooksValid(provider string) bool {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		return false
	}
	invalid := map[string]bool{
		"none":    true,
		"no":      true,
		"false":   true,
		"unknown": true,
		"-":       true,
	}
	return !invalid[normalized]
}

var _ module.Module = (*CDNProvider)(nil)
