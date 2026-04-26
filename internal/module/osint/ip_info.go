package osint

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
)

// IPInfo gathers reverse IP, WHOIS, and geolocation data using WhoisXML API.
type IPInfo struct{}

func (m *IPInfo) Name() string            { return "ip_info" }
func (m *IPInfo) Description() string     { return "Gather IP info via WhoisXML API" }
func (m *IPInfo) Phase() engine.Phase     { return engine.PhaseOSINT }
func (m *IPInfo) Dependencies() []string  { return []string{} }
func (m *IPInfo) RequiredTools() []string { return []string{} } // Pure Go API calls

func (m *IPInfo) Validate(cfg *config.Config) error {
	if !cfg.OSINT.IPInfo {
		return fmt.Errorf("ip_info disabled")
	}
	return nil
}

func (m *IPInfo) Run(ctx context.Context, scan *module.ScanContext) error {
	// Check if target is an IP
	if net.ParseIP(scan.Target) == nil {
		scan.Logger.Info().Msg("Target is not an IP address; skipping ip_info")
		return nil
	}

	apiKey := scan.Config.OSINT.WhoisXMLAPIKey
	if apiKey == "" {
		scan.Logger.Warn().Msg("WhoisXMLAPIKey not configured; skipping ip_info")
		return nil
	}

	outDir := filepath.Join(scan.OutputDir, "osint")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	scan.Logger.Info().Msg("Gathering IP info...")

	client := &http.Client{}

	endpoints := map[string]string{
		"whois":     fmt.Sprintf("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=%s&domainName=%s&outputFormat=JSON", apiKey, scan.Target),
		"location":  fmt.Sprintf("https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=%s&ipAddress=%s", apiKey, scan.Target),
		"relations": fmt.Sprintf("https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=%s&ip=%s", apiKey, scan.Target),
	}

	for key, urlStr := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			scan.Logger.Warn().Err(err).Str("endpoint", key).Msg("Failed to create request")
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			scan.Logger.Warn().Err(err).Str("endpoint", key).Msg("API request failed")
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			scan.Logger.Warn().Err(err).Str("endpoint", key).Msg("Failed to read API response")
			continue
		}

		outFile := filepath.Join(outDir, fmt.Sprintf("ip_%s_%s.json", scan.Target, key))
		_ = os.WriteFile(outFile, body, 0o644)
	}

	scan.Logger.Info().Msg("ip_info complete")
	return nil
}
