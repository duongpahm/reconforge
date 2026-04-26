package web

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
)

// ServiceFingerprint fingerprints open services via nerva with nmap-XML fallback.
type ServiceFingerprint struct{}

func (m *ServiceFingerprint) Name() string            { return "service_fingerprint" }
func (m *ServiceFingerprint) Description() string     { return "Service fingerprinting via nerva/nmap" }
func (m *ServiceFingerprint) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *ServiceFingerprint) Dependencies() []string  { return []string{"port_scan"} }
func (m *ServiceFingerprint) RequiredTools() []string { return []string{"nerva"} }

func (m *ServiceFingerprint) Validate(cfg *config.Config) error {
	if !cfg.Web.ServiceFingerprint {
		return fmt.Errorf("service fingerprinting disabled")
	}
	return nil
}

func (m *ServiceFingerprint) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("create hosts dir: %w", err)
	}

	outFile := filepath.Join(hostsDir, "service_fingerprints.jsonl")
	naabuFile := filepath.Join(hostsDir, "naabu_open.txt")
	nmapXML := filepath.Join(hostsDir, "portscan_active.xml")

	usedFallback := false
	if scan.Runner.IsInstalled("nerva") {
		if _, err := os.Stat(naabuFile); err == nil {
			result, runErr := scan.Runner.Run(ctx, "nerva", []string{"--json", "-l", naabuFile, "-o", outFile}, runner.RunOpts{Timeout: 30 * time.Minute})
			if runErr != nil {
				scan.Logger.Warn().Err(runErr).Msg("nerva failed; falling back to nmap XML parsing")
				usedFallback = true
			} else if _, err := os.Stat(outFile); os.IsNotExist(err) && result != nil && len(result.Stdout) > 0 {
				_ = os.WriteFile(outFile, result.Stdout, 0o644)
			}
		} else {
			usedFallback = true
		}
	} else {
		usedFallback = true
	}

	if usedFallback {
		if _, err := os.Stat(nmapXML); os.IsNotExist(err) {
			scan.Logger.Info().Msg("No service fingerprint inputs available; skipping")
			return nil
		}
		if err := writeServiceFingerprintsFromNmap(nmapXML, outFile); err != nil {
			scan.Logger.Warn().Err(err).Msg("nmap XML fallback parsing failed")
			return nil
		}
	}

	findings, records := parseServiceFingerprintFindings(outFile)
	if len(findings) > 0 {
		scan.Results.AddFindings(findings)
	}

	scan.Logger.Info().Int("records", records).Int("high_risk_services", len(findings)).Msg("service_fingerprint complete")
	return nil
}

func writeServiceFingerprintsFromNmap(xmlPath, outPath string) error {
	raw, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}

	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return err
	}

	out := make([]string, 0)
	for _, host := range run.Hosts {
		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" && len(host.Addresses) > 0 {
			ip = host.Addresses[0].Addr
		}
		if ip == "" {
			continue
		}

		for _, p := range host.Ports {
			if strings.ToLower(p.State.State) != "open" {
				continue
			}
			rec := map[string]interface{}{
				"host":     ip,
				"port":     p.PortID,
				"protocol": p.Protocol,
				"service":  p.Service.Name,
				"product":  p.Service.Product,
				"version":  p.Service.Version,
				"source":   "nmap_fallback",
			}
			b, err := json.Marshal(rec)
			if err != nil {
				continue
			}
			out = append(out, string(b))
		}
	}

	if len(out) == 0 {
		return nil
	}
	return writeLines(outPath, out)
}

func parseServiceFingerprintFindings(path string) ([]module.Finding, int) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer fh.Close()

	highRisk := map[string]bool{
		"redis":         true,
		"mongodb":       true,
		"memcached":     true,
		"elasticsearch": true,
		"kibana":        true,
		"etcd":          true,
		"consul":        true,
	}

	findings := make([]module.Finding, 0)
	records := 0
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		records++

		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		host := extractString(obj, "host", "ip", "target")
		port := extractString(obj, "port")
		if port == "" {
			if n, ok := obj["port"].(float64); ok {
				port = strconv.Itoa(int(n))
			}
		}
		service := strings.ToLower(extractString(obj, "service", "name", "product"))
		if !highRisk[service] {
			continue
		}

		target := strings.Trim(strings.Join([]string{host, port}, ":"), ":")
		if target == "" {
			target = host
		}
		findings = append(findings, module.Finding{
			Module:   "service_fingerprint",
			Type:     "info",
			Severity: "medium",
			Target:   target,
			Detail:   fmt.Sprintf("Potentially exposed sensitive service: %s", service),
		})
	}
	return findings, records
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPort struct {
	PortID   string      `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

var _ module.Module = (*ServiceFingerprint)(nil)
