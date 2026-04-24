package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

// WebsocketChecks discovers WebSocket endpoints and tests handshake/origin behavior.
type WebsocketChecks struct{}

func (m *WebsocketChecks) Name() string            { return "websocket_checks" }
func (m *WebsocketChecks) Description() string     { return "Discover and test WebSocket endpoints" }
func (m *WebsocketChecks) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *WebsocketChecks) Dependencies() []string  { return []string{"url_checks"} }
func (m *WebsocketChecks) RequiredTools() []string { return []string{"curl"} }

func (m *WebsocketChecks) Validate(cfg *config.Config) error {
	if !cfg.Web.WebsocketChecks {
		return fmt.Errorf("websocket_checks disabled")
	}
	return nil
}

func (m *WebsocketChecks) Run(ctx context.Context, scan *module.ScanContext) error {
	vulnDir := filepath.Join(scan.OutputDir, "vulns")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(vulnDir, 0o755); err != nil {
		return fmt.Errorf("create vulns dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	endpoints := discoverWebsocketEndpoints(
		filepath.Join(scan.OutputDir, "js", "js_endpoints.txt"),
		filepath.Join(scan.OutputDir, "webs", "url_extract.txt"),
	)
	if len(endpoints) == 0 {
		scan.Logger.Info().Msg("No WebSocket endpoints discovered; skipping")
		return nil
	}

	handshakes := make([]string, 0)
	misconfigs := make([]string, 0)
	for _, wsURL := range endpoints {
		code := websocketHandshakeCode(ctx, scan, wsURL, "")
		if code != "101" {
			continue
		}
		handshakes = append(handshakes, "HANDSHAKE "+wsURL)
		scan.Results.AddFindings([]module.Finding{{Module: m.Name(), Type: "info", Severity: "info", Target: wsURL, Detail: "WebSocket handshake accepted"}})

		originCode := websocketHandshakeCode(ctx, scan, wsURL, "https://evil.example")
		if originCode == "101" {
			misconfigs = append(misconfigs, "ORIGIN-ALLOWED "+wsURL)
			scan.Results.AddFindings([]module.Finding{{Module: m.Name(), Type: "vuln", Severity: "medium", Target: wsURL, Detail: "WebSocket accepted cross-origin handshake"}})
		}
	}
	if len(handshakes) > 0 {
		_ = writeLines(filepath.Join(vulnDir, "websockets.txt"), handshakes)
	}
	if len(misconfigs) > 0 {
		_ = writeLines(filepath.Join(vulnDir, "websocket_misconfig.txt"), misconfigs)
	}
	scan.Logger.Info().Int("endpoints", len(endpoints)).Int("misconfigs", len(misconfigs)).Msg("websocket_checks complete")
	return nil
}

func discoverWebsocketEndpoints(paths ...string) []string {
	re := regexp.MustCompile(`wss?://[^\s"'\]\[<>]+`)
	seen := make(map[string]bool)
	var out []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, match := range re.FindAllString(string(raw), -1) {
			match = strings.Trim(match, `"' ,;()`)
			if match != "" && !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	return out
}

func websocketHandshakeCode(ctx context.Context, scan *module.ScanContext, wsURL, origin string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(wsURL, "wss://"), "ws://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	args := []string{
		"-sk", "--http1.1", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Connection: Upgrade",
		"-H", "Upgrade: websocket",
		"-H", "Host: " + host,
		"-H", "Sec-WebSocket-Key: " + randomWSKey(),
		"-H", "Sec-WebSocket-Version: 13",
	}
	if origin != "" {
		args = append(args, "-H", "Origin: "+origin)
	}
	args = append(args, wsURL)
	result, err := scan.Runner.Run(ctx, "curl", args, runner.RunOpts{Timeout: 20 * time.Second})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(result.Stdout))
}

func randomWSKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "dGVzdGtleQ=="
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

var _ module.Module = (*WebsocketChecks)(nil)
