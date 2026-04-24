package web

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

// GrpcReflection probes common gRPC ports for reflection services.
type GrpcReflection struct{}

func (m *GrpcReflection) Name() string            { return "grpc_reflection" }
func (m *GrpcReflection) Description() string     { return "Probe common gRPC ports for server reflection" }
func (m *GrpcReflection) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *GrpcReflection) Dependencies() []string  { return []string{"port_scan"} }
func (m *GrpcReflection) RequiredTools() []string { return []string{"grpcurl"} }

func (m *GrpcReflection) Validate(cfg *config.Config) error {
	if !cfg.Web.GrpcReflection {
		return fmt.Errorf("grpc_reflection disabled")
	}
	return nil
}

func (m *GrpcReflection) Run(ctx context.Context, scan *module.ScanContext) error {
	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	tmpDir := filepath.Join(scan.OutputDir, ".tmp")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("create hosts dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	ips := uniqueLinesFromFiles(filepath.Join(hostsDir, "ips.txt"), filepath.Join(hostsDir, "ips_v6.txt"))
	if len(ips) == 0 {
		scan.Logger.Info().Msg("No IP input for grpc_reflection; skipping")
		return nil
	}

	outFile := filepath.Join(hostsDir, "grpc_reflection.txt")
	lines := make([]string, 0)
	for _, ip := range ips {
		for _, port := range []string{"50051", "50052"} {
			target := ip + ":" + port
			result, err := scan.Runner.Run(ctx, "grpcurl", []string{"-plaintext", "-max-msg-sz", "10485760", "-d", "{}", target, "list"}, runner.RunOpts{Timeout: 30 * time.Second})
			if err != nil || len(strings.TrimSpace(string(result.Stdout))) == 0 {
				continue
			}
			for _, line := range strings.Split(strings.TrimSpace(string(result.Stdout)), "\n") {
				entry := fmt.Sprintf("[%s] %s", target, strings.TrimSpace(line))
				lines = append(lines, entry)
				scan.Results.AddFindings([]module.Finding{{Module: m.Name(), Type: "info", Severity: "medium", Target: target, Detail: "gRPC reflection exposed: " + strings.TrimSpace(line)}})
			}
		}
	}
	if len(lines) > 0 {
		if err := writeLines(outFile, lines); err != nil {
			return fmt.Errorf("write grpc reflection output: %w", err)
		}
	}
	scan.Logger.Info().Int("services", len(lines)).Msg("grpc_reflection complete")
	return nil
}

func uniqueLinesFromFiles(paths ...string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, path := range paths {
		lines, err := readLines(path)
		if err != nil {
			continue
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
	}
	return out
}

var _ module.Module = (*GrpcReflection)(nil)
