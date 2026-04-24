package orchestrator

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultConfig() *config.Config {
	return &config.Config{
		General: config.GeneralConfig{
			ToolsDir:   "/tmp/tools",
			OutputDir:  "/tmp/output",
			MaxWorkers: 4,
			Parallel:   true,
		},
		OSINT: config.OSINTConfig{
			Enabled:      true,
			EmailHarvest: true,
			GoogleDorks:  true,
			GithubLeaks:  true,
			CloudEnum:    true,
			SPFDMARC:     true,
		},
		Subdomain: config.SubdomainConfig{
			Enabled:        true,
			Passive:        true,
			CRT:            true,
			Brute:          true,
			Permutations:   true,
			Takeover:       true,
			ZoneTransfer:   true,
			S3Buckets:      true,
			WildcardFilter: true,
		},
		Web: config.WebConfig{
			Enabled:        true,
			Probe:          true,
			Screenshots:    true,
			Crawl:          true,
			JSAnalysis:     true,
			WAFDetect:      true,
			ParamDiscovery: true,
			Nuclei:         true,
		},
		Vuln: config.VulnConfig{
			Enabled: true,
			XSS:     true,
			SQLi:    true,
			SSRF:    true,
			SSL:     true,
		},
		RateLimit: config.RateLimitConfig{
			MinRate: 10,
			MaxRate: 500,
		},
		Cache: config.CacheConfig{
			MaxAgeDays: 30,
		},
	}
}

func TestNew_RegistersAllModules(t *testing.T) {
	logger := zerolog.Nop()
	cfg := defaultConfig()

	orch := New(cfg, logger)
	assert.Equal(t, 82, orch.Registry().Count(), "should register all modules")
}

func TestResults_BeforeScan(t *testing.T) {
	logger := zerolog.Nop()
	cfg := defaultConfig()

	orch := New(cfg, logger)
	results := orch.Results()
	assert.NotNil(t, results, "Results() should return empty results before scan")
	assert.Equal(t, 0, results.SubdomainCount())
}

func TestBuildPipeline_Modes(t *testing.T) {
	logger := zerolog.Nop()
	cfg := defaultConfig()
	orch := New(cfg, logger)

	tests := []struct {
		mode      string
		minStages int
		maxStages int
	}{
		{"recon", 9, 9},   // full pipeline: 9 stages
		{"passive", 2, 2}, // osint + passive subdomain
		{"osint", 1, 1},   // osint only
		{"web", 4, 4},     // web_probe + web_analysis + web_deep + vuln
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			p := orch.buildPipeline(tt.mode)
			require.NotNil(t, p)
			assert.GreaterOrEqual(t, len(p.Stages), tt.minStages)
			assert.LessOrEqual(t, len(p.Stages), tt.maxStages)

			// Validate pipeline has no cycles
			err := p.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestWebDataflow_Ordering(t *testing.T) {
	logger := zerolog.Nop()
	cfg := defaultConfig()
	orch := New(cfg, logger)

	p := orch.buildPipeline("recon")
	require.NoError(t, p.Validate())

	order, err := p.TopologicalOrder()
	require.NoError(t, err)

	// Map module name to its global execution index
	// For parallel stages, all modules get the same base index.
	// For sequential stages, modules get incrementing indices.
	moduleIndex := make(map[string]int)
	currentIndex := 0

	for _, stage := range order {
		if stage.Parallel {
			for _, mod := range stage.Modules {
				moduleIndex[mod] = currentIndex
			}
			currentIndex += 100 // ensure stage boundary
		} else {
			for _, mod := range stage.Modules {
				moduleIndex[mod] = currentIndex
				currentIndex++
			}
			currentIndex += 100 // ensure stage boundary
		}
	}

	// Validate dataflow: port_scan -> url_checks -> url_gf/urlext/service_fingerprint/nuclei_check
	require.Contains(t, moduleIndex, "port_scan")
	require.Contains(t, moduleIndex, "url_checks")
	require.Contains(t, moduleIndex, "url_gf")
	require.Contains(t, moduleIndex, "urlext")
	require.Contains(t, moduleIndex, "service_fingerprint")
	require.Contains(t, moduleIndex, "nuclei_check")

	// Ensure port_scan finishes before dependent web_deep tasks
	assert.Less(t, moduleIndex["port_scan"], moduleIndex["url_checks"], "port_scan must run before url_checks")
	assert.Less(t, moduleIndex["port_scan"], moduleIndex["service_fingerprint"], "port_scan must run before service_fingerprint")

	// Ensure url_checks finishes before tasks that need URLs
	assert.Less(t, moduleIndex["url_checks"], moduleIndex["url_gf"], "url_checks must run before url_gf")
	assert.Less(t, moduleIndex["url_checks"], moduleIndex["urlext"], "url_checks must run before urlext")
	assert.Less(t, moduleIndex["url_checks"], moduleIndex["nuclei_check"], "url_checks must run before nuclei_check")
}

func TestCollectModuleNames(t *testing.T) {
	logger := zerolog.Nop()
	cfg := defaultConfig()
	orch := New(cfg, logger)

	p := orch.fullPipeline()
	names := orch.collectModuleNames(p)

	assert.GreaterOrEqual(t, len(names), 37, "full pipeline should reference at least 37 modules")

	// Check no duplicates
	seen := make(map[string]bool)
	for _, n := range names {
		assert.False(t, seen[n], "duplicate module: %s", n)
		seen[n] = true
	}
}

// minimalConfig returns a config with all modules disabled to avoid real tool execution.
// Use when testing Scan() to prevent network calls or tool invocations.
func minimalConfig(outputDir string) *config.Config {
	return &config.Config{
		General: config.GeneralConfig{
			ToolsDir:   "/tmp/tools",
			OutputDir:  outputDir,
			MaxWorkers: 2,
			Parallel:   true,
		},
		OSINT: config.OSINTConfig{
			Enabled:      false,
			EmailHarvest: false,
			GoogleDorks:  false,
			GithubLeaks:  false,
			CloudEnum:    false,
			SPFDMARC:     false,
		},
		Subdomain: config.SubdomainConfig{
			Enabled:  false,
			Passive:  false,
			CRT:      false,
			Brute:    false,
			Takeover: false,
		},
		Web:       config.WebConfig{Enabled: false},
		Vuln:      config.VulnConfig{Enabled: false},
		RateLimit: config.RateLimitConfig{MinRate: 10, MaxRate: 500},
		Cache:     config.CacheConfig{MaxAgeDays: 30},
	}
}

func TestScan_OSINTMode_AllDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	err := orch.Scan(context.Background(), "example.com", "osint")
	require.NoError(t, err)

	results := orch.Results()
	assert.NotNil(t, results)
}

func TestScan_PassiveMode_AllDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	err := orch.Scan(context.Background(), "example.com", "passive")
	require.NoError(t, err)
}

func TestScan_WebMode_AllDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	err := orch.Scan(context.Background(), "example.com", "web")
	require.NoError(t, err)
}

func TestScan_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should handle cancelled context without panic
	_ = orch.Scan(ctx, "example.com", "osint")
}

func TestResults_AfterScan(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	require.NoError(t, orch.Scan(context.Background(), "example.com", "osint"))

	results := orch.Results()
	assert.NotNil(t, results)
	assert.GreaterOrEqual(t, results.SubdomainCount(), 0)
}
