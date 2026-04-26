package orchestrator

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testModule struct {
	name  string
	runFn func(context.Context, *module.ScanContext) error
}

func (m *testModule) Name() string                    { return m.name }
func (m *testModule) Description() string             { return "test module" }
func (m *testModule) Phase() engine.Phase             { return engine.PhaseOSINT }
func (m *testModule) Dependencies() []string          { return nil }
func (m *testModule) RequiredTools() []string         { return []string{"missing-tool"} }
func (m *testModule) Validate(_ *config.Config) error { return nil }
func (m *testModule) Run(ctx context.Context, scan *module.ScanContext) error {
	if m.runFn != nil {
		return m.runFn(ctx, scan)
	}
	return nil
}

func defaultConfig() *config.Config {
	return &config.Config{
		General: config.GeneralConfig{
			ToolsDir:       "/tmp/tools",
			OutputDir:      "/tmp/output",
			MaxWorkers:     4,
			Parallel:       true,
			CheckpointFreq: 1,
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
			ToolsDir:       "/tmp/tools",
			OutputDir:      outputDir,
			MaxWorkers:     2,
			Parallel:       true,
			CheckpointFreq: 1,
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
	err := orch.Scan(context.Background(), "example.com", "osint", false)
	require.NoError(t, err)

	results := orch.Results()
	assert.NotNil(t, results)
}

func TestScan_PassiveMode_AllDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	err := orch.Scan(context.Background(), "example.com", "passive", false)
	require.NoError(t, err)
}

func TestScan_WebMode_AllDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	err := orch.Scan(context.Background(), "example.com", "web", false)
	require.NoError(t, err)
}

func TestScan_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should handle cancelled context without panic
	_ = orch.Scan(ctx, "example.com", "osint", false)
}

func TestResults_AfterScan(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	require.NoError(t, orch.Scan(context.Background(), "example.com", "osint", false))

	results := orch.Results()
	assert.NotNil(t, results)
	assert.GreaterOrEqual(t, results.SubdomainCount(), 0)
}

func TestFullPipelineModulesAreRegistered(t *testing.T) {
	orch := New(defaultConfig(), zerolog.Nop())
	pipeline := orch.fullPipeline()

	for _, stage := range pipeline.Stages {
		for _, modName := range stage.Modules {
			_, ok := orch.Registry().Get(modName)
			assert.Truef(t, ok, "module %q from stage %q must be registered", modName, stage.Name)
		}
	}
}

func TestScan_SkipMissingTools(t *testing.T) {
	for _, tt := range []struct {
		name        string
		skipMissing bool
		wantErr     bool
	}{
		{name: "disabled", skipMissing: false, wantErr: true},
		{name: "enabled", skipMissing: true, wantErr: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := minimalConfig(dir)
			cfg.General.SkipMissingTools = tt.skipMissing

			orch := New(cfg, zerolog.Nop())
			orch.registry = module.NewRegistry()
			for _, name := range []string{
				"domain_info",
				"ip_info",
				"email_harvest",
				"github_dorks",
				"github_repos",
				"github_leaks",
				"github_actions_audit",
				"metadata",
				"api_leaks",
				"third_parties",
				"mail_hygiene",
				"spoof_check",
				"cloud_enum",
				"spf_dmarc",
			} {
				require.NoError(t, orch.registry.Register(&testModule{name: name}))
			}
			require.NoError(t, orch.registry.Register(&testModule{
				name: "google_dorks",
				runFn: func(context.Context, *module.ScanContext) error {
					return &runner.MissingToolError{Tool: "missing-tool"}
				},
			}))

			err := orch.Scan(context.Background(), "example.com", "osint", false)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), `stage "osint" failed`)
			} else {
				require.NoError(t, err)
				assert.Empty(t, orch.Results().GetFindings())
			}
		})
	}
}

func TestScan_PersistsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	orch := New(cfg, zerolog.Nop())
	require.NoError(t, orch.Scan(context.Background(), "example.com", "osint", false))

	dbPath := filepath.Join(dir, "example.com", "state.db")
	sm, err := engine.NewStateManager(dbPath)
	require.NoError(t, err)
	defer sm.Close()

	lastScan, err := sm.GetLastScan("example.com")
	require.NoError(t, err)
	require.NotNil(t, lastScan)

	var checkpoint ScanCheckpoint
	require.NoError(t, sm.LoadCheckpoint(lastScan.ID, &checkpoint))
	assert.Equal(t, lastScan.ID, checkpoint.ScanID)
	assert.Equal(t, "example.com", checkpoint.Target)
	assert.Equal(t, "osint", checkpoint.Mode)
	assert.GreaterOrEqual(t, checkpoint.Completed, 0)
}

func TestApplyMemoryLimitNoop(t *testing.T) {
	restore := applyMemoryLimit(0, zerolog.Nop())
	require.NotNil(t, restore)
	restore()
}

func TestScan_WarnsWhenFindingsCountDecreases(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalConfig(dir)

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	orch := New(cfg, logger)
	orch.registry = module.NewRegistry()

	for _, name := range []string{"httpx_probe", "screenshots", "crawler", "waf_detect", "port_scan", "cdnprovider"} {
		require.NoError(t, orch.registry.Register(&testModule{name: name}))
	}

	require.NoError(t, orch.registry.Register(&testModule{
		name: "url_checks",
		runFn: func(_ context.Context, scan *module.ScanContext) error {
			scan.Results.AddFindings([]module.Finding{{Module: "url_checks", Type: "info", Severity: "low", Target: scan.Target, Detail: "seed"}})
			return nil
		},
	}))
	require.NoError(t, orch.registry.Register(&testModule{
		name: "js_analysis",
		runFn: func(_ context.Context, scan *module.ScanContext) error {
			scan.Results.Findings = nil
			return nil
		},
	}))

	for _, name := range []string{
		"param_discovery", "url_gf", "urlext", "service_fingerprint", "tls_ip_pivots",
		"virtual_hosts", "favirecon_tech", "nuclei_check", "cms_scanner", "web_fuzz",
		"graphql_scan", "iis_shortname", "jschecks", "broken_links", "wordlist_gen",
		"wordlist_gen_roboxtractor", "password_dict", "sub_js_extract", "wellknown_pivots",
		"grpc_reflection", "websocket_checks", "llm_probe", "nuclei", "xss_scan",
		"sqli_scan", "ssrf_scan", "ssl_audit", "bypass_4xx", "command_injection",
		"crlf_check", "fuzzparams", "http_smuggling", "lfi_check", "nuclei_dast",
		"spraying", "ssti_check", "webcache",
	} {
		require.NoError(t, orch.registry.Register(&testModule{name: name}))
	}

	require.NoError(t, orch.Scan(context.Background(), "example.com", "web", false))
	assert.Contains(t, logBuf.String(), "findings count decreased - possible bug in module")
	assert.Contains(t, logBuf.String(), "\"module\":\"js_analysis\"")
}
