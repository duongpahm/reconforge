package web

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRunner struct {
	t     *testing.T
	runFn func(command string, args []string) (*runner.RunResult, error)
}

func (r *testRunner) Run(_ context.Context, command string, args []string, _ runner.RunOpts) (*runner.RunResult, error) {
	r.t.Helper()
	if r.runFn == nil {
		return &runner.RunResult{ExitCode: 0}, nil
	}
	return r.runFn(command, args)
}

func (r *testRunner) RunPipe(context.Context, []runner.PipeCmd) (*runner.RunResult, error) {
	r.t.Helper()
	return &runner.RunResult{ExitCode: 0}, nil
}

func (r *testRunner) IsInstalled(string) bool { return true }

func newTestScanContext(t *testing.T, r runner.ToolRunner) *module.ScanContext {
	t.Helper()
	return &module.ScanContext{
		Target: "example.com",
		Config: &config.Config{
			General: config.GeneralConfig{Deep: true},
			Web: config.WebConfig{
				Probe:              true,
				Screenshots:        true,
				Crawl:              true,
				JSAnalysis:         true,
				WAFDetect:          true,
				Nuclei:             true,
				CDNProvider:        true,
				URLExt:             true,
				ServiceFingerprint: true,
				GraphQL:            true,
				PortScan:           true,
				URLChecks:          true,
				ParamDiscovery:     true,
				BrokenLinks:        true,
				WordlistGen:        true,
				SubJSExtract:       true,
				WellKnownPivots:    true,
				GrpcReflection:     true,
				WebsocketChecks:    true,
				RobotsWordlist:     true,
				PasswordDict:       true,
				LLMProbe:           true,
				Ports: config.PortsConf{
					Standard: "80,443",
					Uncommon: "8080,8443",
				},
			},
		},
		Runner:    r,
		Logger:    zerolog.Nop(),
		OutputDir: t.TempDir(),
		Results:   module.NewScanResults(),
	}
}

func TestRegisterAll(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	assert.Equal(t, 30, r.Count())
}

func TestAllWebModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseWeb, m.Phase(), "module %s should be web phase", m.Name())
	}
}

func TestWebModules_Dependencies(t *testing.T) {
	// httpx_probe has no deps (first web module)
	assert.Empty(t, (&HTTPXProbe{}).Dependencies())

	// screenshots depends on httpx
	assert.Contains(t, (&Screenshots{}).Dependencies(), "httpx_probe")

	// crawler depends on httpx
	assert.Contains(t, (&Crawler{}).Dependencies(), "httpx_probe")

	// js_analysis depends on crawler
	assert.Contains(t, (&JSAnalyzer{}).Dependencies(), "crawler")

	// nuclei_check and graphql chain
	assert.Contains(t, (&NucleiCheck{}).Dependencies(), "httpx_probe")
	assert.Contains(t, (&GraphQLScan{}).Dependencies(), "nuclei_check")

	// service and URL extension dependencies
	assert.Contains(t, (&CDNProvider{}).Dependencies(), "httpx_probe")
	assert.Contains(t, (&URLExt{}).Dependencies(), "url_checks")
	assert.Contains(t, (&ServiceFingerprint{}).Dependencies(), "port_scan")
	assert.Contains(t, (&GrpcReflection{}).Dependencies(), "port_scan")
	assert.Contains(t, (&WebsocketChecks{}).Dependencies(), "url_checks")
	assert.Contains(t, (&PasswordDict{}).Dependencies(), "wordlist_gen")
}

func TestWebModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		Web: config.WebConfig{
			Probe:              false,
			Screenshots:        false,
			Crawl:              false,
			JSAnalysis:         false,
			WAFDetect:          false,
			Nuclei:             false,
			CDNProvider:        false,
			URLExt:             false,
			ServiceFingerprint: false,
			GraphQL:            false,
			PortScan:           false,
			URLChecks:          false,
			ParamDiscovery:     false,
			BrokenLinks:        false,
			WordlistGen:        false,
			SubJSExtract:       false,
			WellKnownPivots:    false,
			GrpcReflection:     false,
			WebsocketChecks:    false,
			RobotsWordlist:     false,
			PasswordDict:       false,
			LLMProbe:           false,
		},
	}

	tests := []module.Module{
		&HTTPXProbe{},
		&Screenshots{},
		&Crawler{},
		&JSAnalyzer{},
		&WAFDetector{},
		&NucleiCheck{},
		&CDNProvider{},
		&URLExt{},
		&ServiceFingerprint{},
		&GraphQLScan{},
		&ParamDiscovery{},
		&JSChecks{},
		&BrokenLinks{},
		&WordlistGen{},
		&SubJSExtract{},
		&WellKnownPivots{},
		&GrpcReflection{},
		&WebsocketChecks{},
		&WordlistGenRoboxtractor{},
		&PasswordDict{},
		&LLMProbe{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		Web: config.WebConfig{
			Probe:              true,
			Screenshots:        true,
			Crawl:              true,
			JSAnalysis:         true,
			WAFDetect:          true,
			Nuclei:             true,
			CDNProvider:        true,
			URLExt:             true,
			ServiceFingerprint: true,
			GraphQL:            true,
			PortScan:           true,
			URLChecks:          true,
			ParamDiscovery:     true,
			BrokenLinks:        true,
			WordlistGen:        true,
			SubJSExtract:       true,
			WellKnownPivots:    true,
			GrpcReflection:     true,
			WebsocketChecks:    true,
			RobotsWordlist:     true,
			PasswordDict:       true,
			LLMProbe:           true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestWebModules_RequiredTools(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	tools := r.RequiredTools()
	assert.Contains(t, tools, "httpx")
	assert.Contains(t, tools, "gowitness")
	assert.Contains(t, tools, "katana")
	assert.Contains(t, tools, "wafw00f")
	assert.Contains(t, tools, "arjun")
	assert.Contains(t, tools, "nuclei")
	assert.Contains(t, tools, "cdncheck")
	assert.Contains(t, tools, "nerva")
	assert.Contains(t, tools, "gqlspection")
	assert.Contains(t, tools, "grpcurl")
	assert.Contains(t, tools, "curl")
	assert.Contains(t, tools, "roboxtractor")
	assert.Contains(t, tools, "julius")
}

func TestHTTPXProbe_Run_UsesTargetFallbackAndAddsLiveHosts(t *testing.T) {
	var capturedInput []byte
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "httpx", command)
			inputFile := args[1]
			outFile := args[3]
			var err error
			capturedInput, err = os.ReadFile(inputFile)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(outFile, []byte("https://example.com\nhttps://app.example.com\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})

	err := (&HTTPXProbe{}).Run(context.Background(), scan)
	require.NoError(t, err)

	assert.Equal(t, "example.com\n", string(capturedInput))
	assert.ElementsMatch(t, []string{"https://example.com", "https://app.example.com"}, scan.Results.GetLiveHosts())
}

func TestJSAnalyzer_Run_AddsEndpointsAndSecretFindings(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "katana", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("https://cdn.example.com/api/users\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})
	scan.Results.AddURLs([]string{
		"https://cdn.example.com/app.js?token=debug",
		"https://cdn.example.com/logo.png",
	})

	err := (&JSAnalyzer{}).Run(context.Background(), scan)
	require.NoError(t, err)

	assert.Contains(t, scan.Results.GetURLs(), "https://cdn.example.com/api/users")
	findings := scan.Results.GetFindings()
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Detail, "Potential secret exposure")
}

func TestWAFDetector_Run_AddsFindingsFromOutputFile(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "wafw00f", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("Cloudflare\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})
	scan.Results.AddLiveHosts([]string{"https://example.com"})

	err := (&WAFDetector{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Detail, "WAF detected: Cloudflare")
}

func TestParamDiscovery_Run_SamplesAtMost100URLs(t *testing.T) {
	var capturedInput []byte
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "arjun", command)
			inputFile := args[1]
			var err error
			capturedInput, err = os.ReadFile(inputFile)
			require.NoError(t, err)
			return &runner.RunResult{}, nil
		},
	})

	urls := make([]string, 0, 150)
	for i := range 150 {
		urls = append(urls, fmt.Sprintf("https://example.com/path/%03d", i))
	}
	scan.Results.AddURLs(urls)

	err := (&ParamDiscovery{}).Run(context.Background(), scan)
	require.NoError(t, err)

	lines := parseLines(capturedInput)
	assert.Len(t, lines, 100)
}
