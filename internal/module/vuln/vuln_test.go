package vuln

import (
	"context"
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
			Web: config.WebConfig{Nuclei: true},
			Vuln: config.VulnConfig{
				XSS:  true,
				SQLi: true,
				SSRF: true,
				SSL:  true,
			},
			RateLimit: config.RateLimitConfig{
				Nuclei: 123,
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
	assert.Equal(t, 15, r.Count())
}

func TestAllVulnModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseVuln, m.Phase(), "module %s should be vuln phase", m.Name())
	}
}

func TestVulnModules_NoDependencies(t *testing.T) {
	// All vuln modules run independently (they read from shared results)
	mods := []module.Module{
		&Nuclei{},
		&DalfoxXSS{},
		&SQLMapScan{},
		&SSRFScanner{},
		&SSLAudit{},
	}
	for _, m := range mods {
		assert.Empty(t, m.Dependencies(), "vuln module %s should have no dependencies", m.Name())
	}
}

func TestVulnModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		Web: config.WebConfig{Nuclei: false},
		Vuln: config.VulnConfig{
			XSS:  false,
			SQLi: false,
			SSRF: false,
			SSL:  false,
		},
	}

	tests := []module.Module{
		&Nuclei{},
		&DalfoxXSS{},
		&SQLMapScan{},
		&SSRFScanner{},
		&SSLAudit{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		Web: config.WebConfig{Nuclei: true},
		Vuln: config.VulnConfig{
			XSS:  true,
			SQLi: true,
			SSRF: true,
			SSL:  true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestRequiredTools(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	tools := r.RequiredTools()
	assert.Contains(t, tools, "nuclei")
	assert.Contains(t, tools, "dalfox")
	assert.Contains(t, tools, "sqlmap")
	assert.Contains(t, tools, "testssl.sh")
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"[critical] CVE-2023-1234", "critical"},
		{"[high] XSS found", "high"},
		{"[medium] Open redirect", "medium"},
		{"[low] Info disclosure", "low"},
		{"Some other line", "info"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, parseSeverity(tt.input))
	}
}

func TestScanResults_LiveHosts(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddLiveHosts([]string{"http://a.com", "http://b.com"})
	assert.Equal(t, 2, added)

	added = sr.AddLiveHosts([]string{"http://b.com", "http://c.com"})
	assert.Equal(t, 1, added) // only c is new

	hosts := sr.GetLiveHosts()
	assert.Equal(t, 3, len(hosts))
}

func TestScanResults_URLs(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddURLs([]string{"http://a.com/page1", "http://a.com/page2"})
	assert.Equal(t, 2, added)

	added = sr.AddURLs([]string{"http://a.com/page2", "http://a.com/page3"})
	assert.Equal(t, 1, added)

	urls := sr.GetURLs()
	assert.Equal(t, 3, len(urls))
}

func TestScanResults_Emails(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddEmails([]string{"a@test.com", "b@test.com"})
	assert.Equal(t, 2, added)

	added = sr.AddEmails([]string{"b@test.com", "c@test.com"})
	assert.Equal(t, 1, added)
}

func TestNuclei_Run_AddsSeverityFindingsAndRateLimit(t *testing.T) {
	var capturedArgs []string
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "nuclei", command)
			capturedArgs = append([]string(nil), args...)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("[critical] CVE-2026-0001\n[low] missing security.txt\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})
	scan.Results.AddLiveHosts([]string{"https://example.com"})

	err := (&Nuclei{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Contains(t, capturedArgs, "-rate-limit")
	assert.Contains(t, capturedArgs, "123")
}

func TestDalfoxXSS_Run_FiltersParameterizedURLsAndAddsFindings(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "dalfox", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("GET /search?q=test reflected\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})
	scan.Results.AddURLs([]string{
		"https://example.com/",
		"https://example.com/search?q=test",
	})

	err := (&DalfoxXSS{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Detail, "XSS:")
}

func TestSQLMapScan_Run_DetectsInjectableOutput(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "sqlmap", command)
			return &runner.RunResult{
				Stdout: []byte("parameter 'id' is vulnerable\nback-end DBMS is MySQL\n"),
			}, nil
		},
	})
	scan.Results.AddURLs([]string{"https://example.com/item?id=1"})

	err := (&SQLMapScan{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
}

func TestSSRFScanner_Run_AddsFindings(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "nuclei", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("http://example.com SSRF candidate\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})
	scan.Results.AddLiveHosts([]string{"https://example.com"})

	err := (&SSRFScanner{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 1)
	assert.Equal(t, "high", findings[0].Severity)
}

func TestSSLAudit_Run_ParsesIssuesFromStdout(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "testssl.sh", command)
			return &runner.RunResult{
				Stdout: []byte("TLS 1.0 vulnerable\nOCSP stapling not ok\n"),
			}, nil
		},
	})

	err := (&SSLAudit{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Contains(t, findings[0].Detail, "SSL issue:")
}
