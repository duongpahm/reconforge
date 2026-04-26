package subdomain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/duongpahm/ReconForge/internal/runner"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MockRunner ---

type mockRun struct {
	stdout []byte
	err    error
}

type MockRunner struct {
	runs    []mockRun
	callIdx int
}

func (m *MockRunner) Run(_ context.Context, _ string, _ []string, _ runner.RunOpts) (*runner.RunResult, error) {
	if m.callIdx >= len(m.runs) {
		return &runner.RunResult{ExitCode: 0}, nil
	}
	r := m.runs[m.callIdx]
	m.callIdx++
	if r.err != nil {
		return nil, r.err
	}
	return &runner.RunResult{Stdout: r.stdout, ExitCode: 0}, nil
}

func (m *MockRunner) RunPipe(_ context.Context, _ []runner.PipeCmd) (*runner.RunResult, error) {
	return m.Run(context.Background(), "", nil, runner.RunOpts{})
}

func (m *MockRunner) IsInstalled(_ string) bool { return true }

// --- Helper ---

func newTestScanCtx(t *testing.T, r runner.ToolRunner) *module.ScanContext {
	t.Helper()
	return &module.ScanContext{
		Target: "example.com",
		Config: &config.Config{
			Subdomain: config.SubdomainConfig{
				Passive:          true,
				CRT:              true,
				Brute:            true,
				Permutations:     true,
				Takeover:         true,
				ZoneTransfer:     true,
				S3Buckets:        true,
				WildcardFilter:   true,
				RecursivePassive: true,
				RegexPermut:      true,
				PtrCidrs:         true,
				GeoInfo:          true,
				SubIAPermut:      true,
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

	// Should have 22 modules
	assert.Equal(t, 22, r.Count())

	// Verify all are in subdomain phase
	subs := r.ByPhase(engine.PhaseSubdomain)
	assert.Equal(t, 22, len(subs))
}

func TestAllModulesHaveValidMetadata(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	for _, m := range r.All() {
		t.Run(m.Name(), func(t *testing.T) {
			assert.NotEmpty(t, m.Name(), "module name")
			assert.NotEmpty(t, m.Description(), "module description")
			assert.Equal(t, engine.PhaseSubdomain, m.Phase(), "all should be subdomain phase")
		})
	}
}

func TestPassiveModules_NoDependencies(t *testing.T) {
	passives := []module.Module{
		&Subfinder{},
		&CrtSh{},
		&GithubSubdomains{},
	}

	for _, m := range passives {
		t.Run(m.Name(), func(t *testing.T) {
			assert.Empty(t, m.Dependencies(), "passive modules should have no dependencies")
		})
	}
}

func TestActiveModules_HaveDependencies(t *testing.T) {
	actives := []module.Module{
		&DNSBrute{},
		&Permutation{},
		&Takeover{},
		&WildcardFilter{},
	}

	for _, m := range actives {
		t.Run(m.Name(), func(t *testing.T) {
			assert.NotEmpty(t, m.Dependencies(), "active modules should have dependencies")
		})
	}
}

func TestModuleValidation_DisabledConfig(t *testing.T) {
	cfg := &config.Config{
		Subdomain: config.SubdomainConfig{
			Passive:        false,
			CRT:            false,
			Brute:          false,
			Permutations:   false,
			Takeover:       false,
			ZoneTransfer:   false,
			S3Buckets:      false,
			WildcardFilter: false,
			RegexPermut:    false,
			PtrCidrs:       false,
			GeoInfo:        false,
			SubIAPermut:    false,
		},
	}

	tests := []struct {
		module module.Module
		name   string
	}{
		{&Subfinder{}, "subfinder"},
		{&CrtSh{}, "crt_sh"},
		{&DNSBrute{}, "dns_brute"},
		{&Permutation{}, "permutations"},
		{&Takeover{}, "takeover"},
		{&ZoneTransfer{}, "zone_transfer"},
		{&S3Buckets{}, "s3_buckets"},
		{&WildcardFilter{}, "wildcard_filter"},
		{&SubRegexPermut{}, "sub_regex_permut"},
		{&SubPTRCidrs{}, "sub_ptr_cidrs"},
		{&GeoInfo{}, "geo_info"},
		{&SubIAPermut{}, "sub_ia_permut"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.module.Validate(cfg)
			assert.Error(t, err, "should fail when disabled")
		})
	}
}

func TestModuleValidation_EnabledConfig(t *testing.T) {
	cfg := &config.Config{
		Subdomain: config.SubdomainConfig{
			Passive:          true,
			CRT:              true,
			Brute:            true,
			Permutations:     true,
			Takeover:         true,
			ZoneTransfer:     true,
			S3Buckets:        true,
			WildcardFilter:   true,
			RecursivePassive: true,
			RegexPermut:      true,
			PtrCidrs:         true,
			GeoInfo:          true,
			SubIAPermut:      true,
		},
	}

	tests := []struct {
		module module.Module
		name   string
	}{
		{&Subfinder{}, "subfinder"},
		{&CrtSh{}, "crt_sh"},
		{&DNSBrute{}, "dns_brute"},
		{&Permutation{}, "permutations"},
		{&Takeover{}, "takeover"},
		{&ZoneTransfer{}, "zone_transfer"},
		{&S3Buckets{}, "s3_buckets"},
		{&WildcardFilter{}, "wildcard_filter"},
		{&Recursive{}, "recursive"},
		{&Resolver{}, "resolver"},
		{&SubRegexPermut{}, "sub_regex_permut"},
		{&SubPTRCidrs{}, "sub_ptr_cidrs"},
		{&GeoInfo{}, "geo_info"},
		{&SubIAPermut{}, "sub_ia_permut"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.module.Validate(cfg)
			assert.NoError(t, err, "should pass when enabled")
		})
	}
}

func TestRequiredTools(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	tools := r.RequiredTools()
	assert.Contains(t, tools, "subfinder")
	assert.Contains(t, tools, "puredns")
	assert.Contains(t, tools, "dnsx")
	assert.Contains(t, tools, "dnstake")
	assert.Contains(t, tools, "gotator")
	assert.Contains(t, tools, "tlsx")
	assert.Contains(t, tools, "curl")
	assert.Contains(t, tools, "subwiz")
}

func TestGeoInfo_Run_WritesSummaryAndFindings(t *testing.T) {
	mr := &MockRunner{
		runs: []mockRun{
			{stdout: []byte(`{"ip":"8.8.8.8","country":"US","city":"Mountain View","org":"AS15169 Google LLC"}`)},
			{stdout: []byte(`{"ip":"8.8.8.8","asn":{"asn":"AS15169","name":"Google LLC"}}`)},
		},
	}
	scan := newTestScanCtx(t, mr)

	hostsDir := filepath.Join(scan.OutputDir, "hosts")
	require.NoError(t, os.MkdirAll(hostsDir, 0o755))
	require.NoError(t, writeLines(filepath.Join(hostsDir, "ips.txt"), []string{"8.8.8.8", "127.0.0.1"}))

	err := (&GeoInfo{}).Run(context.Background(), scan)
	require.NoError(t, err)

	summary, err := readLines(filepath.Join(hostsDir, "geo_info.txt"))
	require.NoError(t, err)
	assert.Len(t, summary, 1)
	assert.Contains(t, summary[0], "8.8.8.8")
	assert.Contains(t, summary[0], "AS15169")
	assert.Contains(t, summary[0], "Google LLC")

	raw, err := os.ReadFile(filepath.Join(hostsDir, "ipinfo.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"ip":"8.8.8.8"`)
	assert.NotEmpty(t, scan.Results.GetFindings())
	assert.Equal(t, 2, mr.callIdx)
}

func TestScanResults_ThreadSafety(t *testing.T) {
	sr := module.NewScanResults()

	// Concurrent writes
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			sr.AddSubdomains([]string{
				"sub1.example.com",
				"sub2.example.com",
				"sub3.example.com",
			})
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 3 unique subdomains despite 10 concurrent writes
	assert.Equal(t, 3, sr.SubdomainCount())
}

func TestScanResults_Deduplication(t *testing.T) {
	sr := module.NewScanResults()

	added1 := sr.AddSubdomains([]string{"a.example.com", "b.example.com"})
	assert.Equal(t, 2, added1)

	added2 := sr.AddSubdomains([]string{"b.example.com", "c.example.com"})
	assert.Equal(t, 1, added2) // only c is new

	assert.Equal(t, 3, sr.SubdomainCount())
}

func TestHelpers_ReadWriteLines(t *testing.T) {
	tmpFile := t.TempDir() + "/test.txt"

	lines := []string{"foo.example.com", "bar.example.com", "baz.example.com"}
	err := writeLines(tmpFile, lines)
	require.NoError(t, err)

	read, err := readLines(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, lines, read)
}

func TestHelpers_ParseLines(t *testing.T) {
	data := []byte("line1\n  line2  \n\nline3\n")
	lines := parseLines(data)
	assert.Equal(t, []string{"line1", "line2", "line3"}, lines)
}

func TestGenerateBucketNames(t *testing.T) {
	names := generateBucketNames("example.com")
	assert.Contains(t, names, "example")
	assert.Contains(t, names, "example-backup")
	assert.Contains(t, names, "example.com-dev")
	assert.True(t, len(names) > 10)
}

func TestGetParentDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "sub.example.com"},
		{"example.com", "com"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, getParentDomain(tt.input))
	}
}

// --- MockRunner-based tests ---

func TestSubfinder_Run_ToolFails_NonFatal(t *testing.T) {
	mr := &MockRunner{runs: []mockRun{{err: assert.AnError}}}
	scan := newTestScanCtx(t, mr)

	err := (&Subfinder{}).Run(context.Background(), scan)
	assert.NoError(t, err)
	assert.Equal(t, 0, scan.Results.SubdomainCount())
}

func TestSubfinder_Run_AddsSubdomains(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "subdomains")
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	mr := &MockRunner{runs: []mockRun{{stdout: []byte{}}}}
	scan := newTestScanCtx(t, mr)
	scan.OutputDir = filepath.Dir(outDir)

	outFile := filepath.Join(outDir, "subfinder.txt")
	require.NoError(t, writeLines(outFile, []string{"a.example.com", "b.example.com"}))

	err := (&Subfinder{}).Run(context.Background(), scan)
	assert.NoError(t, err)
	assert.Equal(t, 2, scan.Results.SubdomainCount())
}

func TestCrtSh_Run_ParsesMultiValue(t *testing.T) {
	scan := newTestScanCtx(t, &MockRunner{})

	outDir := filepath.Join(scan.OutputDir, "subdomains")
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	outFile := filepath.Join(outDir, "crt_sh.txt")
	require.NoError(t, writeLines(outFile, []string{"a.example.com", "b.example.com", "c.example.com"}))

	subs, err := readLines(outFile)
	require.NoError(t, err)
	assert.Len(t, subs, 3)
	assert.Contains(t, subs, "a.example.com")
	assert.Contains(t, subs, "b.example.com")
	assert.Contains(t, subs, "c.example.com")
}

func TestCrtSh_Run_WildcardFiltered(t *testing.T) {
	entries := []struct {
		raw      string
		expected string
		include  bool
	}{
		{"*.example.com", "example.com", true},
		{"sub.example.com", "sub.example.com", true},
		{"*.sub.example.com", "sub.example.com", true},
	}

	seen := make(map[string]bool)
	var filtered []string
	for _, e := range entries {
		s := strings.TrimSpace(strings.TrimPrefix(e.raw, "*."))
		if s == "" || strings.HasPrefix(s, "*") || seen[s] {
			continue
		}
		seen[s] = true
		filtered = append(filtered, s)
	}

	assert.Contains(t, filtered, "example.com")
	assert.Contains(t, filtered, "sub.example.com")
	for _, s := range filtered {
		assert.False(t, strings.HasPrefix(s, "*."), "wildcard prefix leaked: %s", s)
	}
}

func TestResolver_Run_NoSubdomains_Skips(t *testing.T) {
	mr := &MockRunner{}
	scan := newTestScanCtx(t, mr)

	err := (&Resolver{}).Run(context.Background(), scan)
	assert.NoError(t, err)
	assert.Equal(t, 0, mr.callIdx)
}

func TestResolver_Run_AddsResolvedToResults(t *testing.T) {
	scan := newTestScanCtx(t, &MockRunner{runs: []mockRun{{stdout: []byte{}}}})
	scan.Results.AddSubdomains([]string{"a.example.com", "b.example.com"})

	subsDir := filepath.Join(scan.OutputDir, "subdomains")
	require.NoError(t, os.MkdirAll(subsDir, 0o755))

	resolvedFile := filepath.Join(subsDir, "resolved.txt")
	require.NoError(t, writeLines(resolvedFile, []string{
		"a.example.com [A] 1.2.3.4",
		"b.example.com [A] 5.6.7.8",
	}))

	err := (&Resolver{}).Run(context.Background(), scan)
	assert.NoError(t, err)

	subs := scan.Results.GetSubdomains()
	assert.Contains(t, subs, "a.example.com")
	assert.Contains(t, subs, "b.example.com")
}

func TestDNSBrute_Run_WhenDisabled(t *testing.T) {
	cfg := &config.Config{Subdomain: config.SubdomainConfig{Brute: false}}
	err := (&DNSBrute{}).Validate(cfg)
	assert.Error(t, err)
}

func TestWildcardFilter_Run_EmptyInput(t *testing.T) {
	scan := newTestScanCtx(t, &MockRunner{})

	err := (&WildcardFilter{}).Run(context.Background(), scan)
	assert.NoError(t, err)
}

func TestTakeover_Run_EmptyInput(t *testing.T) {
	scan := newTestScanCtx(t, &MockRunner{})

	err := (&Takeover{}).Run(context.Background(), scan)
	assert.NoError(t, err)
}

func TestZoneTransfer_Validate_Disabled(t *testing.T) {
	cfg := &config.Config{Subdomain: config.SubdomainConfig{ZoneTransfer: false}}
	err := (&ZoneTransfer{}).Validate(cfg)
	assert.Error(t, err)
}
