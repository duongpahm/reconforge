package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
			OSINT: config.OSINTConfig{
				EmailHarvest:  true,
				GoogleDorks:   true,
				GithubLeaks:   true,
				CloudEnum:     true,
				SPFDMARC:      true,
				GithubRepos:   true,
				IPInfo:        true,
				ThirdParties:  true,
				Metadata:      true,
				MailHygiene:   true,
				GithubActions: true,
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

func TestAllOSINTModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseOSINT, m.Phase(), "module %s should be OSINT phase", m.Name())
	}
}

func TestOSINTModules_NoDependencies(t *testing.T) {
	// All OSINT modules run independently
	mods := []module.Module{
		&EmailHarvest{},
		&GoogleDorks{},
		&GithubLeaks{},
		&CloudEnum{},
		&SPFDMARCCheck{},
		&GithubRepos{},
		&IPInfo{},
		&ThirdPartyMisconfigs{},
		&Metadata{},
		&MailHygiene{},
		&GithubActionsAudit{},
	}
	for _, m := range mods {
		assert.Empty(t, m.Dependencies(), "OSINT module %s should have no dependencies", m.Name())
	}
}

func TestOSINTModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		OSINT: config.OSINTConfig{
			EmailHarvest:  false,
			GoogleDorks:   false,
			GithubLeaks:   false,
			CloudEnum:     false,
			SPFDMARC:      false,
			GithubRepos:   false,
			IPInfo:        false,
			ThirdParties:  false,
			Metadata:      false,
			MailHygiene:   false,
			GithubActions: false,
		},
	}

	tests := []module.Module{
		&EmailHarvest{},
		&GoogleDorks{},
		&GithubLeaks{},
		&CloudEnum{},
		&SPFDMARCCheck{},
		&GithubRepos{},
		&IPInfo{},
		&ThirdPartyMisconfigs{},
		&Metadata{},
		&MailHygiene{},
		&GithubActionsAudit{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		OSINT: config.OSINTConfig{
			EmailHarvest:  true,
			GoogleDorks:   true,
			GithubLeaks:   true,
			CloudEnum:     true,
			SPFDMARC:      true,
			GithubRepos:   true,
			IPInfo:        true,
			ThirdParties:  true,
			Metadata:      true,
			MailHygiene:   true,
			GithubActions: true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestParseEmails(t *testing.T) {
	output := []byte(`
info@example.com
admin@example.com
info@example.com
random line without email
test@test.org
`)
	emails := parseEmailsFromOutput(output)
	assert.Equal(t, 3, len(emails))
	assert.Contains(t, emails, "info@example.com")
	assert.Contains(t, emails, "admin@example.com")
	assert.Contains(t, emails, "test@test.org")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 3))
}

func TestEmailHarvest_Run_AddsUniqueEmails(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "theHarvester", command)
			assert.Contains(t, args, "-d")
			return &runner.RunResult{
				Stdout: []byte("info@example.com\nadmin@example.com\ninfo@example.com\n"),
			}, nil
		},
	})

	err := (&EmailHarvest{}).Run(context.Background(), scan)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"info@example.com", "admin@example.com"}, scan.Results.GetEmails())
}

func TestGoogleDorks_Run_AddsFindingsFromOutputFile(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "dorks_hunter", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("site:example.com ext:env\nsite:example.com intitle:index of\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})

	err := (&GoogleDorks{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Contains(t, findings[0].Detail, "Google dork finding:")
}

func TestGithubLeaks_Run_WritesJSONAndFindings(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "trufflehog", command)
			return &runner.RunResult{
				Stdout: []byte("verified-secret-1\nverified-secret-2\n"),
			}, nil
		},
	})

	err := (&GithubLeaks{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Equal(t, "high", findings[0].Severity)

	data, err := os.ReadFile(filepath.Join(scan.OutputDir, "osint", "github_leaks.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "verified-secret-1")
}

func TestCloudEnum_Run_AddsCloudResourceFindings(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "cloud_enum", command)
			outFile := args[3]
			require.NoError(t, os.WriteFile(outFile, []byte("s3://example-assets\nexample.blob.core.windows.net\n"), 0o644))
			return &runner.RunResult{}, nil
		},
	})

	err := (&CloudEnum{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Contains(t, findings[0].Detail, "Cloud resource:")
}

func TestSPFDMARCCheck_Run_ReportsMissingRecords(t *testing.T) {
	callCount := 0
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "dig", command)
			callCount++
			return &runner.RunResult{Stdout: []byte("\n")}, nil
		},
	})

	err := (&SPFDMARCCheck{}).Run(context.Background(), scan)
	require.NoError(t, err)

	findings := scan.Results.GetFindings()
	require.Len(t, findings, 2)
	assert.Equal(t, 2, callCount)
	assert.Contains(t, findings[0].Detail, "Missing")
}

func TestSPFDMARCCheck_Run_RecognizesPresentRecords(t *testing.T) {
	scan := newTestScanContext(t, &testRunner{
		t: t,
		runFn: func(command string, args []string) (*runner.RunResult, error) {
			assert.Equal(t, "dig", command)
			switch fmt.Sprint(args) {
			case "[TXT example.com +short]":
				return &runner.RunResult{Stdout: []byte(`"v=spf1 include:_spf.example.com ~all"` + "\n")}, nil
			case "[TXT _dmarc.example.com +short]":
				return &runner.RunResult{Stdout: []byte(`"v=DMARC1; p=reject"` + "\n")}, nil
			default:
				t.Fatalf("unexpected args: %v", args)
				return nil, nil
			}
		},
	})

	err := (&SPFDMARCCheck{}).Run(context.Background(), scan)
	require.NoError(t, err)
	assert.Empty(t, scan.Results.GetFindings())
}
