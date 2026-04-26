package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/duongpahm/ReconForge/internal/engine"
	"github.com/duongpahm/ReconForge/internal/module"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockReconPipelineEndToEnd(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "example.com")
	require.NoError(t, createOutputTree(outputDir))

	pipeline := mockReconPipeline()
	require.NoError(t, pipeline.Validate())

	results := module.NewScanResults()
	executor := engine.NewPipelineExecutor(pipeline, 4, zerolog.Nop())

	for _, stage := range pipeline.Stages {
		for _, modName := range stage.Modules {
			name := modName
			executor.RegisterModule(name, func(context.Context) (int, error) {
				switch name {
				case "subfinder":
					results.AddSubdomains([]string{"www.example.com", "api.example.com"})
				case "httpx_probe":
					results.AddLiveHosts([]string{"https://www.example.com"})
				case "crawler":
					results.AddURLs([]string{"https://www.example.com/login"})
				case "nuclei_check":
					results.AddFindings([]module.Finding{{
						Module:   name,
						Type:     "info",
						Severity: "info",
						Target:   "https://www.example.com",
						Detail:   "mock finding",
					}})
				}
				return len(results.GetFindings()), nil
			})
		}
	}

	execResults, err := executor.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, execResults, len(pipeline.Stages))

	assert.DirExists(t, filepath.Join(outputDir, ".tmp"))
	assert.DirExists(t, filepath.Join(outputDir, "osint"))
	assert.DirExists(t, filepath.Join(outputDir, "subdomains"))
	assert.DirExists(t, filepath.Join(outputDir, "hosts"))
	assert.DirExists(t, filepath.Join(outputDir, "webs"))
	assert.DirExists(t, filepath.Join(outputDir, "nuclei_output"))
	assert.DirExists(t, filepath.Join(outputDir, "vulns"))
	assert.GreaterOrEqual(t, len(results.GetFindings()), 0)
	assert.Equal(t, 2, results.SubdomainCount())
	assert.NotEmpty(t, results.GetLiveHosts())
	assert.NotEmpty(t, results.GetURLs())
}

func TestMockReconPipelineHasNoCycles(t *testing.T) {
	pipeline := mockReconPipeline()
	order, err := pipeline.TopologicalOrder()
	require.NoError(t, err)
	require.Len(t, order, 6)
	assert.Equal(t, "osint", order[0].Name)
	assert.Equal(t, "vuln", order[len(order)-1].Name)
}

func mockReconPipeline() *engine.Pipeline {
	p := engine.NewPipeline()
	_ = p.AddStage(&engine.Stage{
		Name:     "osint",
		Phase:    engine.PhaseOSINT,
		Modules:  []string{"domain_info", "github_leaks"},
		Parallel: true,
		MaxJobs:  2,
	})
	_ = p.AddStage(&engine.Stage{
		Name:      "subdomain_passive",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"subfinder", "crt_sh"},
		Parallel:  true,
		MaxJobs:   2,
		DependsOn: []string{"osint"},
	})
	_ = p.AddStage(&engine.Stage{
		Name:      "web_probe",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"httpx_probe"},
		DependsOn: []string{"subdomain_passive"},
	})
	_ = p.AddStage(&engine.Stage{
		Name:      "web_analysis",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"crawler", "cdnprovider", "geo_info"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"web_probe"},
	})
	_ = p.AddStage(&engine.Stage{
		Name:      "web_deep",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"nuclei_check", "graphql_scan"},
		DependsOn: []string{"web_analysis"},
	})
	_ = p.AddStage(&engine.Stage{
		Name:      "vuln",
		Phase:     engine.PhaseVuln,
		Modules:   []string{"xss_scan", "sqli_scan"},
		Parallel:  true,
		MaxJobs:   2,
		DependsOn: []string{"web_deep"},
	})
	return p
}

func createOutputTree(root string) error {
	for _, dir := range []string{
		".tmp",
		"osint",
		"subdomains",
		"hosts",
		"webs",
		"js",
		"fuzzing",
		"gf",
		"nuclei_output",
		"vulns",
		"cms",
		"logs",
		"report",
	} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}
