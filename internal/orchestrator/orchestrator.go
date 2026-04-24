// Package orchestrator wires all modules into the engine pipeline and provides
// the top-level Scan() entrypoint that the CLI calls.
package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/rs/zerolog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/reconforge/reconforge/internal/cache"
	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/reconforge/reconforge/internal/module/osint"
	"github.com/reconforge/reconforge/internal/module/subdomain"
	"github.com/reconforge/reconforge/internal/module/vuln"
	"github.com/reconforge/reconforge/internal/module/web"
	"github.com/reconforge/reconforge/internal/ratelimit"
	"github.com/reconforge/reconforge/internal/runner"
	"github.com/reconforge/reconforge/internal/ui"
)

// Orchestrator sets up and executes a full reconnaissance scan.
type Orchestrator struct {
	cfg      *config.Config
	logger   zerolog.Logger
	registry *module.Registry
	results  *module.ScanResults
}

// New creates a new Orchestrator with all modules registered.
func New(cfg *config.Config, logger zerolog.Logger) *Orchestrator {
	o := &Orchestrator{
		cfg:      cfg,
		logger:   logger,
		registry: module.NewRegistry(),
	}

	// Register all modules from every phase
	osint.RegisterAll(o.registry)
	subdomain.RegisterAll(o.registry)
	web.RegisterAll(o.registry)
	vuln.RegisterAll(o.registry)

	return o
}

// Registry returns the module registry.
func (o *Orchestrator) Registry() *module.Registry {
	return o.registry
}

// Results returns the scan results (available after Scan completes).
func (o *Orchestrator) Results() *module.ScanResults {
	if o.results == nil {
		return module.NewScanResults()
	}
	return o.results
}

// Scan executes a full scan against the given target.
func (o *Orchestrator) Scan(ctx context.Context, target, mode string) error {
	outputDir := filepath.Join(o.cfg.General.OutputDir, target)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Initialize state manager
	stateDB := filepath.Join(outputDir, "state.db")
	stateMgr, err := engine.NewStateManager(stateDB)
	if err != nil {
		return fmt.Errorf("init state: %w", err)
	}
	defer stateMgr.Close()

	// Build the execution pipeline based on mode
	pipeline := o.buildPipeline(mode)

	// Create the scan engine
	eng := engine.NewEngine(o.cfg, stateMgr, o.logger)
	eng.SetPipeline(pipeline)

	// Build shared scan context for modules
	localRunner := runner.NewLocalRunner(o.logger)
	fileCache, _ := cache.NewFileCache(filepath.Join(outputDir, ".cache"))
	limiter := ratelimit.NewAdaptiveLimiter(
		ratelimit.AdaptiveConfig{
			MinRate:     float64(o.cfg.RateLimit.MinRate),
			MaxRate:     float64(o.cfg.RateLimit.MaxRate),
			InitialRate: float64(o.cfg.RateLimit.MinRate),
		},
		o.logger,
	)

	scanCtx := &module.ScanContext{
		Target:      target,
		Config:      o.cfg,
		State:       stateMgr,
		Runner:      localRunner,
		RateLimiter: limiter,
		Cache:       fileCache,
		Logger:      o.logger,
		OutputDir:   outputDir,
		Results:     module.NewScanResults(),
	}

	// Store reference so Results() works after scan
	o.results = scanCtx.Results

	// Register module functions with the executor
	executor := engine.NewPipelineExecutor(pipeline, o.cfg.General.MaxWorkers, o.logger)

	for _, modName := range o.collectModuleNames(pipeline) {
		mod, ok := o.registry.Get(modName)
		if !ok {
			o.logger.Warn().Str("module", modName).Msg("Module not found in registry, skipping")
			continue
		}

		// Validate module against config
		if err := mod.Validate(o.cfg); err != nil {
			o.logger.Debug().Str("module", modName).Err(err).Msg("Module disabled by config")
			// Register a no-op so the pipeline doesn't fail
			executor.RegisterModule(modName, func(ctx context.Context) (int, error) {
				return 0, nil
			})
			continue
		}

		// Capture the module for the closure
		m := mod
		executor.RegisterModule(modName, func(ctx context.Context) (int, error) {
			if err := m.Run(ctx, scanCtx); err != nil {
				return 0, err
			}
			// Return finding count for this module
			return len(scanCtx.Results.GetFindings()), nil
		})
	}

	// Setup TUI only when not in debug/verbose mode AND running in a real terminal
	useTUI := o.logger.GetLevel() > zerolog.DebugLevel && term.IsTerminal(int(os.Stderr.Fd()))
	var program *tea.Program
	var adapter *ui.DashboardAdapter

	if useTUI {
		// Silence zerolog output to console to avoid corrupting the TUI
		o.logger = zerolog.Nop()

		dash := ui.NewDashboard(target, mode, "scan-"+time.Now().Format("150405"))
		adapter = ui.NewDashboardAdapter(&dash, nil, scanCtx.Results)
		adapter.RegisterStages(pipeline)

		program = tea.NewProgram(dash)
		adapter = ui.NewDashboardAdapter(&dash, program, scanCtx.Results) // Re-create to inject program

		executor.OnStageStart = adapter.OnStageStart
		executor.OnStageComplete = adapter.OnStageComplete
		executor.OnModuleStart = adapter.OnModuleStart
		executor.OnModuleComplete = adapter.OnModuleComplete
	} else {
		// Wire standard callbacks
		executor.OnModuleStart = func(stage, moduleName string) {
			o.logger.Info().
				Str("stage", stage).
				Str("module", moduleName).
				Msg("Module starting")
		}

		executor.OnModuleComplete = func(stage, moduleName string, result *engine.ModuleResult) {
			status := "✅"
			if result.Error != nil {
				status = "❌"
			}
			o.logger.Info().
				Str("stage", stage).
				Str("module", moduleName).
				Str("status", status).
				Int("findings", result.Findings).
				Dur("duration", result.Duration).
				Msg("Module completed")
		}
	}

	// Execute
	o.logger.Info().
		Str("target", target).
		Str("mode", mode).
		Int("modules", o.registry.Count()).
		Msg("🚀 Starting ReconForge scan")

	var execErr error
	if useTUI {
		errCh := make(chan error, 1)
		go func() {
			_, err := executor.Execute(ctx)
			errCh <- err
			program.Send(tea.Quit())
		}()
		if _, err := program.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		// Wait for executor to finish or just grab its error if it's done
		select {
		case execErr = <-errCh:
		default:
			// If we get here, TUI quit (e.g. user pressed q), but executor might still be running.
			// We return nil and let the context cancellation clean it up.
		}
	} else {
		_, execErr = executor.Execute(ctx)
	}

	if execErr != nil {
		return fmt.Errorf("scan execution: %w", execErr)
	}

	// Final summary
	results := scanCtx.Results
	o.logger.Info().
		Str("target", target).
		Int("subdomains", results.SubdomainCount()).
		Int("live_hosts", len(results.GetLiveHosts())).
		Int("urls", len(results.GetURLs())).
		Int("findings", len(results.GetFindings())).
		Msg("🏁 Scan completed")

	return nil
}

// buildPipeline creates the execution pipeline based on scan mode.
func (o *Orchestrator) buildPipeline(mode string) *engine.Pipeline {
	switch mode {
	case "passive":
		return o.passivePipeline()
	case "osint":
		return o.osintOnlyPipeline()
	case "web":
		return o.webOnlyPipeline()
	default:
		return o.fullPipeline()
	}
}

// fullPipeline returns the complete OSINT → Subdomain → Web → Vuln pipeline.
func (o *Orchestrator) fullPipeline() *engine.Pipeline {
	p := engine.NewPipeline()

	p.AddStage(&engine.Stage{
		Name:     "osint",
		Phase:    engine.PhaseOSINT,
		Modules:  []string{"domain_info", "ip_info", "email_harvest", "google_dorks", "github_dorks", "github_repos", "github_leaks", "github_actions_audit", "metadata", "api_leaks", "third_parties", "mail_hygiene", "spoof_check", "cloud_enum", "spf_dmarc"},
		Parallel: true,
		MaxJobs:  4,
	})

	p.AddStage(&engine.Stage{
		Name:      "subdomain_passive",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"subfinder", "crt_sh", "github_subs"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"osint"},
	})

	p.AddStage(&engine.Stage{
		Name:      "subdomain_active",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"dns_brute", "permutations", "sub_ia_permut", "zone_transfer", "tls_grab", "s3_buckets"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"subdomain_passive"},
	})

	p.AddStage(&engine.Stage{
		Name:      "subdomain_resolve",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"dns_resolve", "recursive_enum"},
		Parallel:  true,
		MaxJobs:   2,
		DependsOn: []string{"subdomain_active"},
	})

	p.AddStage(&engine.Stage{
		Name:      "subdomain_post",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"wildcard_filter", "takeover", "asn_enum", "sub_noerror", "srv_enum", "source_scraping", "sub_analytics", "ns_delegation", "sub_regex_permut", "sub_ptr_cidrs", "geo_info"},
		Parallel:  true,
		MaxJobs:   2,
		DependsOn: []string{"subdomain_resolve"},
	})

	p.AddStage(&engine.Stage{
		Name:      "web_probe",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"httpx_probe"},
		Parallel:  false,
		DependsOn: []string{"subdomain_post"},
	})

	p.AddStage(&engine.Stage{
		Name:      "web_analysis",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"screenshots", "crawler", "waf_detect", "port_scan", "cdnprovider"},
		Parallel:  true,
		MaxJobs:   4,
		DependsOn: []string{"web_probe"},
	})

	p.AddStage(&engine.Stage{
		Name:      "web_deep",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"url_checks", "js_analysis", "param_discovery", "url_gf", "urlext", "service_fingerprint", "tls_ip_pivots", "virtual_hosts", "favirecon_tech", "nuclei_check", "graphql_scan", "iis_shortname", "jschecks", "broken_links", "wordlist_gen", "wordlist_gen_roboxtractor", "password_dict", "sub_js_extract", "wellknown_pivots", "grpc_reflection", "websocket_checks", "llm_probe"},
		Parallel:  false,
		MaxJobs:   1,
		DependsOn: []string{"web_analysis"},
	})

	p.AddStage(&engine.Stage{
		Name:      "vuln",
		Phase:     engine.PhaseVuln,
		Modules:   []string{"nuclei", "xss_scan", "sqli_scan", "ssrf_scan", "ssl_audit"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"web_deep"},
	})

	return p
}

// passivePipeline returns a passive-only pipeline (no active scanning).
func (o *Orchestrator) passivePipeline() *engine.Pipeline {
	p := engine.NewPipeline()

	p.AddStage(&engine.Stage{
		Name:     "osint",
		Phase:    engine.PhaseOSINT,
		Modules:  []string{"domain_info", "email_harvest", "google_dorks", "github_dorks", "github_repos", "github_leaks", "github_actions_audit", "metadata", "api_leaks", "third_parties", "mail_hygiene", "spoof_check", "cloud_enum", "spf_dmarc"},
		Parallel: true,
		MaxJobs:  4,
	})

	p.AddStage(&engine.Stage{
		Name:      "subdomain_passive",
		Phase:     engine.PhaseSubdomain,
		Modules:   []string{"subfinder", "crt_sh", "github_subs"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"osint"},
	})

	return p
}

// osintOnlyPipeline returns an OSINT-only pipeline.
func (o *Orchestrator) osintOnlyPipeline() *engine.Pipeline {
	p := engine.NewPipeline()

	p.AddStage(&engine.Stage{
		Name:     "osint",
		Phase:    engine.PhaseOSINT,
		Modules:  []string{"domain_info", "ip_info", "email_harvest", "google_dorks", "github_dorks", "github_repos", "github_leaks", "github_actions_audit", "metadata", "api_leaks", "third_parties", "mail_hygiene", "spoof_check", "cloud_enum", "spf_dmarc"},
		Parallel: true,
		MaxJobs:  4,
	})

	return p
}

// webOnlyPipeline returns a web-focused pipeline (assumes subdomains already exist).
func (o *Orchestrator) webOnlyPipeline() *engine.Pipeline {
	p := engine.NewPipeline()

	p.AddStage(&engine.Stage{
		Name:     "web_probe",
		Phase:    engine.PhaseWeb,
		Modules:  []string{"httpx_probe"},
		Parallel: false,
	})

	p.AddStage(&engine.Stage{
		Name:      "web_analysis",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"screenshots", "crawler", "waf_detect", "port_scan", "cdnprovider"},
		Parallel:  true,
		MaxJobs:   4,
		DependsOn: []string{"web_probe"},
	})

	p.AddStage(&engine.Stage{
		Name:      "web_deep",
		Phase:     engine.PhaseWeb,
		Modules:   []string{"url_checks", "js_analysis", "param_discovery", "url_gf", "urlext", "service_fingerprint", "tls_ip_pivots", "virtual_hosts", "favirecon_tech", "nuclei_check", "graphql_scan", "iis_shortname", "jschecks", "broken_links", "wordlist_gen", "wordlist_gen_roboxtractor", "password_dict", "sub_js_extract", "wellknown_pivots", "grpc_reflection", "websocket_checks", "llm_probe"},
		Parallel:  false,
		MaxJobs:   1,
		DependsOn: []string{"web_analysis"},
	})

	p.AddStage(&engine.Stage{
		Name:      "vuln",
		Phase:     engine.PhaseVuln,
		Modules:   []string{"nuclei", "xss_scan", "sqli_scan", "ssrf_scan", "ssl_audit"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"web_deep"},
	})

	return p
}

// collectModuleNames extracts all unique module names from a pipeline.
func (o *Orchestrator) collectModuleNames(p *engine.Pipeline) []string {
	seen := make(map[string]bool)
	var names []string
	for _, stage := range p.Stages {
		for _, m := range stage.Modules {
			if !seen[m] {
				seen[m] = true
				names = append(names, m)
			}
		}
	}
	return names
}
