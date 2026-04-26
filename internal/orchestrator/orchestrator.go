// Package orchestrator wires all modules into the engine pipeline and provides
// the top-level Scan() entrypoint that the CLI calls.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	"github.com/reconforge/reconforge/internal/project"
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
func (o *Orchestrator) Scan(ctx context.Context, target, mode string, resume bool) error {
	restoreMemLimit := applyMemoryLimit(o.cfg.General.MemoryLimitMB, o.logger)
	defer restoreMemLimit()

	dirName := target
	if o.cfg.General.Prefix != "" {
		dirName = o.cfg.General.Prefix + "_" + target
	}
	outputDir := filepath.Join(o.cfg.General.OutputDir, dirName)
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
	var toolRunner runner.ToolRunner
	if o.cfg.General.DryRun {
		toolRunner = runner.NewDryRunner(o.logger)
		o.logger.Info().Msg("Running in DRY-RUN mode")
	} else {
		toolRunner = runner.NewLocalRunner(o.logger)
	}
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
		Runner:      toolRunner,
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

	// Find completed modules if resuming
	completedModules := make(map[string]bool)
	var activeScanID string
	if resume {
		lastScan, err := stateMgr.GetLastScan(target)
		if err == nil && lastScan != nil {
			activeScanID = lastScan.ID
			for _, m := range lastScan.Modules {
				if m.Status == engine.StatusComplete {
					completedModules[m.Name] = true
				}
			}
			o.logger.Info().Str("id", activeScanID).Int("completed", len(completedModules)).Msg("Resuming scan")
		} else {
			o.logger.Warn().Msg("No previous scan found to resume, starting fresh")
			resume = false
		}
	}

	if !resume {
		activeScanID, err = stateMgr.StartScan(target, mode)
		if err != nil {
			return fmt.Errorf("start scan state: %w", err)
		}
	}

	if err := persistCheckpoint(stateMgr, activeScanID, target, mode, outputDir, scanCtx.Results); err != nil {
		o.logger.Warn().Err(err).Msg("Failed to persist initial checkpoint")
	}

	if resume {
		var checkpoint ScanCheckpoint
		if err := stateMgr.LoadCheckpoint(activeScanID, &checkpoint); err == nil {
			o.logger.Info().
				Time("updated_at", checkpoint.UpdatedAt).
				Int("completed", checkpoint.Completed).
				Int("failed", checkpoint.Failed).
				Int("findings", checkpoint.Findings).
				Msg("Recovered scan checkpoint")
		}
	}

	for _, modName := range o.collectModuleNames(pipeline) {
		mod, ok := o.registry.Get(modName)
		if !ok {
			o.logger.Warn().Str("module", modName).Msg("Module not found in registry, skipping")
			continue
		}

		if completedModules[modName] {
			o.logger.Info().Str("module", modName).Msg("Skipping completed module (resume)")
			executor.RegisterModule(modName, func(ctx context.Context) (int, error) {
				return 0, nil
			})
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
			before := len(scanCtx.Results.GetFindings())
			if err := m.Run(ctx, scanCtx); err != nil {
				var missingTool *runner.MissingToolError
				if errors.As(err, &missingTool) && o.cfg.General.SkipMissingTools {
					o.logger.Warn().
						Str("module", modName).
						Str("tool", missingTool.Tool).
						Str("fix", fmt.Sprintf("reconforge tools install %s", missingTool.Tool)).
						Msg("Skipping module because required tool is missing")
					return 0, nil
				}
				return 0, err
			}
			after := len(scanCtx.Results.GetFindings())
			if after < before {
				o.logger.Warn().
					Str("module", modName).
					Int("before", before).
					Int("after", after).
					Msg("findings count decreased - possible bug in module")
				return 0, nil
			}
			return after - before, nil
		})
	}

	// Setup TUI only when not in debug/verbose mode AND running in a real terminal
	useTUI := o.logger.GetLevel() > zerolog.DebugLevel && ui.IsStderrTTY()
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
		executor.OnStageStart = func(stage string) {
			o.logger.Info().
				Str("event", "phase_start").
				Str("phase", stage).
				Msg("Phase starting")
		}

		executor.OnStageComplete = func(stage string, result *engine.StageResult) {
			level := o.logger.Info()
			if result.Status != engine.StatusComplete {
				level = o.logger.Warn()
			}
			level.
				Str("event", "phase_complete").
				Str("phase", stage).
				Str("status", string(result.Status)).
				Dur("duration", result.Duration).
				Msg("Phase completed")
		}

		executor.OnModuleStart = func(stage, moduleName string) {
			o.logger.Info().
				Str("event", "module_start").
				Str("stage", stage).
				Str("module", moduleName).
				Msg("Module starting")
			if err := stateMgr.UpdateModule(activeScanID, moduleName, engine.StatusRunning, 0, 0, ""); err != nil {
				o.logger.Warn().Err(err).Str("module", moduleName).Msg("Failed to persist module start state")
			}
			if err := persistCheckpoint(stateMgr, activeScanID, target, mode, outputDir, scanCtx.Results); err != nil {
				o.logger.Warn().Err(err).Str("module", moduleName).Msg("Failed to persist module checkpoint")
			}
		}

		executor.OnModuleComplete = func(stage, moduleName string, result *engine.ModuleResult) {
			status := "[+]"
			if result.Error != nil {
				status = "[-]"
			}
			level := o.logger.Info()
			if result.Error != nil {
				level = o.logger.Warn()
			}
			level.
				Str("event", "module_complete").
				Str("stage", stage).
				Str("module", moduleName).
				Str("status", status).
				Int("findings", result.Findings).
				Dur("duration", result.Duration).
				Msg("Module completed")

			errMsg := ""
			if result.Error != nil {
				errMsg = result.Error.Error()
				var missingTool *runner.MissingToolError
				if errors.As(result.Error, &missingTool) {
					o.logger.Error().
						Str("event", "tool_missing").
						Str("module", moduleName).
						Str("tool", missingTool.Tool).
						Str("fix", fmt.Sprintf("reconforge tools install %s", missingTool.Tool)).
						Msg("Module skipped because required tool is missing")
				}
			}
			if err := stateMgr.UpdateModule(activeScanID, moduleName, result.Status, result.Findings, result.Duration.Seconds(), errMsg); err != nil {
				o.logger.Warn().Err(err).Str("module", moduleName).Msg("Failed to persist module completion state")
			}
			if shouldPersistCheckpoint(stateMgr, activeScanID, o.cfg.General.CheckpointFreq, result.Status != engine.StatusComplete) {
				if err := persistCheckpoint(stateMgr, activeScanID, target, mode, outputDir, scanCtx.Results); err != nil {
					o.logger.Warn().Err(err).Str("module", moduleName).Msg("Failed to persist module checkpoint")
				}
			}
		}
	}

	// Execute
	o.logger.Info().
		Str("target", target).
		Str("mode", mode).
		Int("modules", o.registry.Count()).
		Msg("[*] Starting ReconForge scan")

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
		stateMgr.MarkFailed(activeScanID)
		if err := persistCheckpoint(stateMgr, activeScanID, target, mode, outputDir, scanCtx.Results); err != nil {
			o.logger.Warn().Err(err).Msg("Failed to persist failure checkpoint")
		}
		return fmt.Errorf("scan execution: %w", execErr)
	}

	stateMgr.MarkComplete(activeScanID)
	if err := persistCheckpoint(stateMgr, activeScanID, target, mode, outputDir, scanCtx.Results); err != nil {
		o.logger.Warn().Err(err).Msg("Failed to persist final checkpoint")
	}

	// Final summary
	results := scanCtx.Results

	// Sprint 8: Persist findings to global Project database
	if pm, err := project.NewManager(); err == nil {
		if err := pm.SaveFindings(activeScanID, target, results.GetFindings()); err != nil {
			o.logger.Warn().Err(err).Msg("Failed to persist findings to database")
		} else {
			// Auto-dedup newly saved findings
			pm.DedupFindings(target, true)
		}
		pm.Close()
	}

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
		Modules:   []string{"url_checks", "js_analysis", "param_discovery", "url_gf", "urlext", "service_fingerprint", "tls_ip_pivots", "virtual_hosts", "favirecon_tech", "nuclei_check", "cms_scanner", "web_fuzz", "graphql_scan", "iis_shortname", "jschecks", "broken_links", "wordlist_gen", "wordlist_gen_roboxtractor", "password_dict", "sub_js_extract", "wellknown_pivots", "grpc_reflection", "websocket_checks", "llm_probe"},
		Parallel:  false,
		MaxJobs:   1,
		DependsOn: []string{"web_analysis"},
	})

	p.AddStage(&engine.Stage{
		Name:      "vuln",
		Phase:     engine.PhaseVuln,
		Modules:   []string{"nuclei", "xss_scan", "sqli_scan", "ssrf_scan", "ssl_audit", "bypass_4xx", "command_injection", "crlf_check", "fuzzparams", "http_smuggling", "lfi_check", "nuclei_dast", "spraying", "ssti_check", "webcache"},
		Parallel:  true,
		MaxJobs:   4,
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
		Modules:   []string{"url_checks", "js_analysis", "param_discovery", "url_gf", "urlext", "service_fingerprint", "tls_ip_pivots", "virtual_hosts", "favirecon_tech", "nuclei_check", "cms_scanner", "web_fuzz", "graphql_scan", "iis_shortname", "jschecks", "broken_links", "wordlist_gen", "wordlist_gen_roboxtractor", "password_dict", "sub_js_extract", "wellknown_pivots", "grpc_reflection", "websocket_checks", "llm_probe"},
		Parallel:  false,
		MaxJobs:   1,
		DependsOn: []string{"web_analysis"},
	})

	p.AddStage(&engine.Stage{
		Name:      "vuln",
		Phase:     engine.PhaseVuln,
		Modules:   []string{"nuclei", "xss_scan", "sqli_scan", "ssrf_scan", "ssl_audit", "bypass_4xx", "command_injection", "crlf_check", "fuzzparams", "http_smuggling", "lfi_check", "nuclei_dast", "spraying", "ssti_check", "webcache"},
		Parallel:  true,
		MaxJobs:   4,
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
