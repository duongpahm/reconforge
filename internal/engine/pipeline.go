// Package engine provides DAG-based pipeline execution and scan orchestration.
package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Phase represents the execution phase of a module.
type Phase int

const (
	PhaseOSINT     Phase = iota
	PhaseSubdomain
	PhaseWeb
	PhaseVuln
)

func (p Phase) String() string {
	switch p {
	case PhaseOSINT:
		return "osint"
	case PhaseSubdomain:
		return "subdomain"
	case PhaseWeb:
		return "web"
	case PhaseVuln:
		return "vuln"
	default:
		return "unknown"
	}
}

// ParsePhase converts a string to a Phase.
func ParsePhase(s string) (Phase, error) {
	switch s {
	case "osint":
		return PhaseOSINT, nil
	case "subdomain":
		return PhaseSubdomain, nil
	case "web":
		return PhaseWeb, nil
	case "vuln":
		return PhaseVuln, nil
	default:
		return 0, fmt.Errorf("unknown phase: %q", s)
	}
}

// Stage represents a group of modules that execute together in the pipeline.
type Stage struct {
	Name      string
	Phase     Phase
	Modules   []string // module names to execute
	Parallel  bool     // run modules concurrently within stage
	MaxJobs   int      // max concurrent within stage (0 = unlimited)
	DependsOn []string // stages that must complete first
}

// Pipeline represents a DAG of stages to execute.
type Pipeline struct {
	Stages   []*Stage
	stageMap map[string]*Stage
}

// NewPipeline creates a new empty pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		stageMap: make(map[string]*Stage),
	}
}

// AddStage adds a stage to the pipeline.
func (p *Pipeline) AddStage(s *Stage) error {
	if s.Name == "" {
		return fmt.Errorf("stage name cannot be empty")
	}
	if _, exists := p.stageMap[s.Name]; exists {
		return fmt.Errorf("stage %q already exists", s.Name)
	}

	// Validate dependencies exist
	for _, dep := range s.DependsOn {
		if _, exists := p.stageMap[dep]; !exists {
			return fmt.Errorf("stage %q depends on unknown stage %q", s.Name, dep)
		}
	}

	p.Stages = append(p.Stages, s)
	p.stageMap[s.Name] = s
	return nil
}

// GetStage retrieves a stage by name.
func (p *Pipeline) GetStage(name string) (*Stage, bool) {
	s, ok := p.stageMap[name]
	return s, ok
}

// TopologicalOrder returns stages in a valid execution order.
func (p *Pipeline) TopologicalOrder() ([]*Stage, error) {
	// Kahn's algorithm for topological sort
	inDegree := make(map[string]int)
	deps := make(map[string][]string) // reverse: depName -> stages that depend on it

	for _, s := range p.Stages {
		if _, ok := inDegree[s.Name]; !ok {
			inDegree[s.Name] = 0
		}
		for _, dep := range s.DependsOn {
			inDegree[s.Name]++
			deps[dep] = append(deps[dep], s.Name)
		}
	}

	// Find all stages with no dependencies
	var queue []string
	for _, s := range p.Stages {
		if inDegree[s.Name] == 0 {
			queue = append(queue, s.Name)
		}
	}

	// Stable sort for deterministic ordering
	sort.Strings(queue)

	var result []*Stage
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]

		result = append(result, p.stageMap[name])

		for _, dependent := range deps[name] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
				sort.Strings(queue) // keep stable
			}
		}
	}

	if len(result) != len(p.Stages) {
		return nil, fmt.Errorf("pipeline has circular dependencies")
	}

	return result, nil
}

// Validate checks the pipeline for errors.
func (p *Pipeline) Validate() error {
	if len(p.Stages) == 0 {
		return fmt.Errorf("pipeline has no stages")
	}

	_, err := p.TopologicalOrder()
	if err != nil {
		return err
	}

	return nil
}

// StageResult holds the outcome of a stage execution.
type StageResult struct {
	Name     string
	Status   ScanStatus
	Duration time.Duration
	Modules  map[string]ModuleResult
	Error    error
}

// ModuleResult holds the outcome of a single module execution.
type ModuleResult struct {
	Name     string
	Status   ScanStatus
	Duration time.Duration
	Findings int
	Error    error
}

// ModuleFunc is a function that executes a module's logic.
type ModuleFunc func(ctx context.Context) (int, error) // returns findings count

// PipelineExecutor runs a pipeline with proper ordering and concurrency.
type PipelineExecutor struct {
	pipeline    *Pipeline
	moduleFuncs map[string]ModuleFunc
	logger      zerolog.Logger
	maxWorkers  int

	mu      sync.Mutex
	results map[string]*StageResult

	// Callbacks
	OnStageStart    func(stage string)
	OnStageComplete func(stage string, result *StageResult)
	OnModuleStart   func(stage, module string)
	OnModuleComplete func(stage, module string, result *ModuleResult)
}

// NewPipelineExecutor creates a new pipeline executor.
func NewPipelineExecutor(pipeline *Pipeline, maxWorkers int, logger zerolog.Logger) *PipelineExecutor {
	return &PipelineExecutor{
		pipeline:    pipeline,
		moduleFuncs: make(map[string]ModuleFunc),
		logger:      logger,
		maxWorkers:  maxWorkers,
		results:     make(map[string]*StageResult),
	}
}

// RegisterModule registers a module function for execution.
func (pe *PipelineExecutor) RegisterModule(name string, fn ModuleFunc) {
	pe.moduleFuncs[name] = fn
}

// Execute runs the entire pipeline.
func (pe *PipelineExecutor) Execute(ctx context.Context) (map[string]*StageResult, error) {
	stages, err := pe.pipeline.TopologicalOrder()
	if err != nil {
		return nil, fmt.Errorf("pipeline validation: %w", err)
	}

	pe.logger.Info().Int("stages", len(stages)).Msg("Starting pipeline execution")

	for _, stage := range stages {
		select {
		case <-ctx.Done():
			return pe.results, ctx.Err()
		default:
		}

		result := pe.executeStage(ctx, stage)

		pe.mu.Lock()
		pe.results[stage.Name] = result
		pe.mu.Unlock()

		if result.Error != nil && result.Status == StatusFailed {
			pe.logger.Error().
				Str("stage", stage.Name).
				Err(result.Error).
				Msg("Stage failed, stopping pipeline")
			return pe.results, fmt.Errorf("stage %q failed: %w", stage.Name, result.Error)
		}
	}

	pe.logger.Info().Msg("Pipeline execution complete")
	return pe.results, nil
}

func (pe *PipelineExecutor) executeStage(ctx context.Context, stage *Stage) *StageResult {
	start := time.Now()
	result := &StageResult{
		Name:    stage.Name,
		Status:  StatusRunning,
		Modules: make(map[string]ModuleResult),
	}

	if pe.OnStageStart != nil {
		pe.OnStageStart(stage.Name)
	}

	pe.logger.Info().
		Str("stage", stage.Name).
		Str("phase", stage.Phase.String()).
		Int("modules", len(stage.Modules)).
		Bool("parallel", stage.Parallel).
		Msg("Executing stage")

	if stage.Parallel {
		pe.executeModulesParallel(ctx, stage, result)
	} else {
		pe.executeModulesSerial(ctx, stage, result)
	}

	result.Duration = time.Since(start)

	// Determine stage status
	hasFailure := false
	for _, mr := range result.Modules {
		if mr.Status == StatusFailed {
			hasFailure = true
			break
		}
	}

	if hasFailure {
		result.Status = StatusFailed
		result.Error = fmt.Errorf("one or more modules failed in stage %q", stage.Name)
	} else {
		result.Status = StatusComplete
	}

	if pe.OnStageComplete != nil {
		pe.OnStageComplete(stage.Name, result)
	}

	pe.logger.Info().
		Str("stage", stage.Name).
		Str("status", string(result.Status)).
		Dur("duration", result.Duration).
		Msg("Stage completed")

	return result
}

func (pe *PipelineExecutor) executeModulesSerial(ctx context.Context, stage *Stage, result *StageResult) {
	for _, modName := range stage.Modules {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mr := pe.executeModule(ctx, stage.Name, modName)
		result.Modules[modName] = mr
	}
}

func (pe *PipelineExecutor) executeModulesParallel(ctx context.Context, stage *Stage, result *StageResult) {
	maxJobs := stage.MaxJobs
	if maxJobs <= 0 {
		maxJobs = pe.maxWorkers
	}

	sem := make(chan struct{}, maxJobs)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, modName := range stage.Modules {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			mr := pe.executeModule(ctx, stage.Name, name)

			mu.Lock()
			result.Modules[name] = mr
			mu.Unlock()
		}(modName)
	}

	wg.Wait()
}

func (pe *PipelineExecutor) executeModule(ctx context.Context, stageName, modName string) ModuleResult {
	start := time.Now()

	if pe.OnModuleStart != nil {
		pe.OnModuleStart(stageName, modName)
	}

	pe.logger.Debug().
		Str("stage", stageName).
		Str("module", modName).
		Msg("Executing module")

	fn, ok := pe.moduleFuncs[modName]
	if !ok {
		mr := ModuleResult{
			Name:     modName,
			Status:   StatusFailed,
			Duration: time.Since(start),
			Error:    fmt.Errorf("module %q not registered", modName),
		}
		if pe.OnModuleComplete != nil {
			pe.OnModuleComplete(stageName, modName, &mr)
		}
		return mr
	}

	findings, err := fn(ctx)
	duration := time.Since(start)

	mr := ModuleResult{
		Name:     modName,
		Duration: duration,
		Findings: findings,
	}

	if err != nil {
		mr.Status = StatusFailed
		mr.Error = err
		pe.logger.Warn().
			Str("module", modName).
			Err(err).
			Dur("duration", duration).
			Msg("Module failed")
	} else {
		mr.Status = StatusComplete
		pe.logger.Debug().
			Str("module", modName).
			Int("findings", findings).
			Dur("duration", duration).
			Msg("Module completed")
	}

	if pe.OnModuleComplete != nil {
		pe.OnModuleComplete(stageName, modName, &mr)
	}

	return mr
}

// DefaultPipeline creates the standard recon pipeline with all phases.
func DefaultPipeline() *Pipeline {
	p := NewPipeline()

	p.AddStage(&Stage{
		Name:     "osint",
		Phase:    PhaseOSINT,
		Modules:  []string{"google_dorks", "github_dorks", "github_leaks", "email_harvest", "cloud_enum", "dns_intel"},
		Parallel: true,
		MaxJobs:  4,
	})

	p.AddStage(&Stage{
		Name:      "subdomain_passive",
		Phase:     PhaseSubdomain,
		Modules:   []string{"subfinder", "crt_sh", "github_subs"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"osint"},
	})

	p.AddStage(&Stage{
		Name:      "subdomain_active",
		Phase:     PhaseSubdomain,
		Modules:   []string{"dns_brute", "permutations", "zone_transfer"},
		Parallel:  true,
		MaxJobs:   2,
		DependsOn: []string{"subdomain_passive"},
	})

	p.AddStage(&Stage{
		Name:      "subdomain_post",
		Phase:     PhaseSubdomain,
		Modules:   []string{"wildcard_filter", "takeover", "s3_buckets"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"subdomain_active"},
	})

	p.AddStage(&Stage{
		Name:      "web_probe",
		Phase:     PhaseWeb,
		Modules:   []string{"httpx_probe", "screenshot", "portscan"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"subdomain_post"},
	})

	p.AddStage(&Stage{
		Name:      "web_analysis",
		Phase:     PhaseWeb,
		Modules:   []string{"crawl", "js_analysis", "nuclei_scan", "fuzz", "waf_detect", "param_discovery"},
		Parallel:  true,
		MaxJobs:   4,
		DependsOn: []string{"web_probe"},
	})

	p.AddStage(&Stage{
		Name:      "vuln",
		Phase:     PhaseVuln,
		Modules:   []string{"xss", "ssrf", "sqli", "ssti", "lfi", "ssl_check", "smuggling", "nuclei_dast"},
		Parallel:  true,
		MaxJobs:   3,
		DependsOn: []string{"web_analysis"},
	})

	return p
}
