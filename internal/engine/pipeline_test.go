package engine

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipeline_TopologicalOrder(t *testing.T) {
	p := NewPipeline()

	require.NoError(t, p.AddStage(&Stage{Name: "a", Phase: PhaseOSINT}))
	require.NoError(t, p.AddStage(&Stage{Name: "b", Phase: PhaseSubdomain, DependsOn: []string{"a"}}))
	require.NoError(t, p.AddStage(&Stage{Name: "c", Phase: PhaseWeb, DependsOn: []string{"b"}}))

	order, err := p.TopologicalOrder()
	require.NoError(t, err)
	require.Len(t, order, 3)
	assert.Equal(t, "a", order[0].Name)
	assert.Equal(t, "b", order[1].Name)
	assert.Equal(t, "c", order[2].Name)
}

func TestPipeline_TopologicalOrder_Diamond(t *testing.T) {
	p := NewPipeline()

	require.NoError(t, p.AddStage(&Stage{Name: "root"}))
	require.NoError(t, p.AddStage(&Stage{Name: "left", DependsOn: []string{"root"}}))
	require.NoError(t, p.AddStage(&Stage{Name: "right", DependsOn: []string{"root"}}))
	require.NoError(t, p.AddStage(&Stage{Name: "join", DependsOn: []string{"left", "right"}}))

	order, err := p.TopologicalOrder()
	require.NoError(t, err)
	require.Len(t, order, 4)
	assert.Equal(t, "root", order[0].Name)
	assert.Equal(t, "join", order[3].Name) // join must be last
}

func TestPipeline_CircularDependency(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "a"})
	p.AddStage(&Stage{Name: "b", DependsOn: []string{"a"}})

	// Manually add circular dep (bypass validation)
	p.stageMap["a"].DependsOn = []string{"b"}

	_, err := p.TopologicalOrder()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular")
}

func TestPipeline_DuplicateStage(t *testing.T) {
	p := NewPipeline()
	require.NoError(t, p.AddStage(&Stage{Name: "a"}))
	err := p.AddStage(&Stage{Name: "a"})
	assert.Error(t, err)
}

func TestPipeline_UnknownDependency(t *testing.T) {
	p := NewPipeline()
	err := p.AddStage(&Stage{Name: "a", DependsOn: []string{"nonexistent"}})
	assert.Error(t, err)
}

func TestPipelineExecutor_SerialExecution(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"mod_a", "mod_b"}, Parallel: false})

	var order []string
	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	exec.RegisterModule("mod_a", func(_ context.Context) (int, error) {
		order = append(order, "a")
		return 5, nil
	})
	exec.RegisterModule("mod_b", func(_ context.Context) (int, error) {
		order = append(order, "b")
		return 3, nil
	})

	results, err := exec.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, order)
	assert.Equal(t, StatusComplete, results["s1"].Status)
	assert.Equal(t, 5, results["s1"].Modules["mod_a"].Findings)
	assert.Equal(t, 3, results["s1"].Modules["mod_b"].Findings)
}

func TestPipelineExecutor_ParallelExecution(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"mod_a", "mod_b", "mod_c"}, Parallel: true, MaxJobs: 3})

	var count atomic.Int64
	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	for _, name := range []string{"mod_a", "mod_b", "mod_c"} {
		exec.RegisterModule(name, func(_ context.Context) (int, error) {
			count.Add(1)
			time.Sleep(50 * time.Millisecond)
			return 1, nil
		})
	}

	start := time.Now()
	results, err := exec.Execute(context.Background())
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, int64(3), count.Load())
	assert.Equal(t, StatusComplete, results["s1"].Status)
	// Parallel should be faster than serial (3*50ms = 150ms)
	assert.Less(t, elapsed, 150*time.Millisecond)
}

func TestPipelineExecutor_StageOrdering(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "first", Modules: []string{"m1"}})
	p.AddStage(&Stage{Name: "second", Modules: []string{"m2"}, DependsOn: []string{"first"}})

	var order []string
	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	exec.RegisterModule("m1", func(_ context.Context) (int, error) {
		order = append(order, "first")
		return 0, nil
	})
	exec.RegisterModule("m2", func(_ context.Context) (int, error) {
		order = append(order, "second")
		return 0, nil
	})

	_, err := exec.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second"}, order)
}

func TestPipelineExecutor_ModuleFailure(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"good", "bad"}, Parallel: false})

	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	exec.RegisterModule("good", func(_ context.Context) (int, error) { return 0, nil })
	exec.RegisterModule("bad", func(_ context.Context) (int, error) { return 0, fmt.Errorf("crash") })

	results, err := exec.Execute(context.Background())
	assert.Error(t, err)
	assert.Equal(t, StatusFailed, results["s1"].Status)
	assert.Equal(t, StatusFailed, results["s1"].Modules["bad"].Status)
}

func TestPipelineExecutor_MissingModule(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"nonexistent"}})

	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	results, err := exec.Execute(context.Background())
	assert.Error(t, err)
	assert.Equal(t, StatusFailed, results["s1"].Modules["nonexistent"].Status)
}

func TestPipelineExecutor_ContextCancellation(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"slow"}})
	p.AddStage(&Stage{Name: "s2", Modules: []string{"never"}, DependsOn: []string{"s1"}})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	exec.RegisterModule("slow", func(ctx context.Context) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(5 * time.Second):
			return 0, nil
		}
	})
	exec.RegisterModule("never", func(_ context.Context) (int, error) {
		return 0, nil
	})

	_, err := exec.Execute(ctx)
	assert.Error(t, err)
}

func TestPipelineExecutor_Callbacks(t *testing.T) {
	p := NewPipeline()
	p.AddStage(&Stage{Name: "s1", Modules: []string{"m1"}})

	var stageStarted, stageCompleted, modStarted, modCompleted bool

	exec := NewPipelineExecutor(p, 4, zerolog.Nop())
	exec.RegisterModule("m1", func(_ context.Context) (int, error) { return 2, nil })
	exec.OnStageStart = func(s string) { stageStarted = true }
	exec.OnStageComplete = func(s string, r *StageResult) { stageCompleted = true }
	exec.OnModuleStart = func(s, m string) { modStarted = true }
	exec.OnModuleComplete = func(s, m string, r *ModuleResult) { modCompleted = true }

	exec.Execute(context.Background())

	assert.True(t, stageStarted)
	assert.True(t, stageCompleted)
	assert.True(t, modStarted)
	assert.True(t, modCompleted)
}

func TestDefaultPipeline(t *testing.T) {
	p := DefaultPipeline()
	require.NoError(t, p.Validate())

	order, err := p.TopologicalOrder()
	require.NoError(t, err)
	assert.Len(t, order, 7)
	assert.Equal(t, "osint", order[0].Name)
	assert.Equal(t, "vuln", order[6].Name) // vuln must be last
}
