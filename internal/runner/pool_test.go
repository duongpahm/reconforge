package runner

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

func TestPool_BasicExecution(t *testing.T) {
	pool := NewPool(2, zerolog.Nop())

	var count atomic.Int64
	jobs := make([]Job, 5)
	for i := range jobs {
		jobs[i] = Job{
			ID: fmt.Sprintf("job-%d", i),
			Fn: func(_ context.Context) error {
				count.Add(1)
				return nil
			},
		}
	}

	results := pool.Run(context.Background(), jobs)
	assert.Len(t, results, 5)
	assert.Equal(t, int64(5), count.Load())

	for _, r := range results {
		assert.NoError(t, r.Error)
	}
}

func TestPool_ErrorPropagation(t *testing.T) {
	pool := NewPool(2, zerolog.Nop())

	jobs := []Job{
		{ID: "ok", Fn: func(_ context.Context) error { return nil }},
		{ID: "fail", Fn: func(_ context.Context) error { return fmt.Errorf("something went wrong") }},
		{ID: "ok2", Fn: func(_ context.Context) error { return nil }},
	}

	results := pool.Run(context.Background(), jobs)
	require.Len(t, results, 3)

	assert.NoError(t, results[0].Error)
	assert.Error(t, results[1].Error)
	assert.NoError(t, results[2].Error)

	stats := pool.Stats()
	assert.Equal(t, int64(1), stats.Failed)
}

func TestPool_Backpressure(t *testing.T) {
	pool := NewPool(2, zerolog.Nop())

	var maxConcurrent atomic.Int64
	var current atomic.Int64

	jobs := make([]Job, 10)
	for i := range jobs {
		jobs[i] = Job{
			ID: fmt.Sprintf("job-%d", i),
			Fn: func(_ context.Context) error {
				c := current.Add(1)
				// Track max concurrent
				for {
					old := maxConcurrent.Load()
					if c <= old || maxConcurrent.CompareAndSwap(old, c) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				current.Add(-1)
				return nil
			},
		}
	}

	pool.Run(context.Background(), jobs)
	assert.LessOrEqual(t, maxConcurrent.Load(), int64(2), "should never exceed max workers")
}

func TestPool_ContextCancellation(t *testing.T) {
	pool := NewPool(2, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	jobs := make([]Job, 10)
	for i := range jobs {
		jobs[i] = Job{
			ID: fmt.Sprintf("job-%d", i),
			Fn: func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(1 * time.Second):
					return nil
				}
			},
		}
	}

	results := pool.Run(ctx, jobs)
	// At least some should have context errors
	var ctxErrors int
	for _, r := range results {
		if r.Error != nil {
			ctxErrors++
		}
	}
	assert.Greater(t, ctxErrors, 0)
}
