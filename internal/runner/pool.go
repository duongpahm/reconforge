package runner

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Job represents a unit of work for the pool.
type Job struct {
	ID   string
	Fn   func(ctx context.Context) error
}

// JobResult holds the outcome of a completed job.
type JobResult struct {
	ID    string
	Error error
}

// Pool is a goroutine worker pool with backpressure.
type Pool struct {
	maxWorkers int
	logger     zerolog.Logger

	active  atomic.Int64
	total   atomic.Int64
	failed  atomic.Int64
}

// NewPool creates a worker pool with the given concurrency limit.
func NewPool(maxWorkers int, logger zerolog.Logger) *Pool {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	return &Pool{
		maxWorkers: maxWorkers,
		logger:     logger,
	}
}

// Run executes all jobs with bounded concurrency, returning results.
// This blocks until all jobs complete or context is cancelled.
func (p *Pool) Run(ctx context.Context, jobs []Job) []JobResult {
	results := make([]JobResult, len(jobs))
	var mu sync.Mutex
	var idx int

	sem := make(chan struct{}, p.maxWorkers)
	var wg sync.WaitGroup

	for i, job := range jobs {
		select {
		case <-ctx.Done():
			// Fill remaining with context error
			mu.Lock()
			for j := i; j < len(jobs); j++ {
				results[j] = JobResult{ID: jobs[j].ID, Error: ctx.Err()}
			}
			mu.Unlock()
			wg.Wait()
			return results
		case sem <- struct{}{}: // acquire worker slot (backpressure)
		}

		wg.Add(1)
		go func(i int, job Job) {
			defer wg.Done()
			defer func() { <-sem }() // release worker slot

			p.active.Add(1)
			defer p.active.Add(-1)

			p.logger.Debug().
				Str("job_id", job.ID).
				Int64("active", p.active.Load()).
				Msg("Job started")

			err := job.Fn(ctx)

			p.total.Add(1)
			if err != nil {
				p.failed.Add(1)
				p.logger.Warn().
					Str("job_id", job.ID).
					Err(err).
					Msg("Job failed")
			} else {
				p.logger.Debug().
					Str("job_id", job.ID).
					Msg("Job completed")
			}

			mu.Lock()
			results[i] = JobResult{ID: job.ID, Error: err}
			idx++
			mu.Unlock()
		}(i, job)
	}

	wg.Wait()
	return results
}

// Stats returns pool execution statistics.
func (p *Pool) Stats() PoolStats {
	return PoolStats{
		Active:     p.active.Load(),
		Total:      p.total.Load(),
		Failed:     p.failed.Load(),
		MaxWorkers: p.maxWorkers,
	}
}

// PoolStats holds pool execution metrics.
type PoolStats struct {
	Active     int64
	Total      int64
	Failed     int64
	MaxWorkers int
}
