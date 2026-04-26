// Package runner provides tool execution with timeout, retry, and worker pool management.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/rs/zerolog"
)

// RunOpts configures a single tool execution.
type RunOpts struct {
	Timeout    time.Duration
	Retry      int
	RetryDelay time.Duration
	Stdin      io.Reader
	WorkDir    string
	Env        []string
	Remote     bool // run on Kali VM via SSH
}

// RunResult holds the output of a tool execution.
type RunResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// PipeCmd represents a single command in a pipeline.
type PipeCmd struct {
	Name string
	Args []string
}

// ToolRunner defines the interface for executing security tools.
type ToolRunner interface {
	Run(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error)
	RunPipe(ctx context.Context, cmds []PipeCmd) (*RunResult, error)
	IsInstalled(tool string) bool
}

// LocalRunner executes tools as local processes.
type LocalRunner struct {
	logger zerolog.Logger
}

// NewLocalRunner creates a new local process runner.
func NewLocalRunner(logger zerolog.Logger) *LocalRunner {
	return &LocalRunner{logger: logger}
}

// Run executes a tool with the given arguments and options.
func (r *LocalRunner) Run(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error) {
	var lastErr error
	maxAttempts := opts.Retry + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := r.execute(ctx, tool, args, opts)
		if err == nil {
			return result, nil
		}

		lastErr = err
		r.logger.Warn().
			Str("tool", tool).
			Int("attempt", attempt).
			Int("max", maxAttempts).
			Err(err).
			Msg("Tool execution failed")

		if attempt < maxAttempts && opts.RetryDelay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.RetryDelay):
			}
		}
	}

	return nil, fmt.Errorf("tool %q failed after %d attempts: %w", tool, maxAttempts, lastErr)
}

func (r *LocalRunner) execute(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, tool, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(cmd.Environ(), opts.Env...)
	}

	start := time.Now()
	r.logger.Debug().
		Str("tool", tool).
		Strs("args", args).
		Str("workdir", opts.WorkDir).
		Msg("Executing tool")

	err := cmd.Run()
	duration := time.Since(start)

	result := &RunResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: 0,
		Duration: duration,
	}

	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			return nil, &MissingToolError{
				Tool:    tool,
				Hint:    fmt.Sprintf("reconforge tools install %s", tool),
				DocsURL: docsURLForTool(tool),
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to execute %q: %w", tool, err)
		}
	}

	r.logger.Debug().
		Str("tool", tool).
		Int("exit_code", result.ExitCode).
		Dur("duration", duration).
		Int("stdout_bytes", len(result.Stdout)).
		Msg("Tool completed")

	// Non-zero exit code is an error (tools typically use this for failures)
	if result.ExitCode != 0 {
		return result, fmt.Errorf("tool %q exited with code %d: %s", tool, result.ExitCode, string(result.Stderr))
	}

	return result, nil
}

// RunPipe executes a pipeline of commands (cmd1 | cmd2 | ...).
func (r *LocalRunner) RunPipe(ctx context.Context, cmds []PipeCmd) (*RunResult, error) {
	if len(cmds) == 0 {
		return nil, fmt.Errorf("pipeline cannot be empty")
	}
	if len(cmds) == 1 {
		return r.Run(ctx, cmds[0].Name, cmds[0].Args, RunOpts{})
	}

	start := time.Now()

	// Build command chain
	execCmds := make([]*exec.Cmd, len(cmds))
	for i, pc := range cmds {
		execCmds[i] = exec.CommandContext(ctx, pc.Name, pc.Args...)
	}

	// Connect pipes
	for i := 0; i < len(execCmds)-1; i++ {
		pipe, err := execCmds[i].StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("pipe setup failed at stage %d: %w", i, err)
		}
		execCmds[i+1].Stdin = pipe
	}

	// Capture final output
	var stdout, stderr bytes.Buffer
	execCmds[len(execCmds)-1].Stdout = &stdout
	execCmds[len(execCmds)-1].Stderr = &stderr

	// Start all commands
	for i, cmd := range execCmds {
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start pipeline stage %d (%s): %w", i, cmds[i].Name, err)
		}
	}

	// Wait for all commands
	for i, cmd := range execCmds {
		if err := cmd.Wait(); err != nil {
			// Only report error on last command
			if i == len(execCmds)-1 {
				return &RunResult{
					Stdout:   stdout.Bytes(),
					Stderr:   stderr.Bytes(),
					ExitCode: 1,
					Duration: time.Since(start),
				}, fmt.Errorf("pipeline stage %d (%s) failed: %w", i, cmds[i].Name, err)
			}
		}
	}

	return &RunResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: 0,
		Duration: time.Since(start),
	}, nil
}

// IsInstalled checks if a tool binary exists in PATH.
func (r *LocalRunner) IsInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

func docsURLForTool(tool string) string {
	switch tool {
	case "nuclei":
		return "https://github.com/projectdiscovery/nuclei"
	case "subfinder":
		return "https://github.com/projectdiscovery/subfinder"
	case "httpx":
		return "https://github.com/projectdiscovery/httpx"
	case "naabu":
		return "https://github.com/projectdiscovery/naabu"
	case "dnsx":
		return "https://github.com/projectdiscovery/dnsx"
	case "tlsx":
		return "https://github.com/projectdiscovery/tlsx"
	case "asnmap":
		return "https://github.com/projectdiscovery/asnmap"
	case "urlfinder":
		return "https://github.com/projectdiscovery/urlfinder"
	case "amass":
		return "https://github.com/owasp-amass/amass"
	default:
		return ""
	}
}
