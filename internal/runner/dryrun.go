// Package runner provides tool execution with timeout, retry, and worker pool management.
package runner

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// DryRunner logs tool executions without actually running them.
type DryRunner struct {
	logger zerolog.Logger
}

// NewDryRunner creates a new dry runner.
func NewDryRunner(logger zerolog.Logger) *DryRunner {
	return &DryRunner{logger: logger}
}

// Run logs the tool execution and returns a mock success result.
func (r *DryRunner) Run(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error) {
	cmdStr := tool + " " + strings.Join(args, " ")
	r.logger.Info().Str("cmd", cmdStr).Msg("[DRY-RUN] Would execute command")

	return &RunResult{
		Stdout:   []byte("[DRY-RUN] Mock output for " + tool + "\n"),
		Stderr:   []byte(""),
		ExitCode: 0,
		Duration: 10 * time.Millisecond,
	}, nil
}

// RunPipe logs the pipeline execution and returns a mock success result.
func (r *DryRunner) RunPipe(ctx context.Context, cmds []PipeCmd) (*RunResult, error) {
	var cmdStrs []string
	for _, cmd := range cmds {
		cmdStrs = append(cmdStrs, cmd.Name+" "+strings.Join(cmd.Args, " "))
	}
	pipelineStr := strings.Join(cmdStrs, " | ")

	r.logger.Info().Str("pipeline", pipelineStr).Msg("[DRY-RUN] Would execute pipeline")

	return &RunResult{
		Stdout:   []byte("[DRY-RUN] Mock pipeline output\n"),
		Stderr:   []byte(""),
		ExitCode: 0,
		Duration: 10 * time.Millisecond,
	}, nil
}

// IsInstalled checks the local PATH so dry runs can still warn about missing tools.
func (r *DryRunner) IsInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}
