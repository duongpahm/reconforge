package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRunner() *LocalRunner {
	return NewLocalRunner(zerolog.Nop())
}

func TestLocalRunner_Run_Echo(t *testing.T) {
	r := newTestRunner()
	result, err := r.Run(context.Background(), "echo", []string{"hello", "world"}, RunOpts{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hello world")
	assert.True(t, result.Duration > 0)
}

func TestLocalRunner_Run_Timeout(t *testing.T) {
	r := newTestRunner()
	_, err := r.Run(context.Background(), "sleep", []string{"10"}, RunOpts{
		Timeout: 100 * time.Millisecond,
	})
	assert.Error(t, err)
}

func TestLocalRunner_Run_NonexistentTool(t *testing.T) {
	r := newTestRunner()
	_, err := r.Run(context.Background(), "nonexistent_tool_xyz", nil, RunOpts{})
	assert.Error(t, err)
	var missing *MissingToolError
	assert.True(t, errors.As(err, &missing))
	assert.Equal(t, "nonexistent_tool_xyz", missing.Tool)
	assert.Contains(t, err.Error(), "Fix:  reconforge tools install nonexistent_tool_xyz")
}

func TestLocalRunner_Run_NonZeroExit(t *testing.T) {
	r := newTestRunner()
	_, err := r.Run(context.Background(), "false", nil, RunOpts{})
	assert.Error(t, err)
}

func TestLocalRunner_Run_Retry(t *testing.T) {
	r := newTestRunner()
	_, err := r.Run(context.Background(), "false", nil, RunOpts{
		Retry:      2,
		RetryDelay: 10 * time.Millisecond,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "after 3 attempts")
}

func TestLocalRunner_RunPipe(t *testing.T) {
	r := newTestRunner()
	result, err := r.RunPipe(context.Background(), []PipeCmd{
		{Name: "echo", Args: []string{"hello\nworld\nfoo"}},
		{Name: "grep", Args: []string{"world"}},
	})
	require.NoError(t, err)
	assert.Contains(t, string(result.Stdout), "world")
	assert.NotContains(t, string(result.Stdout), "foo")
}

func TestLocalRunner_IsInstalled(t *testing.T) {
	r := newTestRunner()
	assert.True(t, r.IsInstalled("echo"))
	assert.False(t, r.IsInstalled("nonexistent_tool_xyz"))
}
