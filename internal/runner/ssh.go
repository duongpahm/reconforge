package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// SSHRunner executes tools on a remote machine (Kali VM) via SSH.
type SSHRunner struct {
	host       string
	port       int
	user       string
	keyPath    string
	logger     zerolog.Logger
	client     *ssh.Client
}

// SSHConfig configures SSH connection parameters.
type SSHConfig struct {
	Host    string
	Port    int
	User    string
	KeyPath string // path to private key
}

// NewSSHRunner creates a new SSH-based tool runner.
func NewSSHRunner(cfg SSHConfig, logger zerolog.Logger) *SSHRunner {
	return &SSHRunner{
		host:    cfg.Host,
		port:    cfg.Port,
		user:    cfg.User,
		keyPath: cfg.KeyPath,
		logger:  logger,
	}
}

// Connect establishes the SSH connection.
func (r *SSHRunner) Connect(ctx context.Context) error {
	key, err := os.ReadFile(r.keyPath)
	if err != nil {
		return fmt.Errorf("read SSH key %q: %w", r.keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: r.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // VM is local
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", r.host, r.port)
	r.logger.Debug().Str("addr", addr).Str("user", r.user).Msg("Connecting via SSH")

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH connect to %s: %w", addr, err)
	}

	r.client = client
	r.logger.Info().Str("addr", addr).Msg("SSH connected")
	return nil
}

// Close closes the SSH connection.
func (r *SSHRunner) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Run executes a command on the remote machine.
func (r *SSHRunner) Run(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error) {
	if r.client == nil {
		return nil, fmt.Errorf("SSH not connected")
	}

	// Build command string
	cmd := tool
	for _, arg := range args {
		cmd += " " + shellescape(arg)
	}

	var lastErr error
	maxAttempts := opts.Retry + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := r.executeSSH(ctx, cmd, opts)
		if err == nil {
			return result, nil
		}

		lastErr = err
		r.logger.Warn().
			Str("cmd", cmd).
			Int("attempt", attempt).
			Err(err).
			Msg("SSH command failed")

		if attempt < maxAttempts && opts.RetryDelay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.RetryDelay):
			}
		}
	}

	return nil, fmt.Errorf("SSH command failed after %d attempts: %w", maxAttempts, lastErr)
}

func (r *SSHRunner) executeSSH(ctx context.Context, cmd string, opts RunOpts) (*RunResult, error) {
	session, err := r.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if opts.Stdin != nil {
		session.Stdin = opts.Stdin
	}

	// Set environment
	for _, env := range opts.Env {
		// Parse KEY=VALUE
		for i, c := range env {
			if c == '=' {
				session.Setenv(env[:i], env[i+1:])
				break
			}
		}
	}

	// Handle timeout via context
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Run with context cancellation
	start := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGTERM)
		return nil, ctx.Err()
	case err := <-errCh:
		duration := time.Since(start)
		result := &RunResult{
			Stdout:   stdout.Bytes(),
			Stderr:   stderr.Bytes(),
			ExitCode: 0,
			Duration: duration,
		}

		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				result.ExitCode = exitErr.ExitStatus()
			} else {
				return nil, fmt.Errorf("SSH exec error: %w", err)
			}
		}

		if result.ExitCode != 0 {
			return result, fmt.Errorf("remote command exited with code %d", result.ExitCode)
		}

		return result, nil
	}
}

// RunPipe is not supported over SSH in the same way — runs as shell pipe.
func (r *SSHRunner) RunPipe(ctx context.Context, cmds []PipeCmd) (*RunResult, error) {
	if len(cmds) == 0 {
		return nil, fmt.Errorf("empty pipeline")
	}

	// Build pipe string: cmd1 | cmd2 | cmd3
	var pipeStr string
	for i, cmd := range cmds {
		if i > 0 {
			pipeStr += " | "
		}
		pipeStr += cmd.Name
		for _, arg := range cmd.Args {
			pipeStr += " " + shellescape(arg)
		}
	}

	return r.Run(ctx, "sh", []string{"-c", pipeStr}, RunOpts{})
}

// IsInstalled checks if a tool exists on the remote machine.
func (r *SSHRunner) IsInstalled(tool string) bool {
	if r.client == nil {
		return false
	}
	result, err := r.Run(context.Background(), "which", []string{tool}, RunOpts{Timeout: 5 * time.Second})
	return err == nil && result.ExitCode == 0
}

// Upload copies a file to the remote machine via SCP-style copy.
func (r *SSHRunner) Upload(ctx context.Context, localPath, remotePath string) error {
	if r.client == nil {
		return fmt.Errorf("SSH not connected")
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}

	session, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintf(w, "C0644 %d %s\n", len(data), filepath.Base(remotePath))
		w.Write(data)
		fmt.Fprint(w, "\x00")
	}()

	dir := filepath.Dir(remotePath)
	return session.Run(fmt.Sprintf("mkdir -p %s && scp -tr %s", shellescape(dir), shellescape(dir)))
}

// Download copies a file from the remote machine.
func (r *SSHRunner) Download(ctx context.Context, remotePath, localPath string) error {
	if r.client == nil {
		return fmt.Errorf("SSH not connected")
	}

	result, err := r.Run(ctx, "cat", []string{remotePath}, RunOpts{Timeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("read remote file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("create local dir: %w", err)
	}

	return os.WriteFile(localPath, result.Stdout, 0o644)
}

// WaitForSSH waits until the SSH server is available.
func WaitForSSH(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("%s:%d", host, port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("SSH at %s not available after %v", addr, timeout)
}

// shellescape provides basic shell argument escaping.
func shellescape(s string) string {
	// Simple escape: wrap in single quotes, escape existing single quotes
	result := "'"
	for _, c := range s {
		if c == '\'' {
			result += "'\\''"
		} else {
			result += string(c)
		}
	}
	result += "'"
	return result
}

// Ensure SSHRunner implements the ToolRunner-like interface at compile time.
var _ interface {
	Run(ctx context.Context, tool string, args []string, opts RunOpts) (*RunResult, error)
	RunPipe(ctx context.Context, cmds []PipeCmd) (*RunResult, error)
	IsInstalled(tool string) bool
} = (*SSHRunner)(nil)

// Ensure io.Reader is used (suppress unused import)
var _ io.Reader
