// Package vm provides VM lifecycle management for Kali Linux VMs.
package vm

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// VMStatus represents the current status of a VM.
type VMStatus struct {
	Name      string `json:"name"`
	State     string `json:"state"`  // running, stopped, error, not_found
	Provider  string `json:"provider"`
	Memory    int    `json:"memory_mb"`
	CPUs      int    `json:"cpus"`
	SSHPort   int    `json:"ssh_port"`
	SSHReady  bool   `json:"ssh_ready"`
	SharedDir string `json:"shared_dir"`
	Uptime    string `json:"uptime,omitempty"`
}

// VMOpts configures VM creation.
type VMOpts struct {
	Provider  string // virtualbox, qemu, vagrant
	Name      string // VM name
	Memory    int    // MB
	CPUs      int
	DiskGB    int
	Image     string // kali-rolling, custom ISO path
	SSHPort   int
	SharedDir string
}

// Manager defines the VM management interface.
type Manager interface {
	Setup(ctx context.Context, opts VMOpts) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status(ctx context.Context) (*VMStatus, error)
	Exec(ctx context.Context, cmd string) (string, error)
	SyncTo(ctx context.Context, localPath, remotePath string) error
	SyncFrom(ctx context.Context, remotePath, localPath string) error
	Destroy(ctx context.Context) error
}

// VirtualBoxManager manages VirtualBox VMs.
type VirtualBoxManager struct {
	name    string
	opts    VMOpts
	logger  zerolog.Logger
}

// NewVirtualBoxManager creates a new VirtualBox VM manager.
func NewVirtualBoxManager(name string, logger zerolog.Logger) *VirtualBoxManager {
	return &VirtualBoxManager{
		name:   name,
		logger: logger,
		opts: VMOpts{
			SSHPort: 2222,
		},
	}
}

// Setup creates and configures a new Kali Linux VM.
func (m *VirtualBoxManager) Setup(ctx context.Context, opts VMOpts) error {
	m.opts = opts
	if m.opts.SSHPort == 0 {
		m.opts.SSHPort = 2222
	}
	if m.opts.Memory == 0 {
		m.opts.Memory = 4096
	}
	if m.opts.CPUs == 0 {
		m.opts.CPUs = 2
	}

	m.logger.Info().
		Str("name", m.name).
		Str("provider", opts.Provider).
		Int("memory", m.opts.Memory).
		Int("cpus", m.opts.CPUs).
		Msg("Setting up Kali VM")

	// Check VBoxManage is available
	if _, err := exec.LookPath("VBoxManage"); err != nil {
		return fmt.Errorf("VBoxManage not found in PATH — install VirtualBox first")
	}

	// Step 1: Import OVA if image is provided
	if m.opts.Image != "" {
		m.logger.Info().Str("image", m.opts.Image).Msg("Importing VM image")
		if err := m.vbox(ctx, "import", m.opts.Image, "--vsys", "0", "--vmname", m.name); err != nil {
			return fmt.Errorf("import OVA: %w", err)
		}
	} else {
		return fmt.Errorf("Kali Linux OVA image path is required. Download from https://www.kali.org/get-kali/#kali-virtual-machines and provide it via config or --image flag")
	}

	// Step 2: Configure VM
	if err := m.vbox(ctx, "modifyvm", m.name,
		"--memory", fmt.Sprint(m.opts.Memory),
		"--cpus", fmt.Sprint(m.opts.CPUs),
		"--vram", "16",
		"--graphicscontroller", "vmsvga",
		"--nic1", "nat",
	); err != nil {
		return fmt.Errorf("configure VM: %w", err)
	}

	// Step 3: Setup SSH port forwarding
	if err := m.vbox(ctx, "modifyvm", m.name,
		"--natpf1", fmt.Sprintf("ssh,tcp,,%d,,22", m.opts.SSHPort),
	); err != nil {
		return fmt.Errorf("setup SSH forwarding: %w", err)
	}

	// Step 4: Setup shared folder
	if m.opts.SharedDir != "" {
		_ = m.vbox(ctx, "sharedfolder", "remove", m.name, "--name", "reconforge")
		if err := m.vbox(ctx, "sharedfolder", "add", m.name,
			"--name", "reconforge",
			"--hostpath", m.opts.SharedDir,
			"--automount",
		); err != nil {
			m.logger.Warn().Err(err).Msg("Failed to setup shared folder")
		}
	}

	m.logger.Info().Str("name", m.name).Msg("VM setup complete")
	return nil
}

// Start boots the VM.
func (m *VirtualBoxManager) Start(ctx context.Context) error {
	m.logger.Info().Str("name", m.name).Msg("Starting VM")

	if err := m.vbox(ctx, "startvm", m.name, "--type", "headless"); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}

	m.logger.Info().Str("name", m.name).Msg("VM started in headless mode")
	return nil
}

// Stop gracefully shuts down the VM.
func (m *VirtualBoxManager) Stop(ctx context.Context) error {
	m.logger.Info().Str("name", m.name).Msg("Stopping VM")

	// Try ACPI shutdown first
	if err := m.vbox(ctx, "controlvm", m.name, "acpipowerbutton"); err != nil {
		m.logger.Warn().Err(err).Msg("ACPI shutdown failed, forcing poweroff")
		if err := m.vbox(ctx, "controlvm", m.name, "poweroff"); err != nil {
			return fmt.Errorf("force poweroff: %w", err)
		}
	}

	m.logger.Info().Str("name", m.name).Msg("VM stopped")
	return nil
}

// Status returns the current VM status.
func (m *VirtualBoxManager) Status(ctx context.Context) (*VMStatus, error) {
	status := &VMStatus{
		Name:      m.name,
		Provider:  "virtualbox",
		Memory:    m.opts.Memory,
		CPUs:      m.opts.CPUs,
		SSHPort:   m.opts.SSHPort,
		SharedDir: m.opts.SharedDir,
	}

	// Query VM info
	out, err := m.vboxOutput(ctx, "showvminfo", m.name, "--machinereadable")
	if err != nil {
		status.State = "not_found"
		return status, nil
	}

	// Parse state from output
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "VMState=") {
			val := strings.Trim(strings.TrimPrefix(line, "VMState="), "\"")
			switch val {
			case "running":
				status.State = "running"
			case "poweroff", "saved", "aborted":
				status.State = "stopped"
			default:
				status.State = val
			}
		}
		if strings.HasPrefix(line, "memory=") {
			fmt.Sscanf(strings.TrimPrefix(line, "memory="), "%d", &status.Memory)
		}
		if strings.HasPrefix(line, "cpus=") {
			fmt.Sscanf(strings.TrimPrefix(line, "cpus="), "%d", &status.CPUs)
		}
	}

	// Check SSH
	if status.State == "running" {
		status.SSHReady = m.checkSSH()
	}

	return status, nil
}

// Exec runs a command on the VM via SSH.
func (m *VirtualBoxManager) Exec(ctx context.Context, cmd string) (string, error) {
	m.logger.Debug().Str("cmd", cmd).Msg("VM exec via SSH")

	sshCmd := exec.CommandContext(ctx, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-p", fmt.Sprint(m.opts.SSHPort),
		fmt.Sprintf("kali@localhost"),
		cmd,
	)

	out, err := sshCmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("ssh exec: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// SyncTo copies files from host to VM using rsync.
func (m *VirtualBoxManager) SyncTo(ctx context.Context, localPath, remotePath string) error {
	m.logger.Info().Str("from", localPath).Str("to", remotePath).Msg("Syncing to VM")

	return m.rsync(ctx, localPath, fmt.Sprintf("kali@localhost:%s", remotePath))
}

// SyncFrom copies files from VM to host using rsync.
func (m *VirtualBoxManager) SyncFrom(ctx context.Context, remotePath, localPath string) error {
	m.logger.Info().Str("from", remotePath).Str("to", localPath).Msg("Syncing from VM")

	return m.rsync(ctx, fmt.Sprintf("kali@localhost:%s", remotePath), localPath)
}

// Destroy removes the VM completely.
func (m *VirtualBoxManager) Destroy(ctx context.Context) error {
	m.logger.Warn().Str("name", m.name).Msg("Destroying VM")

	// Stop first if running
	status, _ := m.Status(ctx)
	if status != nil && status.State == "running" {
		_ = m.Stop(ctx)
		time.Sleep(2 * time.Second)
	}

	if err := m.vbox(ctx, "unregistervm", m.name, "--delete"); err != nil {
		return fmt.Errorf("destroy VM: %w", err)
	}

	m.logger.Info().Str("name", m.name).Msg("VM destroyed")
	return nil
}

// WaitForSSH waits until SSH is available on the VM.
func (m *VirtualBoxManager) WaitForSSH(ctx context.Context, timeout time.Duration) error {
	m.logger.Info().Dur("timeout", timeout).Msg("Waiting for SSH...")

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if m.checkSSH() {
				m.logger.Info().Msg("SSH is ready")
				return nil
			}
			time.Sleep(2 * time.Second)
		}
	}
	return fmt.Errorf("SSH not available after %v", timeout)
}

func (m *VirtualBoxManager) checkSSH() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", m.opts.SSHPort), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (m *VirtualBoxManager) vbox(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("VBoxManage %s: %w\n%s", args[0], err, string(out))
	}
	return nil
}

func (m *VirtualBoxManager) vboxOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("VBoxManage %s: %w", args[0], err)
	}
	return string(out), nil
}

func (m *VirtualBoxManager) rsync(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "rsync", "-avz",
		"-e", fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p %d", m.opts.SSHPort),
		src, dst,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync: %w\n%s", err, string(out))
	}
	return nil
}

// NewManager creates a VM manager for the given provider.
func NewManager(provider, name string, logger zerolog.Logger) (Manager, error) {
	switch provider {
	case "virtualbox":
		return NewVirtualBoxManager(name, logger), nil
	case "qemu":
		return nil, fmt.Errorf("QEMU provider not yet implemented")
	case "vagrant":
		return nil, fmt.Errorf("Vagrant provider not yet implemented")
	default:
		return nil, fmt.Errorf("unknown VM provider: %q", provider)
	}
}
