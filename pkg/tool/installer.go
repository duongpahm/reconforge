package tool

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
)

// Installer handles automatic installation of security tools.
type Installer struct {
	logger zerolog.Logger
}

// NewInstaller creates a new tool installer.
func NewInstaller(logger zerolog.Logger) *Installer {
	return &Installer{logger: logger}
}

// Install attempts to install a tool using available methods.
func (i *Installer) Install(ctx context.Context, t *Tool) error {
	i.logger.Info().Str("tool", t.Name).Msg("Installing tool")

	// Try installation methods in order of preference
	methods := i.installMethods(t)
	if len(methods) == 0 {
		return fmt.Errorf("no install method available for %q", t.Name)
	}

	var lastErr error
	for _, m := range methods {
		i.logger.Debug().Str("tool", t.Name).Str("method", m.name).Msg("Trying install method")
		if err := m.fn(ctx); err != nil {
			lastErr = err
			i.logger.Warn().Str("tool", t.Name).Str("method", m.name).Err(err).Msg("Install method failed")
			continue
		}
		i.logger.Info().Str("tool", t.Name).Str("method", m.name).Msg("Install succeeded")
		return nil
	}

	return fmt.Errorf("all install methods failed for %q: %w", t.Name, lastErr)
}

type installMethod struct {
	name string
	fn   func(ctx context.Context) error
}

func (i *Installer) installMethods(t *Tool) []installMethod {
	var methods []installMethod

	if t.Install.Go != "" {
		methods = append(methods, installMethod{"go", func(ctx context.Context) error {
			return i.runCmd(ctx, "go", "install", t.Install.Go)
		}})
	}

	if t.Install.Pip != "" {
		methods = append(methods, installMethod{"pip", func(ctx context.Context) error {
			return i.runCmd(ctx, "pip3", "install", t.Install.Pip)
		}})
	}

	if t.Install.Cargo != "" {
		methods = append(methods, installMethod{"cargo", func(ctx context.Context) error {
			return i.runCmd(ctx, "cargo", "install", t.Install.Cargo)
		}})
	}

	// Platform-specific package managers
	switch runtime.GOOS {
	case "darwin":
		if t.Install.Brew != "" {
			methods = append(methods, installMethod{"brew", func(ctx context.Context) error {
				return i.runCmd(ctx, "brew", "install", t.Install.Brew)
			}})
		}
	case "linux":
		if t.Install.Apt != "" {
			methods = append(methods, installMethod{"apt", func(ctx context.Context) error {
				return i.runCmd(ctx, "sudo", "apt-get", "install", "-y", t.Install.Apt)
			}})
		}
	}

	return methods
}

func (i *Installer) runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// InstallMissing installs all missing required tools.
func (i *Installer) InstallMissing(ctx context.Context, registry *Registry) error {
	for _, t := range registry.All() {
		if !registry.IsInstalled(t.Name) {
			if t.Required {
				if err := i.Install(ctx, t); err != nil {
					return fmt.Errorf("failed to install required tool %q: %w", t.Name, err)
				}
			} else {
				i.logger.Warn().Str("tool", t.Name).Msg("Optional tool not installed, skipping")
			}
		}
	}
	return nil
}
