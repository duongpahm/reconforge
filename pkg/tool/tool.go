// Package tool provides tool definition, installation, and version management.
package tool

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Tool represents an external security tool that ReconForge can execute.
type Tool struct {
	Name        string            `yaml:"name"`
	Binary      string            `yaml:"binary"`
	Description string            `yaml:"description"`
	Phase       string            `yaml:"phase"`
	Version     string            `yaml:"version"`
	Install     InstallConfig     `yaml:"install"`
	HealthCheck string            `yaml:"health_check"`
	Commands    map[string]ToolCmd `yaml:"commands"`
	Args        map[string]ToolArg `yaml:"args"`
	Required    bool              `yaml:"required"`
}

// InstallConfig specifies how to install the tool.
type InstallConfig struct {
	Go     string `yaml:"go"`      // go install path@version
	Apt    string `yaml:"apt"`     // apt package name
	Brew   string `yaml:"brew"`    // homebrew formula
	Pip    string `yaml:"pip"`     // pip package name
	Cargo  string `yaml:"cargo"`   // cargo install
	Script string `yaml:"script"`  // install script URL or path
}

// ToolCmd represents a named command that the tool can run.
type ToolCmd struct {
	Template   string `yaml:"template"`
	Timeout    string `yaml:"timeout"`
	OutputType string `yaml:"output_type"` // lines, json, jsonl
	ParseAs    string `yaml:"parse_as"`    // subdomains, urls, findings, etc.
}

// ToolArg represents a configurable argument for a tool.
type ToolArg struct {
	Flag    string      `yaml:"flag"`
	Default interface{} `yaml:"default"`
}

// Registry manages the collection of available tools.
type Registry struct {
	tools map[string]*Tool
}

// NewRegistry creates a new empty tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]*Tool),
	}
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *Tool) error {
	if t.Name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}
	if _, exists := r.tools[t.Name]; exists {
		return fmt.Errorf("tool %q already registered", t.Name)
	}
	r.tools[t.Name] = t
	return nil
}

// Get retrieves a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// All returns all registered tools.
func (r *Registry) All() []*Tool {
	result := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		result = append(result, t)
	}
	return result
}

// ByPhase returns tools that belong to a specific phase.
func (r *Registry) ByPhase(phase string) []*Tool {
	var result []*Tool
	for _, t := range r.tools {
		if t.Phase == phase {
			result = append(result, t)
		}
	}
	return result
}

// IsInstalled checks if a tool's binary is available in PATH.
func (r *Registry) IsInstalled(name string) bool {
	t, ok := r.tools[name]
	if !ok {
		return false
	}
	_, err := exec.LookPath(t.Binary)
	return err == nil
}

// HealthCheck runs the health check command for a tool.
func (r *Registry) HealthCheck(ctx context.Context, name string) (string, error) {
	t, ok := r.tools[name]
	if !ok {
		return "", fmt.Errorf("tool %q not found", name)
	}

	if t.HealthCheck == "" {
		return "", fmt.Errorf("no health check defined for %q", name)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	parts := strings.Fields(t.HealthCheck)
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("health check failed for %q: %w\nOutput: %s", name, err, string(out))
	}

	return strings.TrimSpace(string(out)), nil
}

// CheckAll runs health checks on all registered tools and returns status.
func (r *Registry) CheckAll(ctx context.Context) map[string]ToolStatus {
	status := make(map[string]ToolStatus)
	for name, t := range r.tools {
		s := ToolStatus{
			Name:      name,
			Required:  t.Required,
			Installed: r.IsInstalled(name),
		}

		if s.Installed {
			if ver, err := r.HealthCheck(ctx, name); err == nil {
				s.Version = ver
				s.Healthy = true
			} else {
				s.Error = err.Error()
			}
		}

		status[name] = s
	}
	return status
}

// ToolStatus represents the installation/health status of a tool.
type ToolStatus struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Installed bool   `json:"installed"`
	Healthy   bool   `json:"healthy"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}
