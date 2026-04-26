package tools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Tool defines an external binary dependency.
type Tool struct {
	Name       string
	InstallCmd []string // e.g., ["go", "install", "-v", "..."]
	Type       string   // go, python, binary
}

// Registry holds the configuration of all manageable tools.
var Registry = map[string]Tool{
	"nuclei": {
		Name:       "nuclei",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		Type:       "go",
	},
	"subfinder": {
		Name:       "subfinder",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		Type:       "go",
	},
	"httpx": {
		Name:       "httpx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		Type:       "go",
	},
	"naabu": {
		Name:       "naabu",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		Type:       "go",
	},
	"amass": {
		Name:       "amass",
		InstallCmd: []string{"go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"},
		Type:       "go",
	},
	"dnsx": {
		Name:       "dnsx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		Type:       "go",
	},
	"tlsx": {
		Name:       "tlsx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
		Type:       "go",
	},
	"urlfinder": {
		Name:       "urlfinder",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"},
		Type:       "go",
	},
	"asnmap": {
		Name:       "asnmap",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
		Type:       "go",
	},
}

// ToolStatus represents the status of a tool on the host system.
type ToolStatus struct {
	Name      string
	Installed bool
	Path      string
}

// Manager manages tool installation and environment checks.
type Manager struct{}

// NewManager creates a new Tool Manager.
func NewManager() *Manager {
	return &Manager{}
}

// IsInstalled checks if a tool is present in the system PATH.
func (m *Manager) IsInstalled(name string) (bool, string) {
	path, err := exec.LookPath(name)
	if err != nil {
		// Fallback to checking ~/go/bin directly if it's a go tool
		home, errHome := os.UserHomeDir()
		if errHome == nil {
			goPath := filepath.Join(home, "go", "bin", name)
			if _, statErr := os.Stat(goPath); statErr == nil {
				return true, goPath
			}
		}
		return false, ""
	}
	return true, path
}

// Install attempts to install the specified tool using its configured command.
func (m *Manager) Install(name string) error {
	tool, exists := Registry[name]
	if !exists {
		return fmt.Errorf("tool %s is not registered in the tool manager", name)
	}

	if len(tool.InstallCmd) == 0 {
		return fmt.Errorf("no automated installation available for %s", name)
	}

	cmd := exec.Command(tool.InstallCmd[0], tool.InstallCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install %s: %w", name, err)
	}

	return nil
}

// List returns the status of all registered tools.
func (m *Manager) List() []ToolStatus {
	var statuses []ToolStatus
	for name := range Registry {
		installed, p := m.IsInstalled(name)
		statuses = append(statuses, ToolStatus{
			Name:      name,
			Installed: installed,
			Path:      p,
		})
	}
	return statuses
}

// CheckEnvironment verifies fundamental system dependencies.
func (m *Manager) CheckEnvironment() []string {
	var issues []string

	// Check Go
	if _, err := exec.LookPath("go"); err != nil {
		issues = append(issues, "Go compiler not found in PATH")
	} else {
		out, _ := exec.Command("go", "version").Output()
		if !strings.Contains(string(out), "go1.2") {
			issues = append(issues, "Go version should be at least 1.21")
		}
	}

	// Check Python3
	if _, err := exec.LookPath("python3"); err != nil {
		issues = append(issues, "Python3 not found in PATH")
	}

	// Output Directory check
	home, err := os.UserHomeDir()
	if err == nil {
		outDir := filepath.Join(home, ".reconforge")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			issues = append(issues, fmt.Sprintf("Cannot create output directory: %s", outDir))
		}
	}

	return issues
}
