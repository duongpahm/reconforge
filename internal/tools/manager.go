package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Tool defines an external binary dependency.
type Tool struct {
	Name       string
	InstallCmd []string // e.g., ["go", "install", "-v", "..."]
	Type       string   // go, python, binary
	DocsURL    string
	SHA256     string
}

// Registry holds the configuration of all manageable tools.
var Registry = map[string]Tool{
	"nuclei": {
		Name:       "nuclei",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/nuclei",
	},
	"subfinder": {
		Name:       "subfinder",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/subfinder",
	},
	"httpx": {
		Name:       "httpx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/httpx",
	},
	"naabu": {
		Name:       "naabu",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/naabu",
	},
	"amass": {
		Name:       "amass",
		InstallCmd: []string{"go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"},
		Type:       "go",
		DocsURL:    "https://github.com/owasp-amass/amass",
	},
	"dnsx": {
		Name:       "dnsx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/dnsx",
	},
	"tlsx": {
		Name:       "tlsx",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/tlsx",
	},
	"urlfinder": {
		Name:       "urlfinder",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/urlfinder",
	},
	"asnmap": {
		Name:       "asnmap",
		InstallCmd: []string{"go", "install", "-v", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
		Type:       "go",
		DocsURL:    "https://github.com/projectdiscovery/asnmap",
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

	if installed, path := m.IsInstalled(name); installed {
		if err := m.verifyInstalledChecksum(name, path, tool); err != nil {
			return err
		}
	}

	cmd := exec.Command(tool.InstallCmd[0], tool.InstallCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install %s: %w", name, err)
	}

	installed, path := m.IsInstalled(name)
	if !installed {
		return fmt.Errorf("tool %s installed but binary not found in PATH", name)
	}
	if err := m.recordInstalledChecksum(name, path, tool); err != nil {
		return err
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
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
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

func (m *Manager) verifyInstalledChecksum(name, path string, tool Tool) error {
	sum, err := sha256File(path)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", name, err)
	}
	if tool.SHA256 != "" && !strings.EqualFold(sum, tool.SHA256) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, sum, tool.SHA256)
	}

	manifest, err := m.loadChecksumManifest()
	if err != nil {
		return err
	}
	if expected, ok := manifest[name]; ok && !strings.EqualFold(sum, expected) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, sum, expected)
	}
	return nil
}

func (m *Manager) recordInstalledChecksum(name, path string, tool Tool) error {
	sum, err := sha256File(path)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", name, err)
	}
	if tool.SHA256 != "" && !strings.EqualFold(sum, tool.SHA256) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, sum, tool.SHA256)
	}

	manifest, err := m.loadChecksumManifest()
	if err != nil {
		return err
	}
	manifest[name] = sum
	return m.saveChecksumManifest(manifest)
}

func (m *Manager) checksumManifestPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".reconforge", "tool-checksums.json"), nil
}

func (m *Manager) loadChecksumManifest() (map[string]string, error) {
	path, err := m.checksumManifestPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read checksum manifest: %w", err)
	}
	manifest := make(map[string]string)
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse checksum manifest: %w", err)
	}
	return manifest, nil
}

func (m *Manager) saveChecksumManifest(manifest map[string]string) error {
	path, err := m.checksumManifestPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create checksum manifest dir: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checksum manifest: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write checksum manifest: %w", err)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
