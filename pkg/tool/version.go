package tool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// VersionInfo stores version and install metadata for a tool.
type VersionInfo struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	InstallPath string    `json:"install_path,omitempty"`
}

// VersionTracker manages tool version records.
type VersionTracker struct {
	dbPath   string
	versions map[string]*VersionInfo
}

// NewVersionTracker creates a version tracker using a JSON file.
func NewVersionTracker(dbPath string) (*VersionTracker, error) {
	vt := &VersionTracker{
		dbPath:   dbPath,
		versions: make(map[string]*VersionInfo),
	}

	if err := vt.load(); err != nil {
		return nil, err
	}
	return vt, nil
}

// Record stores version info for a tool.
func (vt *VersionTracker) Record(name, version, installPath string) error {
	now := time.Now()
	if info, exists := vt.versions[name]; exists {
		info.Version = version
		info.UpdatedAt = now
		if installPath != "" {
			info.InstallPath = installPath
		}
	} else {
		vt.versions[name] = &VersionInfo{
			Name:        name,
			Version:     version,
			InstalledAt: now,
			UpdatedAt:   now,
			InstallPath: installPath,
		}
	}
	return vt.save()
}

// Get retrieves version info for a tool.
func (vt *VersionTracker) Get(name string) (*VersionInfo, bool) {
	info, ok := vt.versions[name]
	return info, ok
}

// NeedsUpdate checks if a tool was last updated more than maxAge ago.
func (vt *VersionTracker) NeedsUpdate(name string, maxAge time.Duration) bool {
	info, ok := vt.versions[name]
	if !ok {
		return true
	}
	return time.Since(info.UpdatedAt) > maxAge
}

func (vt *VersionTracker) load() error {
	data, err := os.ReadFile(vt.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh start
		}
		return fmt.Errorf("read version db: %w", err)
	}

	return json.Unmarshal(data, &vt.versions)
}

func (vt *VersionTracker) save() error {
	if err := os.MkdirAll(filepath.Dir(vt.dbPath), 0o755); err != nil {
		return fmt.Errorf("create version db dir: %w", err)
	}

	data, err := json.MarshalIndent(vt.versions, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal version db: %w", err)
	}

	return os.WriteFile(vt.dbPath, data, 0o644)
}
