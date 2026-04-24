package module

import (
	"fmt"
	"sort"
	"sync"

	"github.com/reconforge/reconforge/internal/engine"
)

// Registry manages module discovery and registration.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry creates a new module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry.
func (r *Registry) Register(m Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := m.Name()
	if name == "" {
		return fmt.Errorf("module name cannot be empty")
	}
	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %q already registered", name)
	}

	r.modules[name] = m
	return nil
}

// Get retrieves a module by name.
func (r *Registry) Get(name string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[name]
	return m, ok
}

// All returns all registered modules.
func (r *Registry) All() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		result = append(result, m)
	}

	// Sort by name for stable ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})

	return result
}

// ByPhase returns modules that belong to a specific phase.
func (r *Registry) ByPhase(phase engine.Phase) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Module
	for _, m := range r.modules {
		if m.Phase() == phase {
			result = append(result, m)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})

	return result
}

// Names returns all registered module names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of registered modules.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}

// RequiredTools returns all unique tool binaries required by registered modules.
func (r *Registry) RequiredTools() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var tools []string

	for _, m := range r.modules {
		for _, t := range m.RequiredTools() {
			if !seen[t] {
				seen[t] = true
				tools = append(tools, t)
			}
		}
	}

	sort.Strings(tools)
	return tools
}
