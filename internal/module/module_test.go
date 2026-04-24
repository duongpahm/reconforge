package module

import (
	"context"
	"testing"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockModule is a test helper that implements the Module interface.
type mockModule struct {
	name         string
	desc         string
	phase        engine.Phase
	deps         []string
	tools        []string
	runFn        func(ctx context.Context, scan *ScanContext) error
}

func (m *mockModule) Name() string                 { return m.name }
func (m *mockModule) Description() string           { return m.desc }
func (m *mockModule) Phase() engine.Phase           { return m.phase }
func (m *mockModule) Dependencies() []string        { return m.deps }
func (m *mockModule) RequiredTools() []string       { return m.tools }
func (m *mockModule) Validate(_ *config.Config) error { return nil }
func (m *mockModule) Run(ctx context.Context, scan *ScanContext) error {
	if m.runFn != nil {
		return m.runFn(ctx, scan)
	}
	return nil
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	err := r.Register(&mockModule{name: "subfinder", phase: engine.PhaseSubdomain})
	require.NoError(t, err)

	err = r.Register(&mockModule{name: "subfinder"})
	assert.Error(t, err, "duplicate should fail")

	err = r.Register(&mockModule{name: ""})
	assert.Error(t, err, "empty name should fail")
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockModule{name: "subfinder"})

	m, ok := r.Get("subfinder")
	assert.True(t, ok)
	assert.Equal(t, "subfinder", m.Name())

	_, ok = r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistry_ByPhase(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockModule{name: "subfinder", phase: engine.PhaseSubdomain})
	r.Register(&mockModule{name: "httpx", phase: engine.PhaseWeb})
	r.Register(&mockModule{name: "crt_sh", phase: engine.PhaseSubdomain})

	subs := r.ByPhase(engine.PhaseSubdomain)
	assert.Len(t, subs, 2)

	web := r.ByPhase(engine.PhaseWeb)
	assert.Len(t, web, 1)

	osint := r.ByPhase(engine.PhaseOSINT)
	assert.Len(t, osint, 0)
}

func TestRegistry_Names(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockModule{name: "c_mod"})
	r.Register(&mockModule{name: "a_mod"})
	r.Register(&mockModule{name: "b_mod"})

	names := r.Names()
	assert.Equal(t, []string{"a_mod", "b_mod", "c_mod"}, names)
}

func TestRegistry_RequiredTools(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockModule{name: "m1", tools: []string{"subfinder", "httpx"}})
	r.Register(&mockModule{name: "m2", tools: []string{"httpx", "nuclei"}})

	tools := r.RequiredTools()
	assert.Equal(t, []string{"httpx", "nuclei", "subfinder"}, tools) // sorted, deduplicated
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()
	assert.Equal(t, 0, r.Count())

	r.Register(&mockModule{name: "a"})
	r.Register(&mockModule{name: "b"})
	assert.Equal(t, 2, r.Count())
}
