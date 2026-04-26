package orchestrator

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestAllRegisteredModulesAreWired(t *testing.T) {
	orch := New(defaultConfig(), zerolog.Nop())
	pipeline := orch.fullPipeline()

	wired := make(map[string]bool)
	for _, stage := range pipeline.Stages {
		for _, modName := range stage.Modules {
			wired[modName] = true
		}
	}

	allowlist := map[string]bool{}

	for _, modName := range orch.Registry().Names() {
		if !wired[modName] && !allowlist[modName] {
			t.Errorf("module %q registered but not wired into any stage", modName)
		}
	}
}
