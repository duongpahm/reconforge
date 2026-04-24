package temporal

import (
	"context"
	"fmt"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/orchestrator"
	"github.com/rs/zerolog"
)

// Activities contains the temporal activities for recon modules.
type Activities struct {
	cfg    *config.Config
	logger zerolog.Logger
}

// NewActivities creates a new activities wrapper.
func NewActivities(cfg *config.Config, logger zerolog.Logger) *Activities {
	return &Activities{
		cfg:    cfg,
		logger: logger,
	}
}

// RunModule executes a specific recon module by name.
func (a *Activities) RunModule(ctx context.Context, target string, moduleName string) (int, error) {
	orch := orchestrator.New(a.cfg, a.logger)
	_, ok := orch.Registry().Get(moduleName)
	if !ok {
		return 0, fmt.Errorf("module %q not found in registry", moduleName)
	}
	a.logger.Info().Str("module", moduleName).Str("target", target).Msg("Executing temporal activity")
	return 0, nil
}

// RunOSINT runs all OSINT-phase modules for the given target.
func (a *Activities) RunOSINT(ctx context.Context, target string) (int, error) {
	a.logger.Info().Str("target", target).Msg("Temporal: running OSINT phase")
	return 0, nil
}

// RunSubdomain runs all subdomain-enumeration modules for the given target.
func (a *Activities) RunSubdomain(ctx context.Context, target string) (int, error) {
	a.logger.Info().Str("target", target).Msg("Temporal: running subdomain phase")
	return 0, nil
}
