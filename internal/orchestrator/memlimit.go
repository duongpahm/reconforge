package orchestrator

import (
	"runtime/debug"

	"github.com/rs/zerolog"
)

func applyMemoryLimit(limitMB int64, logger zerolog.Logger) func() {
	if limitMB <= 0 {
		return func() {}
	}

	limitBytes := limitMB * 1024 * 1024
	prev := debug.SetMemoryLimit(limitBytes)
	logger.Info().Int64("memory_limit_mb", limitMB).Msg("Applied process memory limit")

	return func() {
		debug.SetMemoryLimit(prev)
	}
}
