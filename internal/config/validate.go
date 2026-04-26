package config

import (
	"fmt"
	"strings"
)

// Validate checks configuration for logical errors and constraint violations.
func Validate(cfg *Config) error {
	var errs []string

	// General
	if cfg.General.MaxWorkers < 1 {
		errs = append(errs, "general.max_workers must be >= 1")
	}
	if cfg.General.MaxWorkers > 100 {
		errs = append(errs, "general.max_workers should not exceed 100")
	}
	if cfg.General.CheckpointFreq < 1 {
		errs = append(errs, "general.checkpoint_freq must be >= 1")
	}
	if cfg.General.MemoryLimitMB < 0 {
		errs = append(errs, "general.memory_limit_mb must be >= 0")
	}
	if cfg.General.OutputDir == "" {
		errs = append(errs, "general.output_dir cannot be empty")
	}

	// DNS
	validResolvers := map[string]bool{"auto": true, "puredns": true, "dnsx": true}
	if !validResolvers[cfg.DNS.Resolver] {
		errs = append(errs, fmt.Sprintf("dns.resolver must be one of: auto, puredns, dnsx (got %q)", cfg.DNS.Resolver))
	}

	// Rate limit
	if cfg.RateLimit.MinRate < 1 {
		errs = append(errs, "ratelimit.min_rate must be >= 1")
	}
	if cfg.RateLimit.MaxRate < cfg.RateLimit.MinRate {
		errs = append(errs, "ratelimit.max_rate must be >= ratelimit.min_rate")
	}

	// Cache
	if cfg.Cache.MaxAgeDays < 1 {
		errs = append(errs, "cache.max_age_days must be >= 1")
	}

	// Monitoring
	if cfg.Monitoring.Enabled {
		if cfg.Monitoring.IntervalMinutes < 1 {
			errs = append(errs, "monitoring.interval_minutes must be >= 1")
		}
		validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
		if !validSeverities[cfg.Monitoring.MinSeverity] {
			errs = append(errs, fmt.Sprintf("monitoring.min_severity must be one of: info, low, medium, high, critical (got %q)", cfg.Monitoring.MinSeverity))
		}
	}

	// Export
	validFormats := map[string]bool{"json": true, "html": true, "csv": true, "all": true, "": true}
	if !validFormats[cfg.Export.Format] {
		errs = append(errs, fmt.Sprintf("export.format must be one of: json, html, csv, all (got %q)", cfg.Export.Format))
	}

	// AI
	if cfg.AI.Enabled {
		validProfiles := map[string]bool{"executive": true, "brief": true, "bughunter": true}
		if !validProfiles[cfg.AI.ReportProfile] {
			errs = append(errs, fmt.Sprintf("ai.report_profile must be one of: executive, brief, bughunter (got %q)", cfg.AI.ReportProfile))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation errors:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}
