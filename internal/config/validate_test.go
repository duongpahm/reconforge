package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func validConfig() *Config {
	return &Config{
		General: GeneralConfig{
			ToolsDir:   "~/Tools",
			OutputDir:  "./Recon",
			Parallel:   true,
			MaxWorkers: 4,
		},
		VM: VMConfig{
			Enabled:  true,
			Provider: "virtualbox",
			Memory:   4096,
			CPUs:     2,
			SSHPort:  2222,
		},
		DNS: DNSConfig{
			Resolver: "auto",
		},
		RateLimit: RateLimitConfig{
			MinRate: 10,
			MaxRate: 500,
		},
		Cache: CacheConfig{
			MaxAgeDays: 30,
		},
		Monitoring: MonitoringConfig{
			Enabled:         false,
			IntervalMinutes: 60,
			MinSeverity:     "high",
		},
		Export: ExportConfig{
			Format: "all",
		},
		AI: AIConfig{
			Enabled:       false,
			ReportProfile: "bughunter",
		},
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	assert.NoError(t, Validate(cfg))
}

func TestValidate_InvalidMaxWorkers(t *testing.T) {
	cfg := validConfig()
	cfg.General.MaxWorkers = 0
	assert.Error(t, Validate(cfg))

	cfg.General.MaxWorkers = 101
	assert.Error(t, Validate(cfg))
}

func TestValidate_EmptyOutputDir(t *testing.T) {
	cfg := validConfig()
	cfg.General.OutputDir = ""
	assert.Error(t, Validate(cfg))
}

func TestValidate_InvalidVMProvider(t *testing.T) {
	cfg := validConfig()
	cfg.VM.Enabled = true
	cfg.VM.Provider = "vmware"
	assert.Error(t, Validate(cfg))
}

func TestValidate_VMMemoryTooLow(t *testing.T) {
	cfg := validConfig()
	cfg.VM.Memory = 512
	assert.Error(t, Validate(cfg))
}

func TestValidate_InvalidDNSResolver(t *testing.T) {
	cfg := validConfig()
	cfg.DNS.Resolver = "unbound"
	assert.Error(t, Validate(cfg))
}

func TestValidate_RateLimitMinGreaterThanMax(t *testing.T) {
	cfg := validConfig()
	cfg.RateLimit.MinRate = 100
	cfg.RateLimit.MaxRate = 50
	assert.Error(t, Validate(cfg))
}

func TestValidate_InvalidExportFormat(t *testing.T) {
	cfg := validConfig()
	cfg.Export.Format = "xml"
	assert.Error(t, Validate(cfg))
}

func TestValidate_MonitoringInvalidSeverity(t *testing.T) {
	cfg := validConfig()
	cfg.Monitoring.Enabled = true
	cfg.Monitoring.IntervalMinutes = 60
	cfg.Monitoring.MinSeverity = "extreme"
	assert.Error(t, Validate(cfg))
}

func TestValidate_AIInvalidProfile(t *testing.T) {
	cfg := validConfig()
	cfg.AI.Enabled = true
	cfg.AI.ReportProfile = "summary"
	assert.Error(t, Validate(cfg))
}
