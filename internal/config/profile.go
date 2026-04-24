package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Profile represents a named scan profile.
type Profile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Available profiles
const (
	ProfileQuick   = "quick"
	ProfileStealth = "stealth"
	ProfileFull    = "full"
	ProfileDeep    = "deep"
)

// LoadProfile loads a scan profile and merges it with the base config.
func LoadProfile(profileName string, baseCfg *Config, logger zerolog.Logger) (*Config, error) {
	if profileName == "" {
		return baseCfg, nil
	}

	v := viper.New()
	v.SetConfigType("yaml")

	// Search for profile file
	profilePaths := []string{
		filepath.Join("configs", "profiles", profileName+".yaml"),
		filepath.Join(".", profileName+".yaml"),
	}

	if home, err := os.UserHomeDir(); err == nil {
		profilePaths = append(profilePaths, filepath.Join(home, ".reconforge", "profiles", profileName+".yaml"))
	}

	var found bool
	for _, p := range profilePaths {
		if _, err := os.Stat(p); err == nil {
			v.SetConfigFile(p)
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("profile %q not found in search paths", profileName)
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading profile %q: %w", profileName, err)
	}

	logger.Info().Str("profile", profileName).Str("file", v.ConfigFileUsed()).Msg("Profile loaded")

	// Unmarshal the profile into a fresh config, then overlay on base
	merged := *baseCfg

	if err := v.Unmarshal(&merged); err != nil {
		return nil, fmt.Errorf("error parsing profile %q: %w", profileName, err)
	}

	return &merged, nil
}

// ListProfiles returns a list of available profile names.
func ListProfiles() []string {
	return []string{ProfileQuick, ProfileStealth, ProfileFull, ProfileDeep}
}
