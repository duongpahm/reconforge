package osint

import (
	"testing"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/stretchr/testify/assert"
)

func TestRegisterAll(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	assert.Equal(t, 15, r.Count())
}

func TestAllOSINTModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseOSINT, m.Phase(), "module %s should be OSINT phase", m.Name())
	}
}

func TestOSINTModules_NoDependencies(t *testing.T) {
	// All OSINT modules run independently
	mods := []module.Module{
		&EmailHarvest{},
		&GoogleDorks{},
		&GithubLeaks{},
		&CloudEnum{},
		&SPFDMARCCheck{},
		&GithubRepos{},
		&IPInfo{},
		&ThirdPartyMisconfigs{},
		&Metadata{},
		&MailHygiene{},
		&GithubActionsAudit{},
	}
	for _, m := range mods {
		assert.Empty(t, m.Dependencies(), "OSINT module %s should have no dependencies", m.Name())
	}
}

func TestOSINTModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		OSINT: config.OSINTConfig{
			EmailHarvest:  false,
			GoogleDorks:   false,
			GithubLeaks:   false,
			CloudEnum:     false,
			SPFDMARC:      false,
			GithubRepos:   false,
			IPInfo:        false,
			ThirdParties:  false,
			Metadata:      false,
			MailHygiene:   false,
			GithubActions: false,
		},
	}

	tests := []module.Module{
		&EmailHarvest{},
		&GoogleDorks{},
		&GithubLeaks{},
		&CloudEnum{},
		&SPFDMARCCheck{},
		&GithubRepos{},
		&IPInfo{},
		&ThirdPartyMisconfigs{},
		&Metadata{},
		&MailHygiene{},
		&GithubActionsAudit{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		OSINT: config.OSINTConfig{
			EmailHarvest:  true,
			GoogleDorks:   true,
			GithubLeaks:   true,
			CloudEnum:     true,
			SPFDMARC:      true,
			GithubRepos:   true,
			IPInfo:        true,
			ThirdParties:  true,
			Metadata:      true,
			MailHygiene:   true,
			GithubActions: true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestParseEmails(t *testing.T) {
	output := []byte(`
info@example.com
admin@example.com
info@example.com
random line without email
test@test.org
`)
	emails := parseEmailsFromOutput(output)
	assert.Equal(t, 3, len(emails))
	assert.Contains(t, emails, "info@example.com")
	assert.Contains(t, emails, "admin@example.com")
	assert.Contains(t, emails, "test@test.org")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 3))
}
