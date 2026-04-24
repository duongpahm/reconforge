package vuln

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

func TestAllVulnModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseVuln, m.Phase(), "module %s should be vuln phase", m.Name())
	}
}

func TestVulnModules_NoDependencies(t *testing.T) {
	// All vuln modules run independently (they read from shared results)
	mods := []module.Module{
		&Nuclei{},
		&DalfoxXSS{},
		&SQLMapScan{},
		&SSRFScanner{},
		&SSLAudit{},
	}
	for _, m := range mods {
		assert.Empty(t, m.Dependencies(), "vuln module %s should have no dependencies", m.Name())
	}
}

func TestVulnModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		Web:  config.WebConfig{Nuclei: false},
		Vuln: config.VulnConfig{
			XSS:  false,
			SQLi: false,
			SSRF: false,
			SSL:  false,
		},
	}

	tests := []module.Module{
		&Nuclei{},
		&DalfoxXSS{},
		&SQLMapScan{},
		&SSRFScanner{},
		&SSLAudit{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		Web:  config.WebConfig{Nuclei: true},
		Vuln: config.VulnConfig{
			XSS:  true,
			SQLi: true,
			SSRF: true,
			SSL:  true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestRequiredTools(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	tools := r.RequiredTools()
	assert.Contains(t, tools, "nuclei")
	assert.Contains(t, tools, "dalfox")
	assert.Contains(t, tools, "sqlmap")
	assert.Contains(t, tools, "testssl.sh")
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"[critical] CVE-2023-1234", "critical"},
		{"[high] XSS found", "high"},
		{"[medium] Open redirect", "medium"},
		{"[low] Info disclosure", "low"},
		{"Some other line", "info"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, parseSeverity(tt.input))
	}
}

func TestScanResults_LiveHosts(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddLiveHosts([]string{"http://a.com", "http://b.com"})
	assert.Equal(t, 2, added)

	added = sr.AddLiveHosts([]string{"http://b.com", "http://c.com"})
	assert.Equal(t, 1, added) // only c is new

	hosts := sr.GetLiveHosts()
	assert.Equal(t, 3, len(hosts))
}

func TestScanResults_URLs(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddURLs([]string{"http://a.com/page1", "http://a.com/page2"})
	assert.Equal(t, 2, added)

	added = sr.AddURLs([]string{"http://a.com/page2", "http://a.com/page3"})
	assert.Equal(t, 1, added)

	urls := sr.GetURLs()
	assert.Equal(t, 3, len(urls))
}

func TestScanResults_Emails(t *testing.T) {
	sr := module.NewScanResults()

	added := sr.AddEmails([]string{"a@test.com", "b@test.com"})
	assert.Equal(t, 2, added)

	added = sr.AddEmails([]string{"b@test.com", "c@test.com"})
	assert.Equal(t, 1, added)
}
