package web

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
	assert.Equal(t, 30, r.Count())
}

func TestAllWebModules_Phase(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)
	for _, m := range r.All() {
		assert.Equal(t, engine.PhaseWeb, m.Phase(), "module %s should be web phase", m.Name())
	}
}

func TestWebModules_Dependencies(t *testing.T) {
	// httpx_probe has no deps (first web module)
	assert.Empty(t, (&HTTPXProbe{}).Dependencies())

	// screenshots depends on httpx
	assert.Contains(t, (&Screenshots{}).Dependencies(), "httpx_probe")

	// crawler depends on httpx
	assert.Contains(t, (&Crawler{}).Dependencies(), "httpx_probe")

	// js_analysis depends on crawler
	assert.Contains(t, (&JSAnalyzer{}).Dependencies(), "crawler")

	// nuclei_check and graphql chain
	assert.Contains(t, (&NucleiCheck{}).Dependencies(), "httpx_probe")
	assert.Contains(t, (&GraphQLScan{}).Dependencies(), "nuclei_check")

	// service and URL extension dependencies
	assert.Contains(t, (&CDNProvider{}).Dependencies(), "httpx_probe")
	assert.Contains(t, (&URLExt{}).Dependencies(), "url_checks")
	assert.Contains(t, (&ServiceFingerprint{}).Dependencies(), "port_scan")
	assert.Contains(t, (&GrpcReflection{}).Dependencies(), "port_scan")
	assert.Contains(t, (&WebsocketChecks{}).Dependencies(), "url_checks")
	assert.Contains(t, (&PasswordDict{}).Dependencies(), "wordlist_gen")
}

func TestWebModules_Validation(t *testing.T) {
	disabledCfg := &config.Config{
		Web: config.WebConfig{
			Probe:              false,
			Screenshots:        false,
			Crawl:              false,
			JSAnalysis:         false,
			WAFDetect:          false,
			Nuclei:             false,
			CDNProvider:        false,
			URLExt:             false,
			ServiceFingerprint: false,
			GraphQL:            false,
			PortScan:           false,
			URLChecks:          false,
			ParamDiscovery:     false,
			BrokenLinks:        false,
			WordlistGen:        false,
			SubJSExtract:       false,
			WellKnownPivots:    false,
			GrpcReflection:     false,
			WebsocketChecks:    false,
			RobotsWordlist:     false,
			PasswordDict:       false,
			LLMProbe:           false,
		},
	}

	tests := []module.Module{
		&HTTPXProbe{},
		&Screenshots{},
		&Crawler{},
		&JSAnalyzer{},
		&WAFDetector{},
		&NucleiCheck{},
		&CDNProvider{},
		&URLExt{},
		&ServiceFingerprint{},
		&GraphQLScan{},
		&ParamDiscovery{},
		&JSChecks{},
		&BrokenLinks{},
		&WordlistGen{},
		&SubJSExtract{},
		&WellKnownPivots{},
		&GrpcReflection{},
		&WebsocketChecks{},
		&WordlistGenRoboxtractor{},
		&PasswordDict{},
		&LLMProbe{},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_disabled", func(t *testing.T) {
			assert.Error(t, m.Validate(disabledCfg))
		})
	}

	enabledCfg := &config.Config{
		Web: config.WebConfig{
			Probe:              true,
			Screenshots:        true,
			Crawl:              true,
			JSAnalysis:         true,
			WAFDetect:          true,
			Nuclei:             true,
			CDNProvider:        true,
			URLExt:             true,
			ServiceFingerprint: true,
			GraphQL:            true,
			PortScan:           true,
			URLChecks:          true,
			ParamDiscovery:     true,
			BrokenLinks:        true,
			WordlistGen:        true,
			SubJSExtract:       true,
			WellKnownPivots:    true,
			GrpcReflection:     true,
			WebsocketChecks:    true,
			RobotsWordlist:     true,
			PasswordDict:       true,
			LLMProbe:           true,
		},
	}

	for _, m := range tests {
		t.Run(m.Name()+"_enabled", func(t *testing.T) {
			assert.NoError(t, m.Validate(enabledCfg))
		})
	}
}

func TestWebModules_RequiredTools(t *testing.T) {
	r := module.NewRegistry()
	RegisterAll(r)

	tools := r.RequiredTools()
	assert.Contains(t, tools, "httpx")
	assert.Contains(t, tools, "gowitness")
	assert.Contains(t, tools, "katana")
	assert.Contains(t, tools, "wafw00f")
	assert.Contains(t, tools, "arjun")
	assert.Contains(t, tools, "nuclei")
	assert.Contains(t, tools, "cdncheck")
	assert.Contains(t, tools, "nerva")
	assert.Contains(t, tools, "gqlspection")
	assert.Contains(t, tools, "grpcurl")
	assert.Contains(t, tools, "curl")
	assert.Contains(t, tools, "roboxtractor")
	assert.Contains(t, tools, "julius")
}
