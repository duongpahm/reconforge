package vuln

import "github.com/reconforge/reconforge/internal/module"

// RegisterAll registers all vulnerability scanning modules with the given registry.
func RegisterAll(registry *module.Registry) {
	registry.Register(&Nuclei{})
	registry.Register(&DalfoxXSS{})
	registry.Register(&SQLMapScan{})
	registry.Register(&SSRFScanner{})
	registry.Register(&SSLAudit{})
	registry.Register(&CRLFCheck{})
	registry.Register(&LFICheck{})
	registry.Register(&SSTICheck{})
	registry.Register(&CommandInjection{})
	registry.Register(&Bypass4xx{})
	registry.Register(&HTTPSmuggling{})
	registry.Register(&WebCache{})
	registry.Register(&FuzzParams{})
	registry.Register(&Spraying{})
	registry.Register(&NucleiDAST{})
}
