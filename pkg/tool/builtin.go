package tool

// DefaultRegistry creates a registry populated with the default security tools.
func DefaultRegistry() *Registry {
	r := NewRegistry()

	r.Register(&Tool{
		Name:        "subfinder",
		Binary:      "subfinder",
		Description: "Fast passive subdomain enumeration tool",
		Phase:       "subdomain",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		},
		HealthCheck: "subfinder -version",
	})

	r.Register(&Tool{
		Name:        "httpx",
		Binary:      "httpx",
		Description: "Fast and multi-purpose HTTP toolkit",
		Phase:       "web",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		},
		HealthCheck: "httpx -version",
	})

	r.Register(&Tool{
		Name:        "nuclei",
		Binary:      "nuclei",
		Description: "Fast and customizable vulnerability scanner",
		Phase:       "vuln",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		},
		HealthCheck: "nuclei -version",
	})

	r.Register(&Tool{
		Name:        "amass",
		Binary:      "amass",
		Description: "In-depth Attack Surface Mapping and Asset Discovery",
		Phase:       "subdomain",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/owasp-amass/amass/v4/...@master",
		},
		HealthCheck: "amass -version",
	})

	r.Register(&Tool{
		Name:        "dalfox",
		Binary:      "dalfox",
		Description: "Parameter Analysis and XSS Scanner",
		Phase:       "vuln",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/hahwul/dalfox/v2@latest",
		},
		HealthCheck: "dalfox version",
	})

	r.Register(&Tool{
		Name:        "gowitness",
		Binary:      "gowitness",
		Description: "Web screenshot utility",
		Phase:       "web",
		Required:    true,
		Install: InstallConfig{
			Go: "github.com/sensepost/gowitness@latest",
		},
		HealthCheck: "gowitness version",
	})

	return r
}
