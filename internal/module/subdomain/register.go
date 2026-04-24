package subdomain

import "github.com/reconforge/reconforge/internal/module"

// RegisterAll registers all subdomain modules with the given registry.
func RegisterAll(registry *module.Registry) {
	// Passive enumeration
	registry.Register(&Subfinder{})
	registry.Register(&CrtSh{})
	registry.Register(&GithubSubdomains{})

	// Active enumeration
	registry.Register(&DNSBrute{})
	registry.Register(&Permutation{})
	registry.Register(&Resolver{})
	registry.Register(&Recursive{})

	// TLS / DNS active
	registry.Register(&TLSGrab{})
	registry.Register(&ZoneTransfer{})
	registry.Register(&S3Buckets{})

	// Post-processing
	registry.Register(&WildcardFilter{})
	registry.Register(&Takeover{})

	// ASN / DNS / Scraping
	registry.Register(&ASNEnum{})
	registry.Register(&SubNoError{})
	registry.Register(&SRVEnum{})
	registry.Register(&SourceScraping{})
	registry.Register(&AnalyticsEnum{})
	registry.Register(&NSDelegation{})
	registry.Register(&SubRegexPermut{})
	registry.Register(&SubPTRCidrs{})
	registry.Register(&GeoInfo{})
	registry.Register(&SubIAPermut{})
}
