package osint

import "github.com/reconforge/reconforge/internal/module"

// RegisterAll registers all OSINT modules with the given registry.
func RegisterAll(registry *module.Registry) {
	registry.Register(&EmailHarvest{})
	registry.Register(&GoogleDorks{})
	registry.Register(&GithubLeaks{})
	registry.Register(&CloudEnum{})
	registry.Register(&SPFDMARCCheck{})
	registry.Register(&GithubDorks{})
	registry.Register(&DomainInfo{})
	registry.Register(&APILeaks{})
	registry.Register(&SpoofCheck{})
	registry.Register(&GithubRepos{})
	registry.Register(&IPInfo{})
	registry.Register(&ThirdPartyMisconfigs{})
	registry.Register(&Metadata{})
	registry.Register(&MailHygiene{})
	registry.Register(&GithubActionsAudit{})
}
