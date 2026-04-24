package scope

import (
	"strings"

	"github.com/reconforge/reconforge/pkg/types"
)

// Filter provides result filtering based on scope, sensitivity, and deduplication.
type Filter struct {
	scope            *Scope
	excludeSensitive bool
	seen             map[string]bool
}

// NewFilter creates a result filter.
func NewFilter(scope *Scope, excludeSensitive bool) *Filter {
	return &Filter{
		scope:            scope,
		excludeSensitive: excludeSensitive,
		seen:             make(map[string]bool),
	}
}

// ShouldInclude checks if a domain should be included in results.
func (f *Filter) ShouldInclude(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if domain == "" {
		return false
	}

	// Dedup
	if f.seen[domain] {
		return false
	}

	// Scope check
	if f.scope != nil && !f.scope.IsInScope(domain) {
		return false
	}

	// Sensitivity check
	if f.excludeSensitive {
		d, err := types.NewDomain(domain)
		if err == nil && d.IsSensitiveDomain() {
			return false
		}
	}

	f.seen[domain] = true
	return true
}

// FilterDomains returns only in-scope, non-duplicate domains.
func (f *Filter) FilterDomains(domains []string) []string {
	var result []string
	for _, d := range domains {
		if f.ShouldInclude(d) {
			result = append(result, strings.ToLower(strings.TrimSpace(d)))
		}
	}
	return result
}

// Reset clears the dedup state.
func (f *Filter) Reset() {
	f.seen = make(map[string]bool)
}
