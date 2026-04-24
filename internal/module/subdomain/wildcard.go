package subdomain

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/engine"
	"github.com/reconforge/reconforge/internal/module"
)

// WildcardFilter detects and removes wildcard DNS entries.
type WildcardFilter struct{}

func (m *WildcardFilter) Name() string { return "wildcard_filter" }
func (m *WildcardFilter) Description() string {
	return "Multi-level wildcard DNS detection and filtering"
}
func (m *WildcardFilter) Phase() engine.Phase     { return engine.PhaseSubdomain }
func (m *WildcardFilter) Dependencies() []string  { return []string{"dns_brute", "permutations"} }
func (m *WildcardFilter) RequiredTools() []string { return nil } // pure Go implementation

func (m *WildcardFilter) Validate(cfg *config.Config) error {
	if !cfg.Subdomain.WildcardFilter {
		return fmt.Errorf("wildcard filtering disabled")
	}
	return nil
}

func (m *WildcardFilter) Run(ctx context.Context, scan *module.ScanContext) error {
	currentSubs := scan.Results.GetSubdomains()
	if len(currentSubs) == 0 {
		return nil
	}

	scan.Logger.Info().
		Int("subdomains", len(currentSubs)).
		Msg("Detecting wildcard DNS entries")

	// Group subdomains by parent domain
	parentMap := make(map[string][]string)
	for _, sub := range currentSubs {
		parent := getParentDomain(sub)
		parentMap[parent] = append(parentMap[parent], sub)
	}

	wildcardParents := make(map[string]bool)
	for parent := range parentMap {
		if isWildcard(ctx, parent) {
			wildcardParents[parent] = true
			scan.Logger.Debug().
				Str("domain", parent).
				Msg("Wildcard DNS detected")
		}
	}

	if len(wildcardParents) == 0 {
		scan.Logger.Info().Msg("No wildcards detected")
		return nil
	}

	// Filter out wildcard subdomains
	var filtered []string
	removed := 0
	for _, sub := range currentSubs {
		parent := getParentDomain(sub)
		if wildcardParents[parent] {
			// Verify this specific subdomain resolves to a different IP than the wildcard
			if !isUniqueResolution(ctx, sub, parent) {
				removed++
				continue
			}
		}
		filtered = append(filtered, sub)
	}

	// Write filtered results
	outFile := filepath.Join(scan.OutputDir, "subdomains", "filtered.txt")
	writeLines(outFile, filtered)

	// Update results with filtered set
	scan.Results.AddSubdomains(filtered)

	scan.Logger.Info().
		Int("wildcards", len(wildcardParents)).
		Int("removed", removed).
		Int("remaining", len(filtered)).
		Msg("Wildcard filtering completed")

	// Record wildcard findings
	for parent := range wildcardParents {
		scan.Results.AddFindings([]module.Finding{{
			Module:   "wildcard_filter",
			Type:     "info",
			Severity: "info",
			Target:   parent,
			Detail:   fmt.Sprintf("Wildcard DNS detected for *.%s", parent),
		}})
	}

	return nil
}

// isWildcard checks if a domain has wildcard DNS by querying a random subdomain.
func isWildcard(ctx context.Context, domain string) bool {
	randomSub := fmt.Sprintf("rf-wildcard-check-7f3a9b2c.%s", domain)
	ips, err := net.DefaultResolver.LookupHost(ctx, randomSub)
	return err == nil && len(ips) > 0
}

// isUniqueResolution checks if a subdomain resolves to a different IP than the wildcard.
func isUniqueResolution(ctx context.Context, subdomain, parent string) bool {
	wildcardSub := fmt.Sprintf("rf-wildcard-check-7f3a9b2c.%s", parent)

	subIPs, err := net.DefaultResolver.LookupHost(ctx, subdomain)
	if err != nil {
		return false
	}

	wildcardIPs, err := net.DefaultResolver.LookupHost(ctx, wildcardSub)
	if err != nil {
		return true // if wildcard doesn't resolve, the subdomain is unique
	}

	// Compare IP sets
	wildcardSet := make(map[string]bool)
	for _, ip := range wildcardIPs {
		wildcardSet[ip] = true
	}

	for _, ip := range subIPs {
		if !wildcardSet[ip] {
			return true // has at least one unique IP
		}
	}

	return false
}

// getParentDomain returns the parent domain (removes first label).
func getParentDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return domain
	}
	return parts[1]
}

var _ module.Module = (*WildcardFilter)(nil)
